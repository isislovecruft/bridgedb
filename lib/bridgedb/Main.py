# -*- coding: utf-8 -*-
#
# BridgeDB by Nick Mathewson.
# Copyright (c) 2007-2009, The Tor Project, Inc.
# See LICENSE for licensing information

"""
This module sets up a bridgedb and starts the servers running.
"""

import os
import signal
import sys
import time
import logging
import logging.handlers
import gettext

from pprint import pprint

from twisted.internet import reactor

from bridgedb import crypto
from bridgedb import persistent
from bridgedb.parse import options

import bridgedb.Bridges as Bridges
import bridgedb.Dist as Dist
import bridgedb.Time as Time
import bridgedb.Storage
import bridgedb.Util as Util


def configureLogging(cfg):
    """Set up Python's logging subsystem based on the configuratino.
    """

    # Turn on safe logging by default
    safelogging = getattr(cfg, 'SAFELOGGING', True)

    level = getattr(cfg, 'LOGLEVEL', 'WARNING')
    level = getattr(logging, level)
    logfile = getattr(cfg, 'LOGFILE', "")
    logfile_count = getattr(cfg, 'LOGFILE_COUNT', 5)
    logfile_rotate_size = getattr(cfg, 'LOGFILE_ROTATE_SIZE', 10000000)
    Util.set_safe_logging(safelogging)

    logging.getLogger().setLevel(level)
    if logfile:
        handler = logging.handlers.RotatingFileHandler(logfile, 'a',
                                                       logfile_rotate_size,
                                                       logfile_count)
        formatter = logging.Formatter('%(asctime)s [%(levelname)s] %(message)s',
                                      "%b %d %H:%M:%S")
        handler.setFormatter(formatter)
        logging.getLogger().addHandler(handler)

    logging.info("Logger Started.")
    logging.info("Level: %s", level)
    if logfile:
        logging.info("Log File: %s", os.path.abspath(logfile))
        logging.info("Log File Count: %d", logfile_count)
        logging.info("Rotate Logs After Size: %d",  logfile_rotate_size)
    else:
        logging.info("Logging to stderr")
    if safelogging:
        logging.info("Safe Logging: Enabled")
    else:
        logging.warn("Safe Logging: Disabled")


def load(cfg, splitter, clear=False):
    """Read all the bridge files from cfg, and pass them into a splitter
       object.
    """
    if clear:
        logging.info("Clearing old bridges")
        splitter.clear()
    logging.info("Loading bridges")
    status = {}
    addresses = {}
    timestamps = {}
    if hasattr(cfg, "STATUS_FILE"):
        logging.info("Opening Network Status document %s" % cfg.STATUS_FILE)
        f = open(cfg.STATUS_FILE, 'r')
        for ID, running, stable, or_addresses, timestamp in Bridges.parseStatusFile(f):
            status[ID] = running, stable
            addresses[ID] = or_addresses
            if ID in timestamps.keys(): timestamps[ID].append(timestamp)
            else: timestamps[ID] = [timestamp]
            #transports[ID] = transports
        logging.debug("Closing status document")
        f.close()
    bridges = {} 
    db = bridgedb.Storage.getDB()

    for fname in cfg.BRIDGE_FILES:
        logging.info("Opening cached server-descriptor document: '%s'" % fname)
        logging.debug("Parsing document for purpose=%s" % cfg.BRIDGE_PURPOSE)
        f = open(fname, 'r')
        for bridge in Bridges.parseDescFile(f, cfg.BRIDGE_PURPOSE):
            if bridge.getID() in bridges:
                logging.warn(
                    "Parsed bridge that we've already added. Skipping.")
                continue
            else:
                bridges[bridge.getID()] = bridge
                s = status.get(bridge.getID())
                if s is not None:
                    running, stable = s
                    bridge.setStatus(running=running, stable=stable)
                bridge.or_addresses = addresses.get(bridge.getID())
                splitter.insert(bridge)
                # add or update BridgeHistory entries into the database
                # XXX: what do we do with all these or_addresses?
                # The bridge stability metrics are only concerned with a single ip:port
                # So for now, we will only consider the bridges primary IP:port
                if bridge.getID() in timestamps.keys():
                    ts = timestamps[bridge.getID()][:]
                    ts.sort()
                    for timestamp in ts:
                        bridgedb.Stability.addOrUpdateBridgeHistory(
                            bridge, timestamp)
        logging.debug("Closing server-descriptor document")
        f.close()

    # read pluggable transports from extra-info document
    # XXX: should read from networkstatus after bridge-authority
    # does a reachability test
    for filename in cfg.EXTRA_INFO_FILES:
        logging.info("Opening extra-info document: '%s'" % filename)
        f = open(filename, 'r')
        for transport in Bridges.parseExtraInfoFile(f):
            ID, method_name, address, port, argdict = transport
            try:
                if bridges[ID].running:
                    logging.debug("  Appending transport to running bridge")
                    bridgePT = Bridges.PluggableTransport(
                        bridges[ID], method_name, address, port, argdict)
                    bridges[ID].transports.append(bridgePT)
                    if not bridgePT in bridges[ID].transports:
                        logging.critical("""Added transport...it disappeared!
                        Transport: %r""" % bridgePT)
            except KeyError as error:
                logging.error("Could not find bridge with fingerprint '%s'."
                              % Bridges.toHex(ID))
        logging.debug("Closing extra-info document")
        f.close()
    if hasattr(cfg, "COUNTRY_BLOCK_FILE"):
        logging.info("Opening Blocking Countries file %s"
                     % cfg.COUNTRY_BLOCK_FILE)
        f = open(cfg.COUNTRY_BLOCK_FILE, 'r')
        for ID, address, portlist, countries in Bridges.parseCountryBlockFile(f):
            if ID in bridges.keys() and bridges[ID].running:
                for port in portlist:
                    logging.debug(":.( Tears! %s blocked %s %s:%s"
                                  % (countries, bridges[ID].fingerprint,
                                     address, port))
                    try:
                        bridges[ID].blockingCountries["%s:%s" % \
                                (address, port)].update(countries)
                    except KeyError:
                        bridges[ID].blockingCountries["%s:%s" % \
                                (address, port)] = set(countries)
        logging.debug("Closing blocking-countries document")
        f.close()

    bridges = None

def loadConfig(configFile=None, configCls=None):
    """Load configuration settings on top of the current settings.

    All pathnames and filenames within settings in the ``configFile`` will be
    expanded, and their expanded values will be stored in the returned
    :class:`config <Conf>` object.

    ** Note: **
    On the strange-looking use of
      ``exec compile(open(configFile).read(), '<string>', 'exec') in dict()``
    in this function:

    The contents of the config file should be compiled first, and then
    ``exec``ed -- not ``execfile``! -- in order to get the contents of the
    config file to exist within the scope of the configuration dictionary.
    Otherwise, Python *will* default_ to executing the config file directly
    within the ``globals()`` scope.

    Additionally, it's roughly 20-30 times faster_ to use the ``compile``
    builtin on a string (the contents of the file) before ``exec``ing it, than
    using ``execfile`` directly on the file.

    .. _default: http://stackoverflow.com/q/17470193
    .. _faster: http://lucumr.pocoo.org/2011/2/1/exec-in-python/

    :ivar boolean itsSafeToUseLogging: This is called in :func:`startup`
        before :func:`configureLogging`. When called from ``startup``, the
        ``configCls`` parameter is not given, because that is the first time
        that a :class:`Conf` is created. If a :class:`logging.Logger` is
        created in this function, then logging will not be correctly
        configured, therefore, if the ``configCls`` parameter is not given,
        then it's the first time this function has been called and it is
        therefore not safe to make calls to the logging module.
    :type: configFile: string or None
    :param string configFile: If given, the filename of the config file to
        load.
    :type configCls: :class:`bridgedb.Main.Conf` or None
    :param configCls: The current configuration, if one already exists.
    :rtype: :class:`Conf`
    :returns: A new configuration, with the old settings as defaults, and the
        settings from the config file overriding them.
    """
    itsSafeToUseLogging = False
    configuration = {}

    if configCls:
        itsSafeToUseLogging = True
        oldConfig = configCls.__dict__
        configuration.update(**oldConfig) # Load current settings
        logging.info("Reloading over in-memory configurations...")

    if (len(configuration) > 0) and itsSafeToUseLogging:
        logging.debug("Old configuration settings:\n%s"
                      % pprint(configuration, depth=4))

    conffile = configFile
    if (configFile is None) and ('CONFIG_FILE' in configuration):
        conffile = configuration['CONFIG_FILE']

    if conffile is not None:
        if itsSafeToUseLogging:
            logging.info("Loading settings from config file: '%s'" % conffile)
        compiled = compile(open(conffile).read(), '<string>', 'exec')
        exec compiled in configuration

    if itsSafeToUseLogging:
        logging.debug("New configuration settings:\n%s"
                      % pprint(configuration, depth=4))

    # Create a :class:`Conf` from the settings stored within the local scope
    # of the ``configuration`` dictionary:
    config = persistent.Conf(**configuration)

    # We want to set the updated/expanded paths for files on the ``config``,
    # because the copy of this config, `state.config` is used later to compare
    # with a new :class:`Conf` instance, to see if there were any changes.
    #
    # See :meth:`bridgedb.persistent.State.useUpdatedSettings`.

    for attr in ["PROXY_LIST_FILES", "BRIDGE_FILES", "EXTRA_INFO_FILES"]:
        setting = getattr(config, attr, None)
        if setting is None:
            setattr(config, attr, []) # If they weren't set, make them lists
        else:
            setattr(config, attr, # If they were set, expand the paths:
                    [os.path.abspath(os.path.expanduser(f)) for f in setting])

    for attr in ["DB_FILE", "DB_LOG_FILE", "MASTER_KEY_FILE", "PIDFILE",
                 "ASSIGNMENTS_FILE", "HTTPS_CERT_FILE", "HTTPS_KEY_FILE",
                 "LOG_FILE", "STATUS_FILE", "COUNTRY_BLOCK_FILE"]:
        setting = getattr(config, attr, None)
        if setting is None:
            setattr(config, attr, setting)
        else:
            setattr(config, attr, os.path.abspath(os.path.expanduser(setting)))

    for attr in ["FORCE_PORTS", "FORCE_FLAGS"]:
        setting = getattr(config, attr, []) # Default to empty lists
        setattr(config, attr, setting)

    for domain in config.EMAIL_DOMAINS:
        config.EMAIL_DOMAIN_MAP[domain] = domain

    if conffile: # Store the pathname of the config file, if one was used
        config.CONFIG_FILE = os.path.abspath(os.path.expanduser(conffile))

    return config

def loadProxyList(cfg):
    ipset = {}
    for fname in cfg.PROXY_LIST_FILES:
        f = open(fname, 'r')
        for line in f:
            line = line.strip()
            if line.startswith("#"):
                continue
            elif Bridges.is_valid_ip(line):
                ipset[line] = True
            elif line:
                logging.info("Skipping line %r in %s: not an IP.",
                             line, fname)
        f.close()
    return ipset

def _reloadFn():
    """Placeholder callback function for :func:`_handleSIGHUP`."""
    return True

def _handleSIGHUP(*args):
    """Called when we receive a SIGHUP; invokes _reloadFn."""
    reactor.callLater(0, _reloadFn, *args)


class ProxyCategory:
    def __init__(self):
        self.ipset = {}
    def contains(self, ip):
        return self.ipset.has_key(ip)
    def replaceProxyList(self, ipset):
        self.ipset = ipset

def startup(options, rundir, configFile):
    """Parse bridges,

    :type state: :class:`bridgedb.persistent.State`
    :param state: A persistent state object which holds options and config
         changes.
    """
    # Change to the directory where we're supposed to run. This must be done
    # before parsing the config file, otherwise there will need to be two
    # copies of the config file, one in the directory BridgeDB is started in,
    # and another in the directory it changes into.
    os.chdir(rundir)

    config = loadConfig(configFile)

    # Set up logging as early as possible. We cannot import from the bridgedb
    # package any of our modules which import :mod:`logging` and start using
    # it, at least, not until :func:`configureLogging` is called. Otherwise a
    # default handler that logs to the console will be created by the imported
    # module, and all further calls to :func:`logging.basicConfig` will be
    # ignored.
    configureLogging(config)

    if options['dump-bridges'] or (options.subCommand is not None):
        runSubcommand(options, config)

    # Write the pidfile only after any options.subCommands are run (because
    # these exit when they are finished). Otherwise, if there is a subcommand,
    # the real PIDFILE would get overwritten with the PID of the temporary
    # bridgedb process running the subcommand.
    if config.PIDFILE:
        logging.debug("Writing server PID to file: '%s'" % config.PIDFILE)
        with open(config.PIDFILE, 'w') as pidfile:
            pidfile.write("%s\n" % os.getpid())
            pidfile.flush()

    from bridgedb import persistent

    state = persistent.State(config=config)
    state.RUN_IN_DIR = rundir

    from bridgedb import EmailServer
    from bridgedb import HTTPServer

    # Load the master key, or create a new one.
    key = crypto.getKey(config.MASTER_KEY_FILE)

    # Initialize our DB file.
    db = bridgedb.Storage.Database(config.DB_FILE + ".sqlite", config.DB_FILE)
    # TODO: move setGlobalDB to bridgedb.persistent.State class
    bridgedb.Storage.setGlobalDB(db)

    # Get a proxy list.
    proxyList = ProxyCategory()
    proxyList.replaceProxyList(loadProxyList(config))

    # Create a BridgeSplitter to assign the bridges to the different
    # distributors.
    splitter = Bridges.BridgeSplitter(Bridges.get_hmac(key, "Splitter-Key"))
    logging.debug("Created splitter: %r" % splitter)

    # Create ring parameters.
    ringParams = Bridges.BridgeRingParameters(needPorts=config.FORCE_PORTS,
                                              needFlags=config.FORCE_FLAGS)

    emailDistributor = ipDistributor = None

    # As appropriate, create an IP-based distributor.
    if config.HTTPS_DIST and config.HTTPS_SHARE:
        logging.debug("Setting up HTTPS Distributor...")
        categories = []
        if proxyList.ipset:
            logging.debug("Adding proxyList to HTTPS Distributor categories.")
            categories.append(proxyList)
        logging.debug("HTTPS Distributor categories: '%s'" % categories)

        ipDistributor = Dist.IPBasedDistributor(
            Dist.uniformMap,
            config.N_IP_CLUSTERS,
            Bridges.get_hmac(key, "HTTPS-IP-Dist-Key"),
            categories,
            answerParameters=ringParams)
        splitter.addRing(ipDistributor, "https", config.HTTPS_SHARE)
        #webSchedule = Time.IntervalSchedule("day", 2)
        webSchedule = Time.NoSchedule()

    # As appropriate, create an email-based distributor.
    if config.EMAIL_DIST and config.EMAIL_SHARE:
        logging.debug("Setting up Email Distributor...")
        emailDistributor = Dist.EmailBasedDistributor(
            Bridges.get_hmac(key, "Email-Dist-Key"),
            config.EMAIL_DOMAIN_MAP.copy(),
            config.EMAIL_DOMAIN_RULES.copy(),
            answerParameters=ringParams)
        splitter.addRing(emailDistributor, "email", config.EMAIL_SHARE)
        #emailSchedule = Time.IntervalSchedule("day", 1)
        emailSchedule = Time.NoSchedule()

    # As appropriate, tell the splitter to leave some bridges unallocated.
    if config.RESERVED_SHARE:
        splitter.addRing(Bridges.UnallocatedHolder(),
                         "unallocated",
                         config.RESERVED_SHARE)

    # Add pseudo distributors to splitter
    for pseudoRing in config.FILE_BUCKETS.keys():
        splitter.addPseudoRing(pseudoRing)

    # Save our state
    state.proxyList = proxyList
    state.key = key
    state.save()

    def reload():
        """Reload settings, proxy lists, and bridges.

        State should be saved before calling this method, and will be saved
        again at the end of it.

        The internal variables, ``cfg``, ``splitter``, ``proxyList``,
        ``ipDistributor``, and ``emailDistributor`` are all taken from a
        :class:`~bridgedb.persistent.State` instance, which has been saved to
        a statefile with :meth:`bridgedb.persistent.State.save`.

        :type cfg: :class:`Conf`
        :ivar cfg: The current configuration, including any in-memory
            settings (i.e. settings whose values were not obtained from the
            config file, but were set via a function somewhere)
        :type splitter: A :class:`bridgedb.Bridges.BridgeHolder`
        :ivar splitter: A class which takes an HMAC key and splits bridges
            into their hashring assignments.
        :type proxyList: :class:`ProxyCategory`
        :ivar proxyList: The container for the IP addresses of any currently
             known open proxies.
        :ivar ipDistributor: A :class:`Dist.IPBasedDistributor`.
        :ivar emailDistributor: A :class:`Dist.EmailBasedDistributor`.
        :ivar dict tasks: A dictionary of ``{name: task}``, where name is a
            string to associate with the ``task``, and ``task`` is some
            scheduled event, repetitive or otherwise, for the :class:`reactor
            <twisted.internet.epollreactor.EPollReactor>`. See the classes
            within the :mod:`twisted.internet.tasks` module.
        """
        logging.debug("Caught SIGHUP")
        logging.info("Reloading...")

        logging.info("Loading saved state...")
        state = persistent.load()
        cfg = loadConfig(state.CONFIG_FILE, state.config)
        logging.info("Updating any changed settings...")
        state.useChangedSettings(cfg)

        level = getattr(state, 'LOGLEVEL', 'WARNING')
        logging.info("Updating log level to: '%s'" % level)
        level = getattr(logging, level)
        logging.getLogger().setLevel(level)

        logging.debug("Saving state again before reparsing descriptors...")
        state.save()

        state = persistent.load()
        logging.info("Bridges loaded: %d" % len(splitter))
        logging.debug("Replacing the list of open proxies...")
        state.proxyList.replaceProxyList(loadProxyList(cfg))

        if emailDistributor is not None:
            logging.debug("Prepopulating email distributor hashrings...")
            emailDistributor.prepopulateRings() # create default rings
            logging.info("Bridges allotted for email distribution: %d"
                         % len(emailDistributor.splitter))
        else:
            logging.warn("No email distributor created!")

        if ipDistributor is not None:
            logging.debug("Prepopulating HTTPS distributor hashrings...")
            ipDistributor.prepopulateRings() # create default rings
            logging.info("Bridges allotted for web distribution: %d"
                         % len(ipDistributor.splitter))
            for (n,(f,r)) in ipDistributor.splitter.filterRings.items():
                logging.info("\tby filter set %s, %d" % (n, len(r)))
        else:
            logging.warn("No HTTP(S) distributor created!")

        # Dump bridge pool assignments to disk.
        try:
            logging.debug("Dumping pool assignments to file: '%s'"
                          % state.ASSIGNMENTS_FILE)
            fh = open(state.ASSIGNMENTS_FILE, 'a')
            fh.write("bridge-pool-assignment %s\n" %
                     time.strftime("%Y-%m-%d %H:%M:%S"))
            splitter.dumpAssignments(fh)
            fh.flush()
            fh.close()
        except IOError:
            logging.info("I/O error while writing assignments to: '%s'"
                         % state.ASSIGNMENTS_FILE)

        state.save()

    global _reloadFn
    _reloadFn = reload
    signal.signal(signal.SIGHUP, _handleSIGHUP)

    # And actually load it to start parsing.
    reload()

    # Configure all servers:
    if config.HTTPS_DIST and config.HTTPS_SHARE:
        HTTPServer.addWebServer(config, ipDistributor, webSchedule)
    if config.EMAIL_DIST and config.EMAIL_SHARE:
        EmailServer.addSMTPServer(config, emailDistributor, emailSchedule)

    # Actually run the servers.
    try:
        logging.info("Starting reactors.")
        reactor.run()
    except KeyboardInterrupt:
        logging.fatal("Received keyboard interrupt. Shutting down...")
    finally:
        logging.info("Closing databases...")
        db.close()
        if config.PIDFILE:
            os.unlink(config.PIDFILE)
        logging.info("Exiting...")
        sys.exit()

def runSubcommand(options, config):
    """Run a subcommand from the 'Commands' section of the bridgedb help menu.

    :type options: :class:`bridgedb.opt.MainOptions`
    :param options: A pre-parsed options class containing any arguments and
        options given in the commandline we were called with.
    :type config: :class:`bridgedb.Main.Conf`
    :param config: The current configuration.
    :raises: :exc:`SystemExit` when all subCommands and subOptions have
        finished running.
    """
    # Make sure that the runner module is only imported after logging is set
    # up, otherwise we run into the same logging configuration problem as
    # mentioned above with the EmailServer and HTTPServer.
    from bridgedb import runner

    if options('dump-bridges'):
        runner.doDumpBridges(config)

    if options.subCommand is not None:
        logging.debug("Running BridgeDB command: '%s'" % options.subCommand)

        if 'descriptors' in options.subOptions:
            runner.generateDescriptors(options.subOptions['descriptors'],
                                       config.RUNDIR)

        if options.subCommand == 'test':
            if options.subOptions['trial']:
                runner.runTrial(options.subOptions)
            if options.subOptions['unittests']:
                runner.runTests(options.subOptions)
        raise SystemExit("Subcommand '%s' finished." % options.subCommand)

def run(options):
    """This is the main entry point into BridgeDB.

    Given the parsed commandline options, this function handles locating the
    configuration file, loading and parsing it, and then either
    starting/reloading the servers or dumping bridge assignments to files.

    :type options: :class:`bridgedb.opt.MainOptions`
    :param options: A pre-parsed options class containing any arguments and
        options given in the commandline we were called with.
    """
    if not options['config']:
        options.getUsage()
        sys.exit(1)
    else:
        configFile = os.path.abspath(os.path.expanduser(options['config']))
    if options['rundir']:
        rundir = os.path.abspath(os.path.expanduser(options['rundir']))

    startup(options, rundir, configFile)

# -*- coding: utf-8 ; test-case-name: bridgedb.test.test_Main -*-
#
# This file is part of BridgeDB, a Tor bridge distribution system.
#
# :authors: please see the AUTHORS file for attributions
# :copyright: (c) 2013-2015, Isis Lovecruft
#             (c) 2013-2015, Matthew Finkel
#             (c) 2007-2015, Nick Mathewson
#             (c) 2007-2015, The Tor Project, Inc.
# :license: see LICENSE for licensing information

"""This module sets up BridgeDB and starts the servers running."""

import logging
import os
import signal
import sys
import time

from twisted.internet import reactor
from twisted.internet import task

from bridgedb import crypto
from bridgedb import persistent
from bridgedb import proxy
from bridgedb import runner
from bridgedb import util
from bridgedb.bridges import MalformedBridgeInfo
from bridgedb.bridges import MissingServerDescriptorDigest
from bridgedb.bridges import ServerDescriptorDigestMismatch
from bridgedb.bridges import ServerDescriptorWithoutNetworkstatus
from bridgedb.bridges import Bridge
from bridgedb.configure import loadConfig
from bridgedb.email.distributor import EmailDistributor
from bridgedb.https.distributor import HTTPSDistributor
from bridgedb.parse import descriptors

import bridgedb.Storage

from bridgedb import Bridges
from bridgedb.Stability import updateBridgeHistory


def load(state, hashring, clear=False):
    """Read and parse all descriptors, and load into a bridge hashring.

    Read all the appropriate bridge files from the saved
    :class:`~bridgedb.persistent.State`, parse and validate them, and then
    store them into our ``state.hashring`` instance. The ``state`` will be
    saved again at the end of this function.

    :type hashring: :class:`~bridgedb.Bridges.BridgeSplitter`
    :param hashring: A class which provides a mechanism for HMACing
        Bridges in order to assign them to hashrings.
    :param boolean clear: If True, clear all previous bridges from the
        hashring before parsing for new ones.
    """
    if not state:
        logging.fatal("bridgedb.Main.load() could not retrieve state!")
        sys.exit(2)

    if clear:
        logging.info("Clearing old bridges...")
        hashring.clear()

    logging.info("Loading bridges...")

    ignoreNetworkstatus = state.IGNORE_NETWORKSTATUS
    if ignoreNetworkstatus:
        logging.info("Ignoring BridgeAuthority networkstatus documents.")

    bridges = {}
    timestamps = {}

    logging.info("Opening networkstatus file: %s" % state.STATUS_FILE)
    networkstatuses = descriptors.parseNetworkStatusFile(state.STATUS_FILE)
    logging.debug("Closing networkstatus file: %s" % state.STATUS_FILE)

    logging.info("Processing networkstatus descriptors...")
    for router in networkstatuses:
        bridge = Bridge()
        bridge.updateFromNetworkStatus(router, ignoreNetworkstatus)
        try:
            bridge.assertOK()
        except MalformedBridgeInfo as error:
            logging.warn(str(error))
        else:
            bridges[bridge.fingerprint] = bridge

    for filename in state.BRIDGE_FILES:
        logging.info("Opening bridge-server-descriptor file: '%s'" % filename)
        serverdescriptors = descriptors.parseServerDescriptorsFile(filename)
        logging.debug("Closing bridge-server-descriptor file: '%s'" % filename)

        for router in serverdescriptors:
            try:
                bridge = bridges[router.fingerprint]
            except KeyError:
                logging.warn(
                    ("Received server descriptor for bridge '%s' which wasn't "
                     "in the networkstatus!") % router.fingerprint)
                if ignoreNetworkstatus:
                    bridge = Bridge()
                else:
                    continue

            try:
                bridge.updateFromServerDescriptor(router, ignoreNetworkstatus)
            except (ServerDescriptorWithoutNetworkstatus,
                    MissingServerDescriptorDigest,
                    ServerDescriptorDigestMismatch) as error:
                logging.warn(str(error))
                # Reject any routers whose server descriptors didn't pass
                # :meth:`~bridges.Bridge._checkServerDescriptor`, i.e. those
                # bridges who don't have corresponding networkstatus
                # documents, or whose server descriptor digests don't check
                # out:
                bridges.pop(router.fingerprint)
                continue

            if state.COLLECT_TIMESTAMPS:
                # Update timestamps from server descriptors, not from network
                # status descriptors (because networkstatus documents and
                # descriptors aren't authenticated in any way):
                if bridge.fingerprint in timestamps.keys():
                    timestamps[bridge.fingerprint].append(router.published)
                else:
                    timestamps[bridge.fingerprint] = [router.published]

    extrainfos = descriptors.parseExtraInfoFiles(*state.EXTRA_INFO_FILES)
    for fingerprint, router in extrainfos.items():
        try:
            bridges[fingerprint].updateFromExtraInfoDescriptor(router)
        except MalformedBridgeInfo as error:
            logging.warn(str(error))
        except KeyError as error:
            logging.warn(("Received extrainfo descriptor for bridge '%s', "
                          "but could not find bridge with that fingerprint.")
                         % router.fingerprint)

    inserted = 0
    logging.info("Inserting %d bridges into hashring..." % len(bridges))
    for fingerprint, bridge in bridges.items():
        # Skip insertion of bridges which are geolocated to be in one of the
        # NO_DISTRIBUTION_COUNTRIES, a.k.a. the countries we don't distribute
        # bridges from:
        if bridge.country in state.NO_DISTRIBUTION_COUNTRIES:
            logging.warn("Not distributing Bridge %s %s:%s in country %s!" %
                         (bridge, bridge.address, bridge.orPort, bridge.country))
        else:
            # If the bridge is not running, then it is skipped during the
            # insertion process.
            hashring.insert(bridge)
            inserted += 1
    logging.info("Done inserting %d bridges into hashring." % inserted)

    if state.COLLECT_TIMESTAMPS:
        reactor.callInThread(updateBridgeHistory, bridges, timestamps)

    state.save()

def _reloadFn(*args):
    """Placeholder callback function for :func:`_handleSIGHUP`."""
    return True

def _handleSIGHUP(*args):
    """Called when we receive a SIGHUP; invokes _reloadFn."""
    reactor.callInThread(_reloadFn)

def _handleSIGUSR1(*args):
    """Handler for SIGUSR1. Calls :func:`~bridgedb.runner.doDumpBridges`."""
    logging.debug("Caught SIGUSR1 signal")

    from bridgedb import runner

    logging.info("Loading saved state...")
    state = persistent.load()
    cfg = loadConfig(state.CONFIG_FILE, state.config)

    logging.info("Dumping bridge assignments to files...")
    reactor.callInThread(runner.doDumpBridges, cfg)

def replaceBridgeRings(current, replacement):
    """Replace the current thing with the new one"""
    current.hashring = replacement.hashring

def createBridgeRings(cfg, proxyList, key):
    """Create the bridge distributors defined by the config file

    :type cfg:  :class:`Conf`
    :param cfg: The current configuration, including any in-memory settings
        (i.e. settings whose values were not obtained from the config file,
        but were set via a function somewhere)
    :type proxyList: :class:`~bridgedb.proxy.ProxySet`
    :param proxyList: The container for the IP addresses of any currently
        known open proxies.
    :param bytes key: Hashring master key
    :rtype: tuple
    :returns: A BridgeSplitter hashring, an
        :class:`~bridgedb.https.distributor.HTTPSDistributor` or None, and an
        :class:`~bridgedb.email.distributor.EmailDistributor` or None.
    """
    # Create a BridgeSplitter to assign the bridges to the different
    # distributors.
    hashring = Bridges.BridgeSplitter(crypto.getHMAC(key, "Hashring-Key"))
    logging.debug("Created hashring: %r" % hashring)

    # Create ring parameters.
    ringParams = Bridges.BridgeRingParameters(needPorts=cfg.FORCE_PORTS,
                                              needFlags=cfg.FORCE_FLAGS)

    emailDistributor = ipDistributor = None
    # As appropriate, create an IP-based distributor.
    if cfg.HTTPS_DIST and cfg.HTTPS_SHARE:
        logging.debug("Setting up HTTPS Distributor...")
        ipDistributor = HTTPSDistributor(
            cfg.N_IP_CLUSTERS,
            crypto.getHMAC(key, "HTTPS-IP-Dist-Key"),
            proxyList,
            answerParameters=ringParams)
        hashring.addRing(ipDistributor.hashring, "https", cfg.HTTPS_SHARE)

    # As appropriate, create an email-based distributor.
    if cfg.EMAIL_DIST and cfg.EMAIL_SHARE:
        logging.debug("Setting up Email Distributor...")
        emailDistributor = EmailDistributor(
            crypto.getHMAC(key, "Email-Dist-Key"),
            cfg.EMAIL_DOMAIN_MAP.copy(),
            cfg.EMAIL_DOMAIN_RULES.copy(),
            answerParameters=ringParams,
            whitelist=cfg.EMAIL_WHITELIST.copy())
        hashring.addRing(emailDistributor.hashring, "email", cfg.EMAIL_SHARE)

    # As appropriate, tell the hashring to leave some bridges unallocated.
    if cfg.RESERVED_SHARE:
        hashring.addRing(Bridges.UnallocatedHolder(),
                         "unallocated",
                         cfg.RESERVED_SHARE)

    # Add pseudo distributors to hashring
    for pseudoRing in cfg.FILE_BUCKETS.keys():
        hashring.addPseudoRing(pseudoRing)

    return hashring, emailDistributor, ipDistributor

def run(options, reactor=reactor):
    """This is BridgeDB's main entry point and main runtime loop.

    Given the parsed commandline options, this function handles locating the
    configuration file, loading and parsing it, and then either (re)parsing
    plus (re)starting the servers, or dumping bridge assignments to files.

    :type options: :class:`bridgedb.parse.options.MainOptions`
    :param options: A pre-parsed options class containing any arguments and
        options given in the commandline we were called with.
    :type state: :class:`bridgedb.persistent.State`
    :ivar state: A persistent state object which holds config changes.
    :param reactor: An implementer of
        :api:`twisted.internet.interfaces.IReactorCore`. This parameter is
        mainly for testing; the default
        :api:`twisted.internet.epollreactor.EPollReactor` is fine for normal
        application runs.
    """
    # Change to the directory where we're supposed to run. This must be done
    # before parsing the config file, otherwise there will need to be two
    # copies of the config file, one in the directory BridgeDB is started in,
    # and another in the directory it changes into.
    os.chdir(options['rundir'])
    if options['verbosity'] <= 10: # Corresponds to logging.DEBUG
        print("Changed to runtime directory %r" % os.getcwd())

    config = loadConfig(options['config'])
    config.RUN_IN_DIR = options['rundir']

    # Set up logging as early as possible. We cannot import from the bridgedb
    # package any of our modules which import :mod:`logging` and start using
    # it, at least, not until :func:`safelog.configureLogging` is
    # called. Otherwise a default handler that logs to the console will be
    # created by the imported module, and all further calls to
    # :func:`logging.basicConfig` will be ignored.
    util.configureLogging(config)

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

    from bridgedb.email.server import addServer as addSMTPServer
    from bridgedb.https.server import addWebServer

    # Load the master key, or create a new one.
    key = crypto.getKey(config.MASTER_KEY_FILE)
    proxies = proxy.ProxySet()
    emailDistributor = None
    ipDistributor = None

    # Save our state
    state.proxies = proxies
    state.key = key
    state.save()

    def reload(inThread=True):
        """Reload settings, proxy lists, and bridges.

        State should be saved before calling this method, and will be saved
        again at the end of it.

        The internal variables, ``cfg``, ``hashring``, ``proxyList``,
        ``ipDistributor``, and ``emailDistributor`` are all taken from a
        :class:`~bridgedb.persistent.State` instance, which has been saved to
        a statefile with :meth:`bridgedb.persistent.State.save`.

        :type cfg: :class:`Conf`
        :ivar cfg: The current configuration, including any in-memory
            settings (i.e. settings whose values were not obtained from the
            config file, but were set via a function somewhere)
        :type hashring: A :class:`~bridgedb.Bridges.BridgeSplitter`
        :ivar hashring: A class which takes an HMAC key and splits bridges
            into their hashring assignments.
        :type proxyList: :class:`~bridgedb.proxy.ProxySet`
        :ivar proxyList: The container for the IP addresses of any currently
            known open proxies.
        :ivar ipDistributor: A
            :class:`~bridgedb.https.distributor.HTTPSDistributor`.
        :ivar emailDistributor: A
            :class:`~bridgedb.email.distributor.EmailDistributor`.
        :ivar dict tasks: A dictionary of ``{name: task}``, where name is a
            string to associate with the ``task``, and ``task`` is some
            scheduled event, repetitive or otherwise, for the :class:`reactor
            <twisted.internet.epollreactor.EPollReactor>`. See the classes
            within the :api:`twisted.internet.tasks` module.
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

        logging.info("Reloading the list of open proxies...")
        for proxyfile in cfg.PROXY_LIST_FILES:
            logging.info("Loading proxies from: %s" % proxyfile)
            proxy.loadProxiesFromFile(proxyfile, state.proxies, removeStale=True)

        logging.info("Reparsing bridge descriptors...")
        (hashring,
         emailDistributorTmp,
         ipDistributorTmp) = createBridgeRings(cfg, state.proxies, key)
        logging.info("Bridges loaded: %d" % len(hashring))

        # Initialize our DB.
        bridgedb.Storage.initializeDBLock()
        bridgedb.Storage.setDBFilename(cfg.DB_FILE + ".sqlite")
        load(state, hashring, clear=False)

        if emailDistributorTmp is not None:
            emailDistributorTmp.prepopulateRings() # create default rings
            logging.info("Bridges allotted for %s distribution: %d"
                         % (emailDistributorTmp.name,
                            len(emailDistributorTmp.hashring)))
        else:
            logging.warn("No email distributor created!")

        if ipDistributorTmp is not None:
            ipDistributorTmp.prepopulateRings() # create default rings

            logging.info("Bridges allotted for %s distribution: %d"
                         % (ipDistributorTmp.name,
                            len(ipDistributorTmp.hashring)))
            logging.info("\tNum bridges:\tFilter set:")

            nSubrings  = 0
            ipSubrings = ipDistributorTmp.hashring.filterRings
            for (ringname, (filterFn, subring)) in ipSubrings.items():
                nSubrings += 1
                filterSet = ' '.join(
                    ipDistributorTmp.hashring.extractFilterNames(ringname))
                logging.info("\t%2d bridges\t%s" % (len(subring), filterSet))

            logging.info("Total subrings for %s: %d"
                         % (ipDistributorTmp.name, nSubrings))
        else:
            logging.warn("No HTTP(S) distributor created!")

        # Dump bridge pool assignments to disk.
        try:
            logging.debug("Dumping pool assignments to file: '%s'"
                          % state.ASSIGNMENTS_FILE)
            fh = open(state.ASSIGNMENTS_FILE, 'a')
            fh.write("bridge-pool-assignment %s\n" %
                     time.strftime("%Y-%m-%d %H:%M:%S"))
            hashring.dumpAssignments(fh)
            fh.flush()
            fh.close()
        except IOError:
            logging.info("I/O error while writing assignments to: '%s'"
                         % state.ASSIGNMENTS_FILE)
        state.save()

        if inThread:
            # XXX shutdown the distributors if they were previously running
            # and should now be disabled
            if ipDistributorTmp:
                reactor.callFromThread(replaceBridgeRings,
                                       ipDistributor, ipDistributorTmp)
            if emailDistributorTmp:
                reactor.callFromThread(replaceBridgeRings,
                                       emailDistributor, emailDistributorTmp)
        else:
            # We're still starting up. Return these distributors so
            # they are configured in the outer-namespace
            return emailDistributorTmp, ipDistributorTmp

    global _reloadFn
    _reloadFn = reload
    signal.signal(signal.SIGHUP, _handleSIGHUP)
    signal.signal(signal.SIGUSR1, _handleSIGUSR1)

    if reactor:
        # And actually load it to start parsing. Get back our distributors.
        emailDistributor, ipDistributor = reload(False)

        # Configure all servers:
        if config.HTTPS_DIST and config.HTTPS_SHARE:
            addWebServer(config, ipDistributor)
        if config.EMAIL_DIST and config.EMAIL_SHARE:
            addSMTPServer(config, emailDistributor)

        tasks = {}

        # Setup all our repeating tasks:
        if config.TASKS['GET_TOR_EXIT_LIST']:
            tasks['GET_TOR_EXIT_LIST'] = task.LoopingCall(
                proxy.downloadTorExits,
                state.proxies,
                config.SERVER_PUBLIC_EXTERNAL_IP)

        if config.TASKS.get('DELETE_UNPARSEABLE_DESCRIPTORS'):
            delUnparseableSecs = config.TASKS['DELETE_UNPARSEABLE_DESCRIPTORS']
        else:
            delUnparseableSecs = 24 * 60 * 60  # Default to 24 hours

        # We use the directory name of STATUS_FILE, since that directory
        # is where the *.unparseable descriptor files will be written to.
        tasks['DELETE_UNPARSEABLE_DESCRIPTORS'] = task.LoopingCall(
            runner.cleanupUnparseableDescriptors,
            os.path.dirname(config.STATUS_FILE), delUnparseableSecs)

        # Schedule all configured repeating tasks:
        for name, seconds in config.TASKS.items():
            if seconds:
                try:
                    tasks[name].start(abs(seconds))
                except KeyError:
                    logging.info("Task %s is disabled and will not run." % name)
                else:
                    logging.info("Scheduled task %s to run every %s seconds."
                                 % (name, seconds))

    # Actually run the servers.
    try:
        if reactor and not reactor.running:
            logging.info("Starting reactors.")
            reactor.run()
    except KeyboardInterrupt:
        logging.fatal("Received keyboard interrupt. Shutting down...")
    finally:
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
    # mentioned above with the email.server and https.server.
    from bridgedb import runner

    statuscode = 0

    if options.subCommand is not None:
        logging.debug("Running BridgeDB command: '%s'" % options.subCommand)

        if 'descriptors' in options.subOptions:
            statuscode = runner.generateDescriptors(
                options.subOptions['descriptors'], config.RUN_IN_DIR)

        logging.info("Subcommand '%s' finished with status %s."
                     % (options.subCommand, statuscode))
        sys.exit(statuscode)

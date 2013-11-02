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

from functools import partial

from twisted.internet import reactor
from twisted.internet import task

from bridgedb import crypto
from bridgedb import proxy
from bridgedb.parse import options

import bridgedb.Bridges as Bridges
import bridgedb.Dist as Dist
import bridgedb.Time as Time
import bridgedb.Storage
import bridgedb.Bucket as Bucket
import bridgedb.Util as Util


class Conf:
    """A configuration object.  Holds unvalidated attributes."""
    def __init__(self, **attrs):
        for key, value in attrs.items():
            if key.upper() == key:
                self.__dict__[key] = value

# An example configuration.  Used for testing.  See sample
# bridgedb.conf for documentation.
CONFIG = Conf(
    RUN_IN_DIR = ".",

    PIDFILE = "bridgedb.pid",
    LOGFILE = None,
    LOGLEVEL = "DEBUG",

    BRIDGE_FILES = [ "./cached-descriptors", "./cached-descriptors.new" ],
    STATUS_FILE = "networkstatus-bridges",
    BRIDGE_PURPOSE = "bridge",
    DB_FILE = "./bridgedist.db",
    DB_LOG_FILE = "./bridgedist.log",

    N_IP_CLUSTERS = 4,
    MASTER_KEY_FILE = "./secret_key",

    ASSIGNMENTS_FILE = "assignments.log",

    FORCE_PORTS = [(443, 1)],
    FORCE_FLAGS = [("Stable", 1)],
    PROXY_LIST_FILES = [ ],

    HTTPS_DIST = True,
    HTTPS_SHARE=10,
    HTTPS_BIND_IP=None,
    HTTPS_PORT=6789,
    HTTPS_CERT_FILE="cert",
    HTTPS_KEY_FILE="privkey.pem",
    HTTPS_USE_IP_FROM_FORWARDED_HEADER=0,
    HTTP_UNENCRYPTED_BIND_IP=None,
    HTTP_UNENCRYPTED_PORT=6788,
    HTTP_USE_IP_FROM_FORWARDED_HEADER=1,
    HTTPS_N_BRIDGES_PER_ANSWER=2,
    HTTPS_INCLUDE_FINGERPRINTS = False,

    EMAIL_DIST = True,
    EMAIL_SHARE=10,
    EMAIL_FROM_ADDR = "bridges@torproject.org",
    EMAIL_SMTP_FROM_ADDR = "bridges@torproject.org",
    EMAIL_USERNAME = "bridges",
    EMAIL_DOMAINS = [ "gmail.com", "yahoo.com", "catbus.wangafu.net" ],
    EMAIL_DOMAIN_MAP = { "mail.google.com" : "gmail.com",
                         "googlemail.com" : "gmail.com", },
    EMAIL_DOMAIN_RULES = { 'gmail.com' : ["ignore_dots", "dkim"],
                           'yahoo.com' : ["dkim"] },
    EMAIL_RESTRICT_IPS=[],
    EMAIL_BIND_IP="127.0.0.1",
    EMAIL_PORT=6725,
    EMAIL_N_BRIDGES_PER_ANSWER=2,
    EMAIL_INCLUDE_FINGERPRINTS = False,
    EMAIL_SMTP_HOST="127.0.0.1",
    EMAIL_SMTP_PORT=25,
    EMAIL_GPG_SIGNING_ENABLED = False,
    EMAIL_GPG_SIGNING_KEY = "bridgedb-gpg.sec",

    RESERVED_SHARE=2,

    FILE_BUCKETS = {},
    RECAPTCHA_ENABLED = False,
    RECAPTCHA_PUB_KEY = '',
    RECAPTCHA_PRIV_KEY = '', 
  )

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

    formatter = logging.Formatter('%(asctime)s [%(levelname)s] %(message)s',
                                  "%b %d %H:%M:%S")

    logging.getLogger().setLevel(level)
    if logfile:
        handler = logging.handlers.RotatingFileHandler(logfile, 'a',
                                                       logfile_rotate_size,
                                                       logfile_count)
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
    logging.info("Safe Logging: %s"
                 % ("Enabled" if safelogging else "Disabled"))

def setupIPDistributor(cfg, ringParams, key, proxyList):
    """Setup and return our :class:`Dist.IPBasedDistributor`."""
    if cfg.HTTPS_DIST and cfg.HTTPS_SHARE:
        logging.debug("Setting up HTTPS Distributor...")
        categories = []
        if proxyList:
            logging.debug("Adding proxyList to HTTPS Distributor categories.")
            categories.append(proxyList)
        logging.debug("HTTPS Distributor categories: '%s'" % categories)

        ipDistributor = Dist.IPBasedDistributor(
            Dist.uniformMap,
            cfg.N_IP_CLUSTERS,
            Bridges.get_hmac(key, "HTTPS-IP-Dist-Key"),
            categories,
            answerParameters=ringParams)
        return ipDistributor

def setupEmailDistributor(cfg, ringParams, key):
    # As appropriate, create an email-based distributor.
    if cfg.EMAIL_DIST and cfg.EMAIL_SHARE:
        logging.debug("Resetting email domain map...")
        logging.debug("Old email domain map: '%s'" % cfg.EMAIL_DOMAIN_MAP)
        for d in cfg.EMAIL_DOMAINS:
            cfg.EMAIL_DOMAIN_MAP[d] = d
        logging.debug("New email domain map: '%s'" % cfg.EMAIL_DOMAIN_MAP)

        emailDistributor = Dist.EmailBasedDistributor(
            Bridges.get_hmac(key, "Email-Dist-Key"),
            cfg.EMAIL_DOMAIN_MAP.copy(),
            cfg.EMAIL_DOMAIN_RULES.copy(),
            answerParameters=ringParams)
        return emailDistributor

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
        logging.info("Opening Network Status document %s"
                     % os.path.abspath(cfg.STATUS_FILE))
        fh = open(cfg.STATUS_FILE, 'r')
        for ID, running, stable, oraddrs, ts in Bridges.parseStatusFile(fh):
            status[ID] = running, stable
            addresses[ID] = oraddrs
            if ID in timestamps.keys(): timestamps[ID].append(ts)
            else: timestamps[ID] = [ts]

        logging.debug("Closing status document")
        fh.close()
    bridges = {} 
    db = bridgedb.Storage.getDB()

    for fname in cfg.BRIDGE_FILES:
        logging.info("Opening cached server-descriptor document: '%s'" % fname)
        logging.debug("Parsing document for purpose=%s" % cfg.BRIDGE_PURPOSE)
        fh = open(fname, 'r')
        for bridge in Bridges.parseDescFile(fh, cfg.BRIDGE_PURPOSE):
            if bridge.getID() in bridges:
                logging.warn(
                    "Parsed bridge that we've already added. Skipping.")
                continue
            else:
                bridges[bridge.getID()] = bridge
                stat = status.get(bridge.getID())
                if stat is not None:
                    running, stable = stat
                    bridge.setStatus(running=running, stable=stable)
                bridge.or_addresses = addresses.get(bridge.getID())
                splitter.insert(bridge)
                # add or update BridgeHistory entries into the database
                # XXX: what do we do with all these or_addresses?
                # The bridge stability metrics are only concerned with a
                # single ip:port. So for now, we will only consider the
                # bridges primary IP:port.
                if bridge.getID() in timestamps.keys():
                    timestamp = timestamps[bridge.getID()][:]
                    timestamp.sort()
                    for tstamp in timestamp:
                        bridgedb.Stability.addOrUpdateBridgeHistory(
                            bridge, timestamp)
        logging.debug("Closing server-descriptor document")
        fh.close()

    # read pluggable transports from extra-info document
    # XXX: should read from networkstatus after bridge-authority
    # does a reachability test
    for filename in cfg.EXTRA_INFO_FILES:
        logging.info("Opening extra-info document: '%s'"
                     % os.path.abspath(filename))
        fh = open(filename, 'r')
        for transport in Bridges.parseExtraInfoFile(fh):
            ID, method_name, address, port, argdict = transport
            fpr = Bridges.toHex(ID)
            logging.debug("LOOKING UP FINGERPRINT: %r" % fpr)
            try:
                if bridges[fpr].running:
                    logging.debug("\tAppending transport to running bridge")
                    bridgePT = Bridges.PluggableTransport(bridges[fpr],
                                                          method_name,
                                                          address,
                                                          port,
                                                          argdict)
                    bridges[fpr].transports.append(bridgePT)
                    if not bridges[fpr].transports:
                        logging.critical(
                            "We added a transport but it disappeared!")
            except KeyError as error:
                logging.error("Could not find bridge with fingerprint '%s'."
                              % fpr)
        logging.debug("Closing extra-info document")
        fh.close()

    if hasattr(cfg, "COUNTRY_BLOCK_FILE"):
        logging.info("Opening Blocking Countries file %s"
                     % os.path.abspath(cfg.COUNTRY_BLOCK_FILE))
        fh = open(cfg.COUNTRY_BLOCK_FILE, 'r')
        for ID, addr, portlist, cc in Bridges.parseCountryBlockFile(fh):
            if ID in bridges.keys() and bridges[ID].running:
                for port in portlist:
                    logging.debug(":.( Tears! %s blocked %s %s:%s"
                                  % cc, bridges[ID].fingerprint, addr, port)
                    addrport = "{0}:{1}".format(addr, port)
                    try:
                        bridges[ID].blockingCountries[addrport].update(cc)
                    except KeyError:
                        bridges[ID].blockingCountries[addrport] = set(cc)
        logging.debug("Closing blocking-countries document")
        fh.close() 

    bridges = None
    return splitter

def _reloadFn(*args, **kwargs):
    """Placeholder callback function for :func:`_handleSIGHUP`."""
    return True

def _handleSIGHUP(*args):
    """Called when we receive a SIGHUP; invokes _reloadFn."""
    reactor.callLater(0, _reloadFn, *args)

def reloadServers(cfg, options, splitter, proxyList, distributors, tasks):
    """Reload settings, proxy lists, and bridges.

    The contents of the config file should be compiled (it's roughly 20-30
    times faster to use the ``compile`` builtin on a string before ``exec``ing
    it) first, and then ``exec``ed -- not ``execfile``! -- in order to get the
    contents of the config file to exist within the scope of the configuration
    object. Otherwise, Python *will* default to placing them directly within
    the ``globals()`` scope.

    For a more detailed explanation, see http://stackoverflow.com/q/17470193
    and http://lucumr.pocoo.org/2011/2/1/exec-in-python/

    :type cfg: :class:`Conf`
    :param cfg: The current configuration, including any in-memory settings
        (i.e. settings whose values were not obtained from the config file,
        but were set via a function somewhere)
    :type options: :class:`twisted.python.usage.Options`
    :param options: Any commandline options.

    :param splitter: XXX

    :type proxyList: :class:`ProxyCategory`
    :param proxyList: The container for the IP addresses of any currently
         known open proxies.
    :param dict distributors: A dictionary of {'name': Distributor}. See
        :class:`Dist.EmailDistributor` and :class:`Dist.IPDistributor`.
    :param dict tasks: A dictionary of {'name': Task}, where Task is some
        scheduled event, repetitive or otherwise, for the
        :class:`reactor <twisted.internet.epollreactor.EPollReactor>`
    """
    logging.debug("Caught SIGHUP")
    logging.info("Reloading...")
    
    configuration = {}
    if cfg:
        oldConfig = cfg.__dict__
        configuration.update(**oldConfig) # Load current settings
        logging.debug("Using in-memory configurations. Config setting:\n%s"
                      % configuration)
    if options['config']:
        configFile = options['config']
        logging.debug("Reloading settings from config file: '%s'" % configFile)
        compiled = compile(open(configFile).read(), '<string>', 'exec')
        exec compiled in configuration
    # Create a :class:`Conf` from the settings stored within the local scope
    # of the ``configuration`` dictionary:
    cfg = Conf(**configuration)

    # update loglevel on (re)load
    level = getattr(cfg, 'LOGLEVEL', 'WARNING')
    level = getattr(logging, level)
    logging.getLogger().setLevel(level)

    if 'exittask' in tasks:
        #tasks['exittest'].start(3 * 60 * 60) # Run once every three hours
        tasks['exittask'].start(30)

    splitter = load(cfg, splitter, clear=True)
    #proxyList.replaceProxyList(loadProxyList(cfg))
    logging.info("%d bridges loaded", len(splitter))

    if distributors['email']:
        logging.debug("Prepopulating email distributor hashrings...")
        distributors['email'].prepopulateRings() # create default rings
        logging.info("Bridges allotted for email distribution: %d" %
                     len(emailDistributor.splitter))

    if distributors['ip']:
        logging.debug("Prepopulating HTTPS distributor hashrings...")
        distributors['ip'].prepopulateRings() # create default rings
        logging.info("Bridges allotted for web distribution: %d"
                     % len(distributors['ip'].splitter))
        for (n,(f,r)) in distributors['ip'].splitter.filterRings.items():
            logging.info("\tby filter set %s, %d" % (n, len(r)))
        #logging.info("\tby location set: %s"
        #             % " ".join(
        #    [str(len(r)) for r in distributors['ip'].rings]))
        #logging.info("\tby category set: %s"
        #             % " ".join(
        #    [str(len(r)) for r in distributors['ip'].categoryRings]))
        #logging.info("Here are all known bridges in the category section:")
        #for r in ipDistributor.categoryRings:
        #    for name, b in r.bridges.items():
        #        logging.info("%s" % b.getConfigLine(True))
    else:
        logging.warn("NO IP DISTRIBUTOR")

    # Dump bridge pool assignments to disk.
    try:
        logging.debug("Dumping pool assignments to file: '%s'"
                      % cfg.ASSIGNMENTS_FILE)
        f = open(cfg.ASSIGNMENTS_FILE, 'a')
        f.write("bridge-pool-assignment %s\n" %
                time.strftime("%Y-%m-%d %H:%M:%S"))
        splitter.dumpAssignments(f)
        f.flush()
        f.close()
    except IOError:
        logging.info("I/O error while writing assignments")

def startup(cfg, options):
    """Parse bridges,
    """
    # Expand any ~ characters in paths in the configuration.
    cfg.BRIDGE_FILES = [ os.path.expanduser(fn) for fn in cfg.BRIDGE_FILES ]
    for key in ("RUN_IN_DIR", "DB_FILE", "DB_LOG_FILE", "MASTER_KEY_FILE",
                "ASSIGNMENTS_FILE", "HTTPS_CERT_FILE", "HTTPS_KEY_FILE",
                "PIDFILE", "LOGFILE", "STATUS_FILE"):
        v = getattr(cfg, key, None)
        if v:
            setattr(cfg, key, os.path.expanduser(v))

    # Set up logging.
    configureLogging(cfg)

    if options['dump-bridges']:
        bucketManager = Bucket.BucketManager(cfg)
        bucketManager.assignBridgesToBuckets()
        bucketManager.dumpBridges()

    # Only import the runner after logging is set up
    from bridgedb import runner

    if options.subCommand is not None:
        logging.debug("Running subcommand '%s'" % options.subCommand)

        if 'descriptors' in options.subOptions:
            runner.generateDescriptors(options)

        if options.subCommand == 'test':
            if options.subOptions['trial']:
                runner.runTrial(options.subOptions)
            if options.subOptions['unittests']:
                runner.runTests(options.subOptions)
        raise SystemExit("Subcommand '%s' finished." % options.subCommand)

    newProxyList = []
    if not hasattr(cfg, "PROXY_LIST_FILES") or (cfg.PROXY_LIST_FILES is None):
        cfg.PROXY_LIST_FILES = []
    for filename in cfg.PROXY_LIST_FILES:
        fn = os.path.abspath(os.path.expanduser(filename))
        newProxyList.append(fn)
    cfg.PROXY_LIST_FILES = newProxyList

    # Get a proxy list.
    proxyList = proxy.ProxySet()
    proxyList.replaceProxyList(proxy.loadProxiesFromFiles(cfg.PROXY_LIST_FILES,
                                                          proxyList))
    tasks = {}
    if cfg.GET_TOR_EXIT_LIST:
        exittask = task.LoopingCall(proxy.downloadTorExits, proxyList)
        tasks['exittask'] = exittask

    # Write the pidfile.
    if cfg.PIDFILE:
        f = open(cfg.PIDFILE, 'w')
        f.write("%s\n"%os.getpid())
        f.close()

    # Import Servers after logging is set up. Otherwise, python will create a
    # default handler that logs to the console and ignore further basicConfig
    # calls.
    from bridgedb import EmailServer
    from bridgedb import HTTPServer

    # Load the master key, or create a new one.
    key = bridgedb.crypto.getKey(cfg.MASTER_KEY_FILE)
    # Initialize our DB file.
    db = bridgedb.Storage.Database(cfg.DB_FILE + ".sqlite", cfg.DB_FILE)
    bridgedb.Storage.setGlobalDB(db)

    # Create a BridgeSplitter to assign the bridges to the different
    # distributors.
    splitter = Bridges.BridgeSplitter(Bridges.get_hmac(key, "Splitter-Key"))
    logging.debug("Created splitter: %r" % splitter)

    # Create ring parameters.
    forcePorts = getattr(cfg, "FORCE_PORTS", [])
    forceFlags = getattr(cfg, "FORCE_FLAGS", [])
    ringParams = Bridges.BridgeRingParameters(needPorts=forcePorts,
                                              needFlags=forceFlags)
    ipDist = setupIPDistributor(cfg, ringParams, key, proxyList)
    emailDist = setupEmailDistributor(cfg, ringParams, key)
    splitter.addRing(ipDist, "https", cfg.HTTPS_SHARE)
    splitter.addRing(emailDist, "email", cfg.EMAIL_SHARE)

    distributors = {'email': emailDist, 'ip': ipDist}

    #webSchedule = Time.IntervalSchedule("day", 2)
    webSchedule = Time.NoSchedule()
    #emailSchedule = Time.IntervalSchedule("day", 1)
    emailSchedule = Time.NoSchedule()

    # As appropriate, tell the splitter to leave some bridges unallocated.
    if cfg.RESERVED_SHARE:
        splitter.addRing(Bridges.UnallocatedHolder(), "unallocated",
                         cfg.RESERVED_SHARE)

    # Add pseudo distributors to splitter
    for p in cfg.FILE_BUCKETS.keys():
        splitter.addPseudoRing(p)

    global _reloadFn
    _reloadFn = reloadServers
    signal.signal(signal.SIGHUP, _handleSIGHUP)

    # And actually load it to start parsing.
    reloadServers(cfg, options, splitter, proxyList, distributors, tasks)

    # Configure the servers:
    if cfg.HTTPS_DIST and cfg.HTTPS_SHARE:
        HTTPServer.addWebServer(cfg, distributors['ip'], webSchedule)
    if cfg.EMAIL_DIST and cfg.EMAIL_SHARE:
        EmailServer.addSMTPServer(cfg, distributors['email'], emailSchedule)

    # Actually run the servers.
    try:
        logging.info("Starting reactors.")
        reactor.run()
    finally:
        db.close()
        if cfg.PIDFILE:
            os.unlink(cfg.PIDFILE)
        sys.exit()

def run(options):
    """This is the main entry point into BridgeDB.

    Given the parsed commandline options, this function handles locating the
    configuration file, loading and parsing it, and then either
    starting/reloading the servers or dumping bridge assignments to files.

    :type options: :class:`bridgedb.opt.MainOptions`
    :param options: A pre-parsed options class.
    """
    # Change to the directory where we're supposed to run.
    if options['rundir']:
        os.chdir(options['rundir'])

    configuration = {}
    compiled = compile(open(options['config']).read(), '<string>', 'exec')
    exec compiled in configuration
    cfg = Conf(**configuration)

    startup(cfg, options)

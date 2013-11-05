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

from twisted.internet import reactor

from bridgedb.parse import options

import bridgedb.crypto
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
        logging.info("Opening Network Status document %s", os.path.abspath(cfg.STATUS_FILE))
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
        logging.info("Opening cached Descriptor document %s", fname)
        logging.debug("Parsing document for purpose=%s", cfg.BRIDGE_PURPOSE)
        f = open(fname, 'r')
        for bridge in Bridges.parseDescFile(f, cfg.BRIDGE_PURPOSE):
            if bridge.getID() in bridges:
                logging.warn(
                    "Parsed bridge that we've already added. Skipping.")
                logging.debug("  Bridge: %s" % bridge.getID())
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
        logging.debug("Closing descriptor document")
        f.close()

    # read pluggable transports from extra-info document
    # XXX: should read from networkstatus after bridge-authority
    # does a reachability test
        logging.info("Opening extra-info document: '%s'" % cfg.EXTRA_INFO_FILE)
        f = open(cfg.EXTRA_INFO_FILE, 'r')
        for transport in Bridges.parseExtraInfoFile(f):
            ID, method_name, address, port, argdict = transport
            if bridges[ID].running:
                logging.debug("  Appending transport to running bridge")
                bridgePT = Bridges.PluggableTransport(
                    bridges[ID], method_name, address, port, argdict)
                bridges[ID].transports.append(bridgePT)
                assert bridges[ID].transports, "We added a transport but it disappeared!"
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

_reloadFn = lambda x: True
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
    if hasattr(cfg, "PROXY_LIST_FILES"):
        cfg.PROXY_LIST_FILES = [
            os.path.expanduser(v) for v in cfg.PROXY_LIST_FILES ]
    else:
        cfg.PROXY_LIST_FILES = []

    # Write the pidfile.
    if cfg.PIDFILE:
        f = open(cfg.PIDFILE, 'w')
        f.write("%s\n" % os.getpid())
        f.close()

    # Set up logging.
    configureLogging(cfg)

    # Import Servers after logging is set up. Otherwise, python will create a
    # default handler that logs to the console and ignore further basicConfig
    # calls.
    from bridgedb import EmailServer
    from bridgedb import HTTPServer

    # Load the master key, or create a new one.
    key = bridgedb.crypto.getKey(cfg.MASTER_KEY_FILE)

    # Initialize our DB file.
    db = bridgedb.Storage.Database(cfg.DB_FILE+".sqlite",
                                   cfg.DB_FILE)
    bridgedb.Storage.setGlobalDB(db)

    # Get a proxy list.
    proxyList = ProxyCategory()
    proxyList.replaceProxyList(loadProxyList(cfg))

    # Create a BridgeSplitter to assign the bridges to the different
    # distributors.
    splitter = Bridges.BridgeSplitter(Bridges.get_hmac(key, "Splitter-Key"))

    # Create ring parameters.
    forcePorts = getattr(cfg, "FORCE_PORTS")
    forceFlags = getattr(cfg, "FORCE_FLAGS")
    if not forcePorts: forcePorts = []
    if not forceFlags: forceFlags = []
    ringParams=Bridges.BridgeRingParameters(needPorts=forcePorts,
                                            needFlags=forceFlags)

    emailDistributor = ipDistributor = None
    # As appropriate, create an IP-based distributor.
    if cfg.HTTPS_DIST and cfg.HTTPS_SHARE:
        categories = []
        if proxyList.ipset:
            categories.append(proxyList)
        ipDistributor = Dist.IPBasedDistributor(
            Dist.uniformMap,
            cfg.N_IP_CLUSTERS,
            Bridges.get_hmac(key, "HTTPS-IP-Dist-Key"),
            categories,
            answerParameters=ringParams)
        splitter.addRing(ipDistributor, "https", cfg.HTTPS_SHARE)
        #webSchedule = Time.IntervalSchedule("day", 2)
        webSchedule = Time.NoSchedule()

    # As appropriate, create an email-based distributor.
    if cfg.EMAIL_DIST and cfg.EMAIL_SHARE:
        for d in cfg.EMAIL_DOMAINS:
            cfg.EMAIL_DOMAIN_MAP[d] = d
        emailDistributor = Dist.EmailBasedDistributor(
            Bridges.get_hmac(key, "Email-Dist-Key"),
            cfg.EMAIL_DOMAIN_MAP.copy(),
            cfg.EMAIL_DOMAIN_RULES.copy(),
            answerParameters=ringParams)
        splitter.addRing(emailDistributor, "email", cfg.EMAIL_SHARE)
        #emailSchedule = Time.IntervalSchedule("day", 1)
        emailSchedule = Time.NoSchedule()

    # As appropriate, tell the splitter to leave some bridges unallocated.
    if cfg.RESERVED_SHARE:
        splitter.addRing(Bridges.UnallocatedHolder(),
                         "unallocated",
                         cfg.RESERVED_SHARE)

    # Add pseudo distributors to splitter
    for p in cfg.FILE_BUCKETS.keys():
        splitter.addPseudoRing(p)

    # Make the parse-bridges function get re-called on SIGHUP.
    def reload(*args):
        logging.info("Caught SIGHUP")

        # reparse the config file
        configuration = {}
        if options['config']:
            execfile(options['config'], configuration)
            cfg = Conf(**configuration)
            # update loglevel on (re)load
            level = getattr(cfg, 'LOGLEVEL', 'WARNING')
            level = getattr(logging, level)
            logging.getLogger().setLevel(level)

        load(cfg, splitter, clear=True)
        proxyList.replaceProxyList(loadProxyList(cfg))
        logging.info("%d bridges loaded", len(splitter))
        if emailDistributor:
            emailDistributor.prepopulateRings() # create default rings
            logging.info("%d for email", len(emailDistributor.splitter))
        if ipDistributor:
            ipDistributor.prepopulateRings() # create default rings
            logging.info("%d for web:", len(ipDistributor.splitter))
            for (n,(f,r)) in ipDistributor.splitter.filterRings.items():
                logging.info("\tby filter set %s, %d" % (n, len(r)))
            #logging.info("  by location set: %s",
            #             " ".join(str(len(r)) for r in ipDistributor.rings))
            #logging.info("  by category set: %s",
            #             " ".join(str(len(r)) for r in ipDistributor.categoryRings))
            #logging.info("Here are all known bridges in the category section:")
            #for r in ipDistributor.categoryRings:
            #    for name, b in r.bridges.items():
            #        logging.info("%s" % b.getConfigLine(True))

        # Dump bridge pool assignments to disk.
        try:
            logging.debug("Dumping pool assignments file")
            f = open(cfg.ASSIGNMENTS_FILE, 'a')
            f.write("bridge-pool-assignment %s\n" %
                    time.strftime("%Y-%m-%d %H:%M:%S"))
            splitter.dumpAssignments(f)
            f.close()
        except IOError:
            logging.info("I/O error while writing assignments")

    global _reloadFn
    _reloadFn = reload
    signal.signal(signal.SIGHUP, _handleSIGHUP)

    # And actually load it to start.
    reload(options)

    # Configure HTTP and/or HTTPS servers.
    if cfg.HTTPS_DIST and cfg.HTTPS_SHARE:
        HTTPServer.addWebServer(cfg, ipDistributor, webSchedule)

    # Configure Email servers.
    if cfg.EMAIL_DIST and cfg.EMAIL_SHARE:
        EmailServer.addSMTPServer(cfg, emailDistributor, emailSchedule)

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
    configuration = {}

    if not options['config']:
        options.getUsage()
        sys.exit(1)

    # Change to the directory where we're supposed to run.
    if options['rundir']:
        os.chdir(options['rundir'])

    execfile(options['config'], configuration)
    config = Conf(**configuration)

    if options['dump-bridges']:
        bucketManager = Bucket.BucketManager(config)
        bucketManager.assignBridgesToBuckets()
        bucketManager.dumpBridges()
    else:
        startup(config, options)

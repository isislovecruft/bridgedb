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
import gettext

from twisted.internet import reactor

import bridgedb.log as log
import bridgedb.Util as util
import bridgedb.config as config
import bridgedb.Bridges as Bridges
import bridgedb.Dist as Dist
import bridgedb.Time as Time
import bridgedb.Storage
import bridgedb.Opt as Opt
import bridgedb.Bucket as Bucket


def getKey(fname):
    """Load the key stored in fname, or create a new 32-byte key and store
       it in fname.

    >>> name = os.tmpnam()
    >>> os.path.exists(name)
    False
    >>> k1 = getKey(name)
    >>> os.path.exists(name)
    True
    >>> open(name).read() == k1
    True
    >>> k2 = getKey(name)
    >>> k1 == k2
    True
    """
    try:
        f = open(fname, 'rb')
    except IOError:
        k = os.urandom(32)
        flags = os.O_WRONLY|os.O_TRUNC|os.O_CREAT|getattr(os, "O_BIN", 0)
        fd = os.open(fname, flags, 0400)
        os.write(fd, k)
        os.close(fd)
    else:
        k = f.read()
        f.close()

    return k

def beginLogging(conf, rundir):
    """Configure and begin logging.

    1) Get the filename for our main logfile, and if we should log to stdout.
    2) Expand the directory name to keep logfiles in and set it to
       ``log.folder``.
    3) Configure the logging level.
    4) Start the log publisher, :class:`bridgedb.log.BridgeDBLogPublisher`.

    :param conf: A :class:`bridgedb.config.Conf` configuration object.
    :param rundir: The absolute path of the RUN_IN_DIR bridgedb.conf setting.
    """
    logfile = conf.get('LOGFILE', 'bridgedb.log')
    lstdout = conf.get('LOG_STDOUT', True)
    ldirect = os.path.join(rundir, conf.get('LOGDIR', 'log'))
    logdir  = Util.touch(ldirect, directory=True)
    conf['LOGDIR'] = logdir

    log.folder = logdir
    log.setLevel(conf.LOGLEVEL)
    log.startLogging(logfile, lstdout)

def load(cfg, splitter, clear=False):
    """Read all the bridge files from cfg, and pass them into a splitter
       object.
    """
    if clear:
        log.info("Clearing old bridges")
        splitter.clear()
    log.info("Loading bridges")
    status = {}
    addresses = {}
    timestamps = {}
    if hasattr(cfg, "STATUS_FILE"):
        f = open(cfg.STATUS_FILE, 'r')
        for ID, running, stable, or_addresses, timestamp in Bridges.parseStatusFile(f):
            status[ID] = running, stable
            addresses[ID] = or_addresses
            if ID in timestamps.keys(): timestamps[ID].append(timestamp)
            else: timestamps[ID] = [timestamp]
            #transports[ID] = transports
        f.close()
    bridges = {} 
    db = bridgedb.Storage.getDB()
    for fname in cfg.BRIDGE_FILES:
        f = open(fname, 'r')
        for bridge in Bridges.parseDescFile(f, cfg.BRIDGE_PURPOSE):
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
                    bridgedb.Stability.addOrUpdateBridgeHistory(bridge, timestamp)
        f.close()
    # read pluggable transports from extra-info document
    # XXX: should read from networkstatus after bridge-authority
    # does a reachability test
    if cfg.EXTRA_INFO_FILE is not None:
        f = open(cfg.EXTRA_INFO_FILE, 'r')
        for transport in Bridges.parseExtraInfoFile(f):
            ID, method_name, address, port, argdict = transport
            if bridges[ID].running:
                bridges[ID].transports.append(Bridges.PluggableTransport(bridges[ID],
                    method_name, address, port, argdict))
    if cfg.COUNTRY_BLOCK_FILE is not None:
        f = open(cfg.COUNTRY_BLOCK_FILE, 'r')
        for ID,address,portlist,countries in Bridges.parseCountryBlockFile(f):
            if ID in bridges.keys() and bridges[ID].running:
                for port in portlist:
                    log.debug(":.( Tears! %s blocked %s %s:%s" % (
                        countries, bridges[ID].fingerprint, address, port))
                    try:
                        bridges[ID].blockingCountries["%s:%s" % \
                                (address, port)].update(countries)
                    except KeyError:
                        bridges[ID].blockingCountries["%s:%s" % \
                                (address, port)] = set(countries)
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

_reloadFn = lambda: True
def _handleSIGHUP(*args):
    """Called when we receive a SIGHUP; invokes _reloadFn."""
    reactor.callLater(0, _reloadFn)

class ProxyCategory:
    def __init__(self):
        self.ipset = {}
    def contains(self, ip):
        return self.ipset.has_key(ip)
    def replaceProxyList(self, ipset):
        self.ipset = ipset

def reconfigure(configuration=None):
    """Take the options and reconfigure our settings.

    This is used at startup to load our config file, and after handling a
    SIGHUP, to reload any new settings.

    Parse the command line to determine where the configuration file is, and
    whether or not we are in testing mode (the '-t' flag). Parse the
    configuration file, and apply those settings, and then, if extra settings
    were given in :attr:`bridgedb.config.TESTING_CONFIG`, apply those settings
    on top of the settings from the configuration file.
    """
    options, arguments = Opt.parseOpts()
    settings = {}

    if options.testing:
        settings = config.TESTING_CONFIG
    if not configuration:
        configuration = config.Conf()

    if options.configfile:
        configuration.load(options.configfile)
    elif not (len(settings) > 0):
        raise SystemExit("Syntax: %s -c CONFIGFILE" % sys.argv[0])

    configuration.update(**settings)
    return options, configuration

def startup(cfg):
    """Parse config files,

    :ivar rundir: The run directory, taken from ``conf.RUN_IN_DIR``. Defaults
        to the current working directory if not set.
    :ivar logdir: The directory to store logfiles in. Defaults to rundir/log/.
    """
    rundir = util.touch(cfg.RUN_IN_DIR)
    os.chdir(rundir)

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
        cfg.PROXY_LIST_FILES = [ ]

    # Write the pidfile.
    if cfg.PIDFILE:
        with open(cfg.PIDFILE, 'w') as pidfile:
            pidfile.write("{}\n".format(os.getpid()))

    # Set up logging.
    beginLogging(cfg, rundir)

    # Import Servers after logging is set up
    # Otherwise, python will create a default handler that logs to
    # the console and ignore further basicConfig calls
    from bridgedb import EmailServer
    from bridgedb import HTTPServer

    # Load the master key, or create a new one.
    key = getKey(cfg.MASTER_KEY_FILE)

    # Initialize our DB file.
    dbfile = cfg.get('DB_FILE')
    db = bridgedb.Storage.Database(dbfile + ".sqlite", dbfile)
    bridgedb.Storage.setGlobalDB(db)

    # Get a proxy list.
    proxyList = ProxyCategory()
    proxyList.replaceProxyList(loadProxyList(cfg))

    # Create a BridgeSplitter to assign the bridges to the different
    # distributors.
    splitter = Bridges.BridgeSplitter(Bridges.get_hmac(key, "Splitter-Key"))

    # Create ring parameters.
    forcePorts = cfg.get("FORCE_PORTS", list())
    forceFlags = cfg.get("FORCE_FLAGS", list())
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
            cfg['EMAIL_DOMAIN_MAP'].copy(),
            cfg['EMAIL_DOMAIN_RULES'].copy(),
            answerParameters=ringParams)
        splitter.addRing(emailDistributor, "email", cfg.EMAIL_SHARE)
        #emailSchedule = Time.IntervalSchedule("day", 1)
        emailSchedule = Time.NoSchedule()

    # As appropriate, tell the splitter to leave some bridges unallocated.
    reserved = cfg.get('RESERVED_SHARE')
    if reserved:
        splitter.addRing(Bridges.UnallocatedHolder(), "unallocated", reserved)

    # Add pseudo distributors to splitter
    for p in cfg.FILE_BUCKETS.keys():
        splitter.addPseudoRing(p)

    # Make the parse-bridges function get re-called on SIGHUP.
    def reload():
        log.info("Caught SIGHUP")
        reconfigure(cfg)

        load(cfg, splitter, clear=True)
        proxyList.replaceProxyList(loadProxyList(cfg))
        log.info("%d bridges loaded", len(splitter))
        if emailDistributor:
            emailDistributor.prepopulateRings() # create default rings
            log.info("%d for email", len(emailDistributor.splitter))
        if ipDistributor:
            ipDistributor.prepopulateRings() # create default rings
            log.info("%d for web:", len(ipDistributor.splitter))
            for (n,(f,r)) in ipDistributor.splitter.filterRings.items():
                    log.info(" by filter set %s, %d" % (n, len(r)))
            #log.info("  by location set: %s",
            #         " ".join(str(len(r)) for r in ipDistributor.rings))
            #log.info("  by category set: %s",
            #         " ".join(str(len(r)) for r in ipDistributor.categoryRings))
            #log.info("Here are all known bridges in the category section:")
            #for r in ipDistributor.categoryRings:
            #    for name, b in r.bridges.items():
            #        log.info("%s" % b.getConfigLine(True))

        # Dump bridge pool assignments to disk.
        try:
            f = open(cfg.ASSIGNMENTS_FILE, 'a')
            f.write("bridge-pool-assignment %s\n" %
                    time.strftime("%Y-%m-%d %H:%M:%S"))
            splitter.dumpAssignments(f)
            f.close()
        except IOError:
            log.info("I/O error while writing assignments")

    global _reloadFn
    _reloadFn = reload
    signal.signal(signal.SIGHUP, _handleSIGHUP)

    # And actually load it to start.
    reload()

    # Configure HTTP and/or HTTPS servers.
    if cfg.HTTPS_DIST and cfg.HTTPS_SHARE:
        HTTPServer.addWebServer(cfg, ipDistributor, webSchedule)

    # Configure Email servers.
    if cfg.EMAIL_DIST and cfg.EMAIL_SHARE:
        EmailServer.addSMTPServer(cfg, emailDistributor, emailSchedule)

    # Actually run the servers.
    try:
        log.info("Starting reactors.")
        reactor.run()
    finally:
        db.close()
        if cfg.PIDFILE:
            os.unlink(cfg.PIDFILE)

def run():
    """Start running BridgeDB and all configured servers.

    If the option to dump bridges into bucket files is given, do that. Else,
    start all the servers.
    """
    options, configuration = reconfigure()

    if options.dumpbridges:
        bucketManager = Bucket.BucketManager(configuration)
        bucketManager.assignBridgesToBuckets()
        bucketManager.dumpBridges()
    else:
        startup(configuration)

if __name__ == '__main__':
    run()

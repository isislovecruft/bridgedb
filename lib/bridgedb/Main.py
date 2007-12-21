# BridgeDB by Nick Mathewson.
# Copyright (c) 2007, The Tor Project, Inc.
# See LICENSE for licensing information

"""
This module sets up a bridgedb and starts the servers running.
"""

import anydbm
import os
import signal
import sys
import logging

from twisted.internet import reactor

import bridgedb.Bridges as Bridges
import bridgedb.Dist as Dist
import bridgedb.Time as Time
import bridgedb.Server as Server

class Conf:
    """A configuration object.  Holds unvalidated attributes.
    """
    def __init__(self, **attrs):
        self.__dict__.update(attrs)

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

    HTTPS_DIST = True,
    HTTPS_SHARE=10,
    HTTPS_BIND_IP=None,
    HTTPS_PORT=6789,
    HTTPS_CERT_FILE="cert",
    HTTPS_KEY_FILE="privkey.pem",
    HTTP_UNENCRYPTED_BIND_IP=None,
    HTTP_UNENCRYPTED_PORT=6788,
    HTTPS_N_BRIDGES_PER_ANSWER=2,

    EMAIL_DIST = True,
    EMAIL_SHARE=10,
    EMAIL_DOMAINS = [ "gmail.com", "yahoo.com", "catbus.wangafu.net" ],
    EMAIL_DOMAIN_MAP = { "mail.google.com" : "gmail.com",
                         "googlemail.com" : "gmail.com", },
    EMAIL_RESTRICT_IPS=[],
    EMAIL_BIND_IP=None,
    EMAIL_PORT=6725,
    EMAIL_N_BRIDGES_PER_ANSWER=2,

    RESERVED_SHARE=2,
  )

def configureLogging(cfg):
    """Set up Python's logging subsystem based on the configuratino.
    """
    level = getattr(cfg, 'LOGLEVEL', 'WARNING')
    level = getattr(logging, level)
    extra = {}
    if getattr(cfg, "LOGFILE"):
        extra['filename'] = cfg.LOGFILE

    logging.basicConfig(format='%(asctime)s [%(levelname)s] %(message)s',
                        datefmt="%b %d %H:%M:%S",
                        level=level,
                        **extra)

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

def load(cfg, splitter):
    """Read all the bridge files from cfg, and pass them into a splitter
       object.
    """
    status = {}
    if cfg.STATUS_FILE:
        f = open(cfg.STATUS_FILE, 'r')
        for ID, running in Bridges.parseStatusFile(f):
            status[ID] = running
    for fname in cfg.BRIDGE_FILES:
        f = open(fname, 'r')
        for bridge in Bridges.parseDescFile(f, cfg.BRIDGE_PURPOSE):
            running = status.get(bridge.getID())
            if running is not None:
                bridge.setStatus(running=running)
            splitter.insert(bridge)
        f.close()

_reloadFn = lambda: True
def _handleSIGHUP(*args):
    """Called when we receive a SIGHUP; invokes _reloadFn."""
    reactor.callLater(0, _reloadFn)

def startup(cfg):
    """Parse bridges, 
    """
    # Expand any ~ characters in paths in the configuration.
    cfg.BRIDGE_FILES = [ os.path.expanduser(fn) for fn in cfg.BRIDGE_FILES ]
    for key in ("RUN_IN_DIR", "DB_FILE", "DB_LOG_FILE", "MASTER_KEY_FILE",
                "HTTPS_CERT_FILE", "HTTPS_KEY_FILE", "PIDFILE", "LOGFILE"):
        v = getattr(cfg, key)
        if v:
            setattr(cfg, key, os.path.expanduser(v))

    # Change to the directory where we're supposed to run.
    if cfg.RUN_IN_DIR:
        os.chdir(cfg.RUN_IN_DIR)

    # Write the pidfile.
    if cfg.PIDFILE:
        f = open(cfg.PIDFILE, 'w')
        f.write("%s\n"%os.getpid())
        f.close()

    # Set up logging.
    configureLogging(cfg)

    # Load the master key, or create a new one.
    key = getKey(cfg.MASTER_KEY_FILE)

    # Initialize our DB file.
    dblogfile = None
    baseStore = store = anydbm.open(cfg.DB_FILE, "c", 0600)
    if cfg.DB_LOG_FILE:
        dblogfile = open(cfg.DB_LOG_FILE, "a+", 0)
        store = Bridges.LogDB(None, store, dblogfile)

    # Create a BridgeSplitter to assign the bridges to the different
    # distributors.
    splitter = Bridges.BridgeSplitter(Bridges.get_hmac(key, "Splitter-Key"),
                                      Bridges.PrefixStore(store, "sp|"))

    emailDistributor = ipDistributor = None
    # As appropriate, create an IP-based distributor.
    if cfg.HTTPS_DIST and cfg.HTTPS_SHARE:
        ipDistributor = Dist.IPBasedDistributor(
            Dist.uniformMap,
            cfg.N_IP_CLUSTERS,
            Bridges.get_hmac(key, "HTTPS-IP-Dist-Key"))
        splitter.addRing(ipDistributor, "https", cfg.HTTPS_SHARE)
        webSchedule = Time.IntervalSchedule("day", 2)

    # As appropriate, create an email-based distributor.
    if cfg.EMAIL_DIST and cfg.EMAIL_SHARE:
        for d in cfg.EMAIL_DOMAINS:
            cfg.EMAIL_DOMAIN_MAP[d] = d
        emailDistributor = Dist.EmailBasedDistributor(
            Bridges.get_hmac(key, "Email-Dist-Key"),
            Bridges.PrefixStore(store, "em|"),
            cfg.EMAIL_DOMAIN_MAP.copy())
        splitter.addRing(emailDistributor, "email", cfg.EMAIL_SHARE)
        emailSchedule = Time.IntervalSchedule("day", 1)

    # As appropriate, tell the splitter to leave some bridges unallocated.
    if cfg.RESERVED_SHARE:
        splitter.addRing(Bridges.UnallocatedHolder(),
                         "unallocated",
                         cfg.RESERVED_SHARE)

    # Add a tracker to tell us how often we've seen various bridges.
    stats = Bridges.BridgeTracker(Bridges.PrefixStore(store, "fs|"),
                                  Bridges.PrefixStore(store, "ls|"))
    splitter.addTracker(stats)

    # Parse the bridges and log how many we put where.
    logging.info("Loading bridges")
    load(cfg, splitter)
    logging.info("%d bridges loaded", len(splitter))
    if emailDistributor:
        logging.info("%d for email", len(emailDistributor.ring))
    if ipDistributor:
        logging.info("%d for web:", len(ipDistributor.splitter))
        logging.info("  by location set: %s",
                     " ".join(str(len(r)) for r in ipDistributor.rings))

    # Configure HTTP and/or HTTPS servers.
    if cfg.HTTPS_DIST and cfg.HTTPS_SHARE:
        Server.addWebServer(cfg, ipDistributor, webSchedule)

    # Configure Email servers.
    if cfg.EMAIL_DIST and cfg.EMAIL_SHARE:
        Server.addSMTPServer(cfg, emailDistributor, emailSchedule)

    # Make the parse-bridges function get re-called on SIGHUP.
    def reload():
        logging.info("Caught SIGHUP")
        load(cfg, splitter)
    global _reloadFn
    _reloadFn = reload
    signal.signal(signal.SIGHUP, _handleSIGHUP)

    # Actually run the servers.
    try:
        logging.info("Starting reactors.")
        Server.runServers()
    finally:
        baseStore.close()
        if dblogfile is not None:
            dblogfile.close()
        if cfg.PIDFILE:
            os.unlink(cfg.PIDFILE)

def run():
    """Parse the command line to determine where the configuration is.
       Parse the configuration, and start the servers.
    """
    if len(sys.argv) != 2:
        print "Syntax: %s [config file]" % sys.argv[0]
        sys.exit(1)
    if sys.argv[1] == "TESTING":
        configuration = CONFIG
    else:
        configuration = {}
        execfile(sys.argv[1], configuration)
        C = Conf(**configuration)
        configuration = C

    startup(configuration)

if __name__ == '__main__':
    run()

# BridgeDB by Nick Mathewson.
# Copyright (c) 2007, The Tor Project, Inc.
# See LICENSE for licensing informatino

import anydbm
import os
import signal
import sys

from twisted.internet import reactor

import bridgedb.Bridges as Bridges
import bridgedb.Dist as Dist
import bridgedb.Time as Time
import bridgedb.Server as Server

class Conf:
    def __init__(self, **attrs):
        self.__dict__.update(attrs)

CONFIG = Conf(
    RUN_IN_DIR = ".",

    BRIDGE_FILES = [ "./cached-descriptors", "./cached-descriptors.new" ],
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
    for fname in cfg.BRIDGE_FILES:
        f = open(fname, 'r')
        for bridge in Bridges.parseDescFile(f, cfg.BRIDGE_PURPOSE):
            splitter.insert(bridge)
        f.close()

_reloadFn = None
def _handleSIGHUP(*args):
    reactor.callLater(0, _reloadFn)

def startup(cfg):
    cfg.BRIDGE_FILES = [ os.path.expanduser(fn) for fn in cfg.BRIDGE_FILES ]
    for key in ("RUN_IN_DIR", "DB_FILE", "DB_LOG_FILE", "MASTER_KEY_FILE",
                "HTTPS_CERT_FILE", "HTTPS_KEY_FILE"):
        v = getattr(cfg, key)
        if v:
            setattr(cfg, key, os.path.expanduser(v))

    if cfg.RUN_IN_DIR:
        os.chdir(cfg.RUN_IN_DIR)

    key = getKey(cfg.MASTER_KEY_FILE)
    dblogfile = None
    emailDistributor = ipDistributor = None

    baseStore = store = anydbm.open(cfg.DB_FILE, "c", 0600)
    if cfg.DB_LOG_FILE:
        dblogfile = open(cfg.DB_LOG_FILE, "a+", 0)
        store = Bridges.LogDB("db", store, dblogfile)

    splitter = Bridges.BridgeSplitter(Bridges.get_hmac(key, "Splitter-Key"),
                                      Bridges.PrefixStore(store, "sp|"))

    if cfg.HTTPS_DIST and cfg.HTTPS_SHARE:
        ipDistributor = Dist.IPBasedDistributor(
            Dist.uniformMap,
            cfg.N_IP_CLUSTERS,
            Bridges.get_hmac(key, "HTTPS-IP-Dist-Key"))
        splitter.addRing(ipDistributor, "https", cfg.HTTPS_SHARE)
        webSchedule = Time.IntervalSchedule("day", 2)

    if cfg.EMAIL_DIST and cfg.EMAIL_SHARE:
        for d in cfg.EMAIL_DOMAINS:
            cfg.EMAIL_DOMAIN_MAP[d] = d
        emailDistributor = Dist.EmailBasedDistributor(
            Bridges.get_hmac(key, "Email-Dist-Key"),
            Bridges.PrefixStore(store, "em|"),
            cfg.EMAIL_DOMAIN_MAP.copy())
        splitter.addRing(emailDistributor, "email", cfg.EMAIL_SHARE)
        emailSchedule = Time.IntervalSchedule("day", 1)

    if cfg.RESERVED_SHARE:
        splitter.addRing(Bridges.UnallocatedHolder(),
                         "unallocated",
                         cfg.RESERVED_SHARE)

    stats = Bridges.BridgeTracker(Bridges.PrefixStore(store, "fs|"),
                                  Bridges.PrefixStore(store, "ls|"))
    splitter.addTracker(stats)

    print "Loading bridges"
    load(cfg, splitter)
    print "%d bridges loaded" % len(splitter)
    if emailDistributor:
        print "%d for email" % len(emailDistributor.ring)
    if ipDistributor:
        print "%d for web:" % len(ipDistributor.splitter)
        print "  by location set:", " ".join(str(len(r)) for r in ipDistributor.rings)

    if cfg.HTTPS_DIST and cfg.HTTPS_SHARE:
        Server.addWebServer(cfg, ipDistributor, webSchedule)

    if cfg.EMAIL_DIST and cfg.EMAIL_SHARE:
        Server.addSMTPServer(cfg, emailDistributor, emailSchedule)

    def reload():
        load(cfg, splitter)

    global _reloadFn
    _reloadFn = reload
    signal.signal(signal.SIGHUP, _handleSIGHUP)

    try:
        print "Starting reactors."
        Server.runServers()
    finally:
        baseStore.close()
        if dblogfile is not None:
            dblogfile.close()

if __name__ == '__main__':
    if len(sys.argv) != 2:
        print "Syntax: %s [config file]" % sys.argv[0]
        sys.exit(1)
    if sys.argv[1] == "TESTING":
        configuration = CONFIG
    else:
        configuration = {}
        execfile(sys.argv[1], configuration)

    startup(CONFIG)

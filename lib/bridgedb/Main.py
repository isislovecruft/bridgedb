# BridgeDB by Nick Mathewson.
# Copyright (c) 2007, The Tor Project, Inc.
# See LICENSE for licensing informatino

import anydbm

import os
import sys

import bridgedb.Bridges as Bridges
import bridgedb.Dist as Dist

class Conf:
    def __init__(self, **attrs):
        self.__dict__.update(attrs)

CONFIG = Conf(
    BRIDGE_FILES = [ "./cached-descriptors", "./cached-descriptors.new" ],
    BRIDGE_PURPOSE = "bridge",
    DB_FILE = [ "./bridgedist" ],
    DB_LOG_FILE = [ "./bridgedist.log" ],
    HTTPS_DIST = True,
    EMAIL_DIST = True,
    N_IP_CLUSTERS = 8,
    MASTER_KEY_FILE = [ "./secret_key" ],
    HTTPS_SHARE=10,
    EMAIL_SHARE=10,
    EMAIL_DOMAINS = [ "gmail.com", "yahoo.com" ],
    EMAIL_DOMAIN_MAP = { "mail.google.com" : "gmail.com",
                         "googlemail.com" : "gmail.com", },
    RESERVED_SHARE=2,
  )

def getKey(fname):
    try:
        f = open(fname, 'r')
    except IOError:
        k = os.urandom(32)
        flags = os.O_WRONLY|os.O_TRUNC|getattr(os, "O_BIN", 0)
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

def startup(cfg):
    key = getKey(MASTER_KEY_FILE)

    store = anydbm.open(cfg.DB_FILE, "c", 0600)
    if DB_LOG_FILE:
        dblogfile = open(cfg.DB_LOG_FILE, "a+", 0)
        store = LogDB("db", store, dblogfile)

    splitter = Bridges.BridgeSplitter(Bridges.get_hmac(key, "Splitter-Key"),
                                      Bridges.PrefixStore(store, "sp|"))

    if cfg.HTTPS_DIST and cfg.HTTPS_SHARE:
        ipDistrbutor = Dist.ipBasedDistributor(Dist.uniformMap,
                                 Dist.N_IP_CLUSTERS,
                                 Bridges.get_hmac(key, "HTTPS-IP-Dist-Key"))
        splitter.addRing(ipDistributor, "https", cfg.HTTPS_SHARE)

    if cfg.EMAIL_DIST and cfg.EMAIL_SHARE:
        for d in cfg.EMAIL_DOMAINS:
            cfg.EMAIL_DOMAIN_MAP[d] = d
        emailDistributor = Dist.emailBasedDistributor(
            Bridges.get_hmac(key, "Email-Dist-Key"),
            Bridges.PrefixStore(store, "em|"),
            cfg.EMAIL_DOMAIN_MAP.copy())
        splitter.addRing(emailDistributor, "email", cfg.EMAIL_SHARE)

    if cfg.RESERVED_SHARE:
        splitter.addRing(Bridges.UnallocatedHolder(),
                         "unallocated",
                         cfg.RESERVED_SHARE)

    stats = Bridges.BridgeTracker(Bridges.PrefixStore(store, "fs"),
                                  Bridges.PrefixStore(store, "ls"))
    splitter.addTracker(stats)

    load(cfg, splitter)

    # XXXX create twisted listeners.


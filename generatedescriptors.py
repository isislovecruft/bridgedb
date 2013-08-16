#!/usr/sbin/env python -tt

import sys
import random
import time
import ipaddr
from datetime import datetime
import binascii


def randomIP():
    return randomIP4()

def randomIP4():
    return ipaddr.IPAddress(random.getrandbits(32))

def randomPort():
    return random.randint(1,65535)

def gettimestamp():
    ts = time.strftime("%Y-%m-%d %H:%M:%S")
    return "opt published %s\n" % ts

def getHexString(size):
    s = ""
    for i in xrange(size):
        s+= random.choice("ABCDEF0123456789") 
    return s


baseDesc = "router Unnamed %s %s 0 9030\n"\
"opt fingerprint %s\n"\
"opt @purpose bridge\n"

baseStatus = "r %s %s %s %s %s %d %d\n"\
"s Running Stable\n"

baseExtraInfo = "extra-info %s %s\n"\
"transport %s %s:%d\n"

ei = ""
df = ""
sf = ""
for i in xrange(500):
    fp = "DEAD BEEF F00F DEAD BEEF F00F " + \
        getHexString(4) + " " + getHexString(4) + " " + \
        getHexString(4) + " " + getHexString(4)
    ID = binascii.a2b_hex(fp.replace(" ", ""))

    sf += "".join(baseStatus % ("namedontmattah", binascii.b2a_base64(ID)[:-2],
            "randomstring", time.strftime("%Y-%m-%d %H:%M:%S"), randomIP(),
             randomPort(), randomPort()))

    df += "".join(baseDesc % (randomIP(), randomPort(), fp))
    df += gettimestamp()
    df += "router-signature\n"

    if i % 4 == 0:
        ei += "".join(baseExtraInfo % ("namedontmattah", fp.replace(" ", ""),
                                       random.choice(["obfs2", "obfs3", "obfs2"]),
                                       randomIP(), randomPort()))

ei += "router-signature\n"

try:
    f = open("networkstatus-bridges", 'w')
    f.write(sf)
    f.close()
except:
    print "Failed to open status file"

try:
    f = open("bridge-descriptors", 'w')
    f.write(df)
    f.close()
except:
    print "Failed to open df file"

try:
    f = open("extra-infos", 'w')
    f.write(ei)
    f.close()
except:
    print "Failed to open ei file"

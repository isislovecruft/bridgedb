# -*- coding: utf-8 -*-
#
# This file is part of BridgeDB, a Tor bridge distribution system.
#
# :authors: Isis Lovecruft 0xA3ADB67A2CDB8B35 <isis@torproject.org>
#           please also see AUTHORS file
# :copyright: (c) 2013 Isis Lovecruft
#             (c) 2007-2013, The Tor Project, Inc.
#             (c) 2007-2013, all entities within the AUTHORS file
# :license: 3-clause BSD, see included LICENSE for information

"""Parsers for ``@type bridge-network-status 1.0`` descriptors.

.. _descriptors: https://metrics.torproject.org/formats.html#descriptortypes

**Module Overview:**

..
  parse
   \_networkstatus     
      |_ parseRLine - Parse an 'r'-line from a networkstatus document
      |_ parseALine - Parse an 'a'-line from a networkstatus document
      \_ parseSLine - Parse an 's'-line from a networkstatus document
"""

import binascii
import logging
import string
import time

from bridgedb.parse import addr
from bridgedb.parse import padBase64


class NetworkstatusParsingError(Exception):
    """Unable to parse networkstatus document line."""

class InvalidNetworkstatusRouterIdentity(ValueError):
    """The ID field of a networkstatus document 'r'-line is invalid."""

class InvalidNetworkstatusDescriptorDigest(ValueError):
    """Descriptor digest of a networkstatus document 'r'-line is invalid."""

class InvalidRouterNickname(ValueError):
    """Router nickname doesn't follow tor-spec."""


ALPHANUMERIC = string.letters + string.digits


def isValidRouterNickname(nickname):
    """Determine if a router's given nickname meets the specification.

    :param string nickname: An OR's nickname.
    """
    try:
        if not (1 <= len(nickname) <= 19):
            raise InvalidRouterNickname(
                "Nicknames must be between 1 and 19 characters: %r" % nickname)
        for letter in nickname:
            if not letter in ALPHANUMERIC:
                raise InvalidRouterNickname(
                    "Nicknames must only use [A-Za-z0-9]: %r" % nickname)
    except Exception as error:
        logging.exception(error)
    else:
        return True

    raise InvalidRouterNickname

def parseRLine(line):
    """Parse an 'r'-line from a networkstatus document.

    From torspec.git/dir-spec.txt, commit 36761c7d553d L1499-1512:
      |
      |"r" SP nickname SP identity SP digest SP publication SP IP SP ORPort
      |    SP DirPort NL
      |
      |    [At start, exactly once.]
      |
      |    "Nickname" is the OR's nickname.  "Identity" is a hash of its
      |    identity key, encoded in base64, with trailing equals sign(s)
      |    removed.  "Digest" is a hash of its most recent descriptor as
      |    signed (that is, not including the signature), encoded in base64.
      |    "Publication" is the
      |    publication time of its most recent descriptor, in the form
      |    YYYY-MM-DD HH:MM:SS, in UTC.  "IP" is its current IP address;
      |    ORPort is its current OR port, "DirPort" is its current directory
      |    port, or "0" for "none".
      |

    :param string line: An 'r'-line from an bridge-network-status descriptor.

    """
    (nickname, ID, descDigest, timestamp,
     ORaddr, ORport, dirport) = (None for x in xrange(7))

    if not line.startswith('r '):
        raise NetworkstatusParsingError(
            "Networkstatus parser received non 'r'-line: %r" % line)

    line = line[2:] # Chop of the 'r '

    fields = line.split()
    if len(fields) != 8:
        raise NetworkstatusParsingError(
            "Wrong number of fields in networkstatus 'r'-line: %r" % line)

    try:
        nickname, ID = fields[:2]

        isValidRouterNickname(nickname)

        if ID.endswith('='):
            raise InvalidNetworkstatusRouterIdentity(
                "Skipping networkstatus parsing for router with nickname %r:"\
                "\n\tUnpadded, base64-encoded networkstatus router identity "\
                "string ends with '=': %r" % (nickname, ID))
        try:
            ID = padBase64(ID) # Add the trailing equals sign back in
        except (AttributeError, ValueError) as error:
            raise InvalidNetworkstatusRouterIdentity(error.message)

        ID = binascii.a2b_base64(ID) 
        if not ID:
            raise InvalidNetworkstatusRouterIdentity(
                "Skipping networkstatus parsing for router with nickname %r:"\
                "\n\tBase64-encoding for networkstatus router identity string"\
                "is invalid!\n\tLine: %r" % (nickname, line))

    except IndexError as error:
        logging.error(error.message)
    except InvalidRouterNickname as error:
        logging.error(error.message)
        nickname = None
    except InvalidNetworkstatusRouterIdentity as error:
        logging.error(error.message)
        ID = None

    try:
        descDigest = binascii.a2b_base64(fields[2])
    except (AttributeError, ValueError) as error:
        raise InvalidNetworkstatusDescriptorDigest(error.message)


        timestamp = time.mktime(time.strptime(" ".join(fields[3:5]),
                                              "%Y-%m-%d %H:%M:%S"))
        ORaddr = fields[5]
        ORport = fields[6]
        dirport = fields[7]

    finally:
        return (nickname, ID, descDigest, timestamp, ORaddr, ORport, dirport)

def parseALine(line, fingerprint=None):
    """Parse an 'a'-line of a bridge networkstatus document.

    From torspec.git/dir-spec.txt, commit 36761c7d553d L1499-1512:
      |
      | "a" SP address ":" port NL
      |
      |    [Any number.]
      |
      |    Present only if the OR has at least one IPv6 address.
      |
      |    Address and portlist are as for "or-address" as specified in
      |    2.1.
      |
      |    (Only included when the vote or consensus is generated with
      |    consensus-method 14 or later.)

    :param string line: An 'a'-line from an bridge-network-status descriptor.
    :raises: :exc:`NetworkstatusParsingError`
    :rtype: tuple
    :returns: A 2-tuple of a string respresenting the IP address and a
        :class:`bridgedb.parse.addr.PortList`.
    """
    ip = None
    address = None
    portlist = None

    if not line.startswith('a '):
        logging.error("Networkstatus parser received non 'a'-line for %r:"
                      % (fingerprint or 'Unknown'))
        logging.error("\t%r" % line)
        return address, portlist

    line = line[2:] # Chop off the 'a '

    try:
        ip, portlist = line.rsplit(':', 1)
    except (IndexError, ValueError, addr.InvalidPort) as error:
        logging.exception(error)
        raise NetworkstatusParsingError(
            "Parsing networkstatus 'a'-line for %r failed! Line: %r"
            %(fingerprint, line))
    else:
        ip = ip.strip('[]') 
        address = addr.isIPAddress(ip)
        if not ip:
            raise NetworkstatusParsingError(
                "Got invalid IP Address in networkstatus 'a'-line for %r: %r"
                % (fingerprint, ip))
        
        portlist = addr.PortList(portlist)

    logging.debug("Parsed networkstatus ORAddress line for %r:" % fingerprint)
    logging.debug("\tAddress: %s  \tPorts: %s" % (address, portlist))

    return address, portlist

def parseSLine(line):
    """Parse an 's'-line from a bridge networkstatus document.

    The 's'-line contains all flags assigned to a bridge. The flags which may
    be assigned to a bridge are as follows:

    From torspec.git/dir-spec.txt, commit 36761c7d553d L1526-1554:
      |
      | "s" SP Flags NL
      |
      |    [Exactly once.]
      |
      |    A series of space-separated status flags, in lexical order (as ASCII
      |    byte strings).  Currently documented flags are:
      |
      |      "BadDirectory" if the router is believed to be useless as a
      |         directory cache (because its directory port isn't working,
      |         its bandwidth is always throttled, or for some similar
      |         reason).
      |      "Fast" if the router is suitable for high-bandwidth circuits.
      |      "Guard" if the router is suitable for use as an entry guard.
      |      "HSDir" if the router is considered a v2 hidden service directory.
      |      "Named" if the router's identity-nickname mapping is canonical,
      |         and this authority binds names.
      |      "Stable" if the router is suitable for long-lived circuits.
      |      "Running" if the router is currently usable.
      |      "Valid" if the router has been 'validated'.
      |      "V2Dir" if the router implements the v2 directory protocol.

    :param string line: An 's'-line from an bridge-network-status descriptor.
    :rtype: tuple
    :returns: A 2-tuple of booleans, the first is True if the bridge has the
        "Running" flag, and the second is True if it has the "Stable" flag.
    """
    fast, running, stable, guard, valid = False
    
    line = line[2:]

    flags = [x.capitalize() for x in line.split()]
    fast    = 'Fast' in flags
    running = 'Running' in flags
    stable  = 'Stable' in flags
    guard   = 'Guard' in flags
    valid   = 'Valid' in flags
    
    logging.debug("Parsed Flags: %s" % flags)

    # Right now, we only care about 'Running' and 'Stable'
    return running, stable

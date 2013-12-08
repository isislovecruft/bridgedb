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
import warnings

from twisted.python.log import showwarning

from bridgedb.parse import addr
from bridgedb.parse import padBase64


class NetworkstatusParsingError(Exception):
    """Unable to parse networkstatus document line."""

class InvalidNetworkstatusRouterIdentity(ValueError):
    """The ID field of a networkstatus document 'r'-line is invalid."""

class InvalidRouterNickname(ValueError):
    """Router nickname doesn't follow tor-spec."""


def isValidRouterNickname(nickname):
    """Determine if a router's given nickname meets the specification.

    :param string nickname: An OR's nickname.
    """
    ALPHANUMERIC = string.letters + string.digits

    if not (1 <= len(nickname) <= 19):
        raise InvalidRouterNickname(
            "Nicknames must be between 1 and 19 characters: %r" % nickname)
    for letter in nickname:
        if not letter in ALPHANUMERIC:
            raise InvalidRouterNickname(
                "Nicknames must only use [A-Za-z0-9]: %r" % nickname)
    return True

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

    try:
        if not line.startswith('r '):
            raise NetworkstatusParsingError(
                "Networkstatus parser received non 'r'-line: %r" % line)

        line = line[2:] # Chop of the 'r '
        fields = line.split()

        if len(fields) != 8:
            raise NetworkstatusParsingError(
                "Wrong number of fields in networkstatus 'r'-line: %r" % line)

        nickname, ID = fields[:2]
        isValidRouterNickname(nickname)

        if ID.endswith('='):
            raise InvalidNetworkstatusRouterIdentity(
                "Skipping networkstatus parsing for router with nickname "\
                "'%s':\n  Unpadded, base64-encoded networkstatus router identity "\
                "string ends with '=': %r" % (nickname, ID))
        paddedID = padBase64(ID) # Add the trailing equals sign back in
        debasedID = binascii.a2b_base64(paddedID)
        if not debasedID:
            raise InvalidNetworkstatusRouterIdentity(
                "Skipping networkstatus parsing for router with nickname "\
                "'%s':\n  Base64-encoding for networkstatus router identity "\
                "string is invalid!\n  Line: %r" % (nickname, line))
        ID = debasedID

    except NetworkstatusParsingError as error:
        logging.error(error)
        nickname, ID = None, None
    except InvalidRouterNickname as error:
        logging.error(error)
        nickname = None
    except InvalidNetworkstatusRouterIdentity as error:
        logging.error(error)
        ID = None
    else:
        try:
            descDigest = binascii.a2b_base64(fields[2])
            timestamp = time.mktime(time.strptime(" ".join(fields[3:5]),
                                                  "%Y-%m-%d %H:%M:%S"))
            ORaddr = fields[5]
            ORport = fields[6]
            dirport = fields[7]
        except (AttributeError, ValueError, IndexError) as error:
            logging.error(error)
            descDigest = None
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
    :type fingerprint: string or None
    :param fingerprint: A string which identifies which OR the descriptor
        we're parsing came from (since the 'a'-line doesn't tell us, this can
        help make the log messages clearer).
    :raises: :exc:`NetworkstatusParsingError`
    :rtype: tuple
    :returns: A 2-tuple of a string respresenting the IP address and a
        :class:`bridgedb.parse.addr.PortList`.
    """
    ip = None
    portlist = None

    if not line.startswith('a '):
        logging.error("Networkstatus parser received non 'a'-line for %r:"\
                      "  %r" % (fingerprint or 'Unknown', line))
        return ip, portlist

    line = line[2:] # Chop off the 'a '

    try:
        ip, portlist = line.rsplit(':', 1)
    except ValueError as error:
        logging.error("Bad separator in networkstatus 'a'-line: %r" % line)
        return (None, None)

    if ip.startswith('[') and ip.endswith(']'):
        ip = ip.strip('[]')

    try:
        if not addr.isIPAddress(ip):
            raise NetworkstatusParsingError(
                "Got invalid IP Address in networkstatus 'a'-line for %r: %r"
                % (fingerprint or 'Unknown', line))

        if addr.isIPv4(ip):
            warnings.warn(FutureWarning(
                "Got IPv4 address in networkstatus 'a'-line! "\
                "Networkstatus document format may have changed!"))
    except NetworkstatusParsingError as error:
        logging.error(error)
        ip, portlist = None, None

    try:
        portlist = addr.PortList(portlist)
        if not portlist:
            raise NetworkstatusParsingError(
                "Got invalid portlist in 'a'-line for %r!\n  Line: %r"
                % (fingerprint or 'Unknown', line))
    except (addr.InvalidPort, NetworkstatusParsingError) as error:
        logging.exception(error)
        portlist = None
    else:
        logging.debug("Parsed networkstatus ORAddress line for %r:"\
                      "\n  Address: %s  \tPorts: %s"
                      % (fingerprint or 'Unknown', ip, portlist))
    finally:
        return (ip, portlist)

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
    line = line[2:]

    flags = [x.capitalize() for x in line.split()]
    fast    = 'Fast' in flags
    running = 'Running' in flags
    stable  = 'Stable' in flags
    guard   = 'Guard' in flags
    valid   = 'Valid' in flags

    if (fast or running or stable or guard or valid):
        logging.debug("Parsed Flags: %s%s%s%s%s"
                      % ('Fast ' if fast else '',
                         'Running ' if running else '',
                         'Stable ' if stable else '',
                         'Guard ' if guard else '',
                         'Valid ' if valid else ''))

    # Right now, we only care about 'Running' and 'Stable'
    return running, stable

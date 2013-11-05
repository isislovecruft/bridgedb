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

"""Modules for parsing data.

** Package Overview: **

..
  parse
   ||_ isIPAddress - Check if an arbitrary string is an IP address.
   ||_ isIPv4 - Check if an arbitrary string is an IPv4 address.
   ||_ isIPv6 - Check if an arbitrary string is an IPv6 address.
   |\_ isValidIP - Check that an IP address is valid.
   |
   |__ :mod:`bridgedbparse.headers`
   |__ :mod:`bridgedb.parse.options`
   \__ :mod:`bridgedb.parse.versions`

"""

import logging

import ipaddr


def isIPAddress(ip, compressed=True):
    """Check if an arbitrary string is an IP address, and that it's valid.

    :type ip: basestring or int
    :param ip: The IP address to check.
    :param boolean compressed: If True, return a string representing the
        compressed form of the address. Otherwise, return an
        :class:`ipaddr.IPAddress` instance.
    :rtype: A :class:`ipaddr.IPAddress`, or a string, or False
    :returns: The IP, as a string or a class, if it passed the
        checks. Otherwise, returns False.
    """
    try:
        ip = ipaddr.IPAddress(ip)
    except ValueError:
        return False
    except Exception as error:
        logging.exception(error)
    else:
        if isValidIP(ip):
            if compressed:
                return ip.compressed
            else:
                return ip
    return False

def _isIPv(version, ip):
    """Check if an address is a certain ``version``, either IPv4 or IPv6.

    :param integer version: The IPv[4|6] version to check; must be either
        ``4`` or ``6``.
    :type ip: basestring or int
    :param ip: The IP address to check.
    :rtype: boolean
    :returns: True if the address is an IPv4 address.
    """
    ip = isIPAddress(ip, compressed=False)
    if ip and (ip.version == version):
        return True
    return False

def isIPv4(ip):
    """Check if an address is IPv4.

    :type ip: basestring or int
    :param ip: The IP address to check.
    :rtype: boolean
    :returns: True if the address is an IPv4 address.
    """
    return _isIPv(4, ip)

def isIPv6(ip):
    """Check if an address is IPv6.

    :type ip: basestring or int
    :param ip: The IP address to check.
    :rtype: boolean
    :returns: True if the address is an IPv6 address.
    """
    return _isIPv(6, ip)

def isValidIP(ipaddress):
    """Check that an IP (v4 or v6) is public and not reserved.

    The IP address, ``ip``, must not be any of the following:
      * A link-local address, such as ``169.254.0.0/16`` or ``fe80::/64``.
      * The address of a loopback interface, i.e. ``127.0.0.1`` or ``::1``.
      * A multicast address, for example, ``255.255.255.0``.
      * An unspecified address, for example ``0.0.0.0/32`` in IPv4 or
        ``::/128`` in IPv6.
      * A default route address, for example ``0.0.0.0/0`` or ``::/0``.
      * Any other address within a private networks, such as the IANA
        reserved Shared Address Space, defined in RFC6598_ as
        ``100.64.0.0/10``.

    If it is an IPv4 address, it also must not be:
      *  A reserved address vis-á-vis RFC1918_

    If it is an IPv6 address, it also must not be:
      *  A "site-local", or Unique Local Address (ULA_), address vis-á-vis
         RFC4193_ (i.e. within the ``fc00::/7`` netblock)

    .. _RFC6598: https://tools.ietf.org/htmłrfc6598
    .. _RFC1918: https://tools.ietf.org/html/rfc1918
    .. _ULA: https://en.wikipedia.org/wiki/Unique_local_address
    .. _RFC4193: https://tools.ietf.org/html/rfc4193

    :type ipaddress: An :class:`ipaddr.IPAddress`,
        :class:`ipaddr.IPv4Address`, or :class:`ipaddr.IPv6Address`.
    :param ipaddress: An IPAddress class.
    :rtype: boolean
    :returns: True if the address passes the checks, False otherwise.
    """
    if not (ipaddress.is_link_local or ipaddress.is_loopback
            or ipaddress.is_multicast or ipaddress.is_private
            or ipaddress.is_unspecified):
        if (ipaddress.version == 6) and (not ipaddress.is_site_local):
            return True
        elif (ipaddress.version == 4) and (not ipaddress.is_reserved):
            return True
    return False

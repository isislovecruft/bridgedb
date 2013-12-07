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

"""Utilities for parsing IP addresses.

** Module Overview: **

..
  parse
   ||_ parse.addr
   |   |_ isIPAddress - Check if an arbitrary string is an IP address.
   |   |_ isIPv4 - Check if an arbitrary string is an IPv4 address.
   |   |_ isIPv6 - Check if an arbitrary string is an IPv6 address.
   |   \_ isValidIP - Check that an IP address is valid.
   |
   |__ :mod:`bridgedbparse.headers`
   |__ :mod:`bridgedb.parse.options`
   \__ :mod:`bridgedb.parse.versions`

..

Private IP Address Ranges:
''''''''''''''''''''''''''
.. glossary::

   10.0.0.0    - 10.255.255.255  (10.0.0.0/8 prefix)
   172.16.0.0  - 172.31.255.255  (172.16.0.0/12 prefix)
   192.168.0.0 - 192.168.255.255 (192.168.0.0/16 prefix)
      These Address ranges are reserved by IANA for private intranets, and not
      routable to the Internet.  For additional information, see :rfc:`1918`.

Reserved and Special Use Addresses:
'''''''''''''''''''''''''''''''''''
.. glossary::

   Unspecified Address
   Default Route
      ex. ``0.0.0.0/8``
      ex. ``::/128``
      Current network (only valid as source address). See :rfc:`1122`. An
      **Unspecified Address** in the context of firewalls means "all addresses
      of the local machine". In a routing context, it is usually termed the
      **Default Route**, and it means the default route (to "the rest of" the
      internet). See :rfc:`1700`.

   Loopback Address
      ex. ``127.0.0.0``
      Reserved for loopback and IPC on the localhost. See :rfc:`1122`.

   Localhost Address
      ex. ``127.0.0.1 - 127.255.255.254`` (``127.0.0.0/8``)
      ex. ``::1``
      Loopback IP addresses (refers to self). See :rfc:`5735`.

   Link-Local Address
      ex. ``169.254.0.0/16``
      ex. ``fe80::/64``
      These are the link-local blocks, used for communication between hosts on
      a single link. See :rfc:`3927`.

   Multicast Address
      ex. ``224.0.0.0 - 239.255.255.255`` (``224.0.0.0/4``)
      Reserved for multicast addresses. See :rfc:`3171`.

   Private Address
      ex. ``10.0.0.0/8``
      ex. ``172.16.0.0/12``
      ex. ``192.168.0.0/16``
      Reserved for private networks. See :rfc:`1918`.

   Reserved Address
      ex. ``240.0.0.0 - 255.255.255.255`` (``240.0.0.0/4``)
      Reserved (former Class E network). See :rfc:`1700`, :rfc:`3232`, and
      :rfc:`5735`. The one exception to this rule is the :term:`Limited
      Broadcast Address`, ``255.255.255.255`` for which packets at the IP
      layer are not forwarded to the public internet.

   Limited Broadcast Address
      ex. ``255.255.255.255``
      Limited broadcast address (limited to all other nodes on the LAN). See
      :rfc:`919`. For IPv4, ``255`` in any part of the IP is reserved for
      broadcast addressing to the local LAN.


.. warning:: The :mod:`ipaddr` module (as of version 2.1.10) does not
             understand the following reserved_ addresses:

.. _reserved: https://tools.ietf.org/html/rfc5735#page-4

.. glossary::

   Reserved Address (Protocol Assignments)
      ex. ``192.0.0.0/24``
      Reserved for IETF protocol assignments. See :rfc:`5735`.

   Reserved Address (6to4 Relay Anycast)
      ex. ``192.88.99.0/24``
      IPv6 to IPv4 relay. See :rfc:`3068`.

   Reserved Address (Network Benchmark)
      ex. ``198.18.0.0/15``
      Network benchmark tests. See :rfc:`2544`.

   Reserved Address (TEST-NET-1)
      ex. ``192.0.2.0/24``
      Reserved for use in documentation and example code. It is often used in
      conjunction with domain names ``example.com`` or ``example.net`` in
      vendor and protocol documentation. See :rfc:`1166`.

   Reserved Address (TEST-NET-2)
      ex. ``198.51.100.0/24``
      TEST-NET-2. See :rfc:`5737`.

   Reserved Address (TEST-NET-3)
      ex. ``203.0.113.0/24``
      TEST-NET-3. See :rfc:`5737`.

   Shared Address Space
      ex. ``100.64.0.0/10``
      See :rfc:`6598`.

   Site-Local Address
   Unique Local Address
      ex. ``ff00::0/8``
      ex. ``fec0::/10`` (:rfc:`3513` §2.5.6)
      Similar uses to :term:`Limited Broadcast Address`. For IPv6, everything
      becomes convoluted_ and complicated_, and then redefined_. See
      :rfc:`4193`, :rfc:`3879`, and :rfc:`3513`. The
      :meth:`ipaddr.IPAddress.is_site_local` method *only* checks to see if
      the address is a **Unique Local Address** vis-á-vis :rfc:`3513` §2.5.6.

.. _convoluted: https://en.wikipedia.org/wiki/IPv6_address#Multicast_addresses
.. _complicated: https://en.wikipedia.org/wiki/IPv6_address#IPv6_address_scopes
.. _redefined: https://en.wikipedia.org/wiki/Unique_local_address
"""

from __future__ import absolute_import
from __future__ import print_function
from __future__ import unicode_literals

import logging
import ipaddr


class InvalidPort(ValueError):
    """Raised when a given port number is invalid."""


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
    else:
        if isValidIP(ip):
            if compressed:
                return ip.compressed
            else:
                return ip
    return False

def _isIPv(version, ip):
    """Check if **ip** is a certain **version** (IPv4 or IPv6).

    :param integer version: The IPv[4|6] version to check; must be either
        ``4`` or ``6``.
    :param ip: The IP address to check. May be an any type which
               :class:`ipaddr.IPAddress` will accept.
    :rtype: boolean
    :returns: ``True``, if the address is an IPv4 address.
    """
    try:
        ip = ipaddr.IPAddress(ip, version=version)
    except ipaddr.AddressValueError:
        logging.debug("Address %s seems not to be IPv%d." % (ip, version))
        return False
    else:
        return True

def isIPv4(ip):
    """Check if an address is IPv4.

    .. attention:: This does *not* check validity. See :func:`isValidIP`.

    :type ip: basestring or int
    :param ip: The IP address to check.
    :rtype: boolean
    :returns: True if the address is an IPv4 address.
    """
    return _isIPv(4, ip)

def isIPv6(ip):
    """Check if an address is IPv6.

    .. attention:: This does *not* check validity. See :func:`isValidIP`.

    :type ip: basestring or int
    :param ip: The IP address to check.
    :rtype: boolean
    :returns: True if the address is an IPv6 address.
    """
    return _isIPv(6, ip)

def isValidIP(ip):
    """Check that an IP (v4 or v6) is valid.

    The IP address, **ip**, must not be any of the following:

      * A :term:`Link-Local Address`,
      * A :term:`Loopback Address` or :term:`Localhost Address`,
      * A :term:`Multicast Address`,
      * An :term:`Unspecified Address` or :term:`Default Route`,
      * Any other :term:`Private Address`, or address within a privately
        allocated space, such as the IANA-reserved
        :term:`Shared Address Space`.

    If it is an IPv6 address, it also must not be:

      * A :term:`Site-Local Address` or an :term:`Unique Local Address`.

    :type ip: An :class:`ipaddr.IPAddress`, :class:`ipaddr.IPv4Address`, or
              :class:`ipaddr.IPv6Address`.

    :param ip: An ``ipaddr.IPAddress`` class.
    :rtype: boolean
    :returns: ``True``, if **ip** passes the checks; False otherwise.
    """
    reasons  = []

    if ip.is_link_local:
        reasons.append('link local')
    if ip.is_loopback:
        reasons.append('loopback')
    if ip.is_multicast:
        reasons.append('multicast')
    if ip.is_private:
        reasons.append('private')
    if ip.is_unspecified:
        reasons.append('unspecified')

    if (ip.version == 6) and ip.is_site_local:
        reasons.append('site local')
    elif (ip.version == 4) and ip.is_reserved:
        reasons.append('reserved')

    if reasons:
        explain = ', '.join([r for r in reasons]).strip(', ')
        logging.debug("IPv%d address %s is invalid! Reason(s): %s"
                      % (ip.version, ip, explain))
        return False
    return True


class PortList(object):
    """A container class for validated port ranges.

    From torspec.git/dir-spec.txt §2.3:
      |
      | portspec ::= "*" | port | port "-" port
      | port ::= an integer between 1 and 65535, inclusive.
      |
      |    [Some implementations incorrectly generate ports with value 0.
      |     Implementations SHOULD accept this, and SHOULD NOT generate it.
      |     Connections to port 0 are never permitted.]
      |

    :ivar set ports: All ports which have been added to this ``PortList``.
    """

    #: The maximum number of allowed ports per IP address.
    PORTSPEC_LEN = 16

    def __init__(self, *args, **kwargs):
        """Create a :class:`~bridgedb.parse.addr.PortList`.

        :param args: Should match the ``portspec`` defined above.
        :raises: InvalidPort, if one of ``args`` doesn't match ``port`` as
            defined above.
        """
        self.ports = set()
        self.add(*args)

    def _sanitycheck(self, port):
        """Check that ``port`` is in the range [1, 65535] inclusive.

        :raises: InvalidPort, if ``port`` doesn't match ``port`` as defined
            in the excert from torspec above.
        :rtype: int
        :returns: The **port**, if no exceptions were raised.
        """
        if (not isinstance(port, int)) or not (0 < port <= 65535):
            raise InvalidPort("%s is not a valid port number!" % port)
        return port

    def __contains__(self, port):
        """Determine whether ``port`` is already in this ``PortList``.

        :returns: True if ``port`` is in this ``PortList``; False otherwise.
        """
        return port in self.ports

    def add(self, *args):
        """Add a port (or ports) to this ``PortList``.

        :param args: Should match the ``portspec`` defined above.
        :raises: InvalidPort, if one of ``args`` doesn't match ``port`` as
            defined above.
        """
        for arg in args:
            portlist = []
            try:
                if isinstance(arg, basestring):
                    ports = set([int(p)
                                 for p in arg.split(',')][:self.PORTSPEC_LEN])
                    portlist.extend([self._sanitycheck(p) for p in ports])
                if isinstance(arg, int):
                    portlist.append(self._sanitycheck(arg))
                if isinstance(arg, PortList):
                    self.add(list(arg.ports))
            except ValueError:
                raise InvalidPort("%s is not a valid port number!" % arg)

            self.ports.update(set(portlist))

    def __iter__(self):
        """Iterate through all ports in this PortList."""
        return self.ports.__iter__()

    def __str__(self):
        """Returns a pretty string representation of this PortList."""
        ret = []
        for port in self.ports:
            ret.append(',%s' % port)
        ret = ''.join([piece for piece in ret])
        return ret.lstrip(",")

    def __repr__(self):
        """Returns a raw depiction of this PortList."""
        return "PortList('%s')" % self.__str__()

    def __len__(self):
        """Returns the total number of ports in this PortList."""
        return len(self.ports)

    def __getitem__(self, port):
        """Get the value of ``port`` if it is in this PortList.

        :raises: ValueError, if ``port`` isn't in this PortList.
        :rtype: integer
        :returns: The ``port``, if it is in this PortList.
        """
        portlist = list(self.ports)
        return portlist[portlist.index(port)]

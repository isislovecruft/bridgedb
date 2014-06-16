# -*- coding: utf-8 ; test-case-name: bridgedb.test.test_hashring ; -*-
#_____________________________________________________________________________
#
# This file is part of BridgeDB, a Tor bridge distribution system.
#
# :authors: Isis Lovecruft 0xA3ADB67A2CDB8B35 <isis@torproject.org>
#           please also see AUTHORS file
# :copyright: (c) 2007-2014, The Tor Project, Inc.
#             (c) 2014, Isis Lovecruft
# :license: see LICENSE for licensing information
#_____________________________________________________________________________



from zope import interface
from zope.interface import Attribute
from zope.interface import implements


class IHashring(interface.Interface):
    """A ``zope.interface`` specification for a HashRing.

    A hashring is a simple data structure which uses `consistent hashing`_ in
    order to map keys to values which are points lying on the edges of a
    cicle. The keys in a hashring are usually produced via some digested
    output of a random hashing function (i.e. SHA256, etc.). The values may be
    any objects, but often they are nodes in a distributed network.

    When a value is to be distributed, a new key is created (i.e. a new hash
    digest), and this key is again mapped to a point on the edge of the
    circle, and then the node nearest to that point is allocated for
    distribution.

    .. note:: This interface is essentially the revised, proper implementation
        of what was previously ``bridgedb.Bridges.BridgeHolder``.

    .. _`consistent hashing`:
         http://www.tomkleinpeter.com/2008/03/17/programmers-toolbox-part-3-consistent-hashing/
    """

    name = Attribute(
        ("A string which identifies this hashring, used mostly for "
         "differentiating this hashring in log messages, but it is also used "
         "for naming sub-hashrings. If this hashring *is* a sub-hashring of "
         "another, the ``name`` will include whatever distinguishing "
         "parameters differentiate that particular sub-hashring (i.e. "
         "``'(port-443 subring)'`` or ``'(Stable subring)'``)."))

    subrings = Attribute(
        ("A list of sub-hashrings of this hashring. Sub-hashrings should "
         "contain some subset of all the items contained within this "
         "hashring. Subhashrings should *also* be implementers of IHashRing."))

    key = Attribute(
        ("The master HMAC key for this hashring, used for generating HMACs "
         "via this class's ``getHMAC`` function."))

    def __len__():
        """Determine the cumulative number of items in this HashRing and all of
        its subhashrings.
        """

    def addSubring(subhashring):
        """Add a sub-hashring to this hashring."""

    def insert(item):
        """Insert an **item** into this hashring."""

    def clear():
        """Clear all items this hashring."""

    def exportToFile(filename, description=""):
        """Dump the hashring assignments to a **filename**, optionally with a
        **description**.
        """

    def dumpAssignments(filename, description=""):
        """Dump the hashring assignments to a **filename**, optionally with a
        **description**. This is a (deprecated alias for ``exportToFile``).
        """

    def setName(name):
        """Set this hashring's ``name`` attribute."""

    def hmac(data):
        """Create an HMAC of **data** using this HashRing's ``key``."""

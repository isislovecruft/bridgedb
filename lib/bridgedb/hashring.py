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


class Hashring(object):
    """Arranges bridges into a hashring based on an HMAC function.

    :ivar dict bridges: A dictionary which maps HMAC keys to
        :class:`~bridgedb.Bridges.Bridge`s.

    :ivar dict bridgesByID: A dictionary which maps raw hash digests of bridge
        ID keys to :class:`~bridgedb.Bridges.Bridge`s.

    :type hmac: callable
    :ivar hmac: An HMAC function, which uses the **key** parameter to generate
        new HMACs for storing, inserting, and retrieving
        :class:`~bridgedb.Bridges.Bridge`s within mappings.

    :ivar bool isSorted: ``True`` if ``sortedKeys`` is currently sorted.

    :ivar list sortedKeys: A sorted list of all of the HMACs.

    :ivar str name: A string which identifies this hashring, used mostly for
        differentiating this hashring in log messages, but it is also used for
        naming subrings. If this hashring is a subring, the ``name`` will
        include whatever distinguishing parameters differentiate that
        particular subring (i.e. ``'(port-443 subring)'`` or ``'(Stable
        subring)'``)

    :type subrings: list
    :ivar subrings: A list of other ``BridgeRing``s, each of which contains
        bridges of a particular type. For example, a subring might contain
        only ``Bridge``s which have been given the "Stable" flag, or it might
        contain only IPv6 bridges. Each item in this list should be a
        4-tuple::

            (type, value, count, ring)

        where:

          * ``type`` is a string which describes what kind of parameter is
            used to determine if a ``Bridge`` belongs in that subring,
            i.e. ``'port'`` or ``'flag'``.

          * ``value`` is a specific value pertaining to the ``type``,
            e.g. ``type='port'; value=443``.

          * ``count`` is an integer for the current total number of bridges in
            the subring.

          * ``ring`` is a :class:`~bridgedb.Bridges.BridgeRing`; it is the sub
            hashring which contains ``count`` number of
            :class:`~bridgedb.Bridges.Bridge`s of a certain ``type``.

        So, for example, we might have hashring with the following subrings::

            subrings = [('port', 443, 100, Hashring(),),
                        ('flag', 'Stable', 20, Hashring(),),]

        meaning that we have two subrings, one with one hundred bridges on
        port 443, and the other with twenty bridges who have been marked by
        the ``BridgeAuth`` with the ``Stable`` flag.
    """
    implements(IHashring)

    name = None
    key = None
    subrings = []

    def __init__(self, key, replications=1):
        """Create a new Hashring, using **key** as its HMAC key.

        If replication is enabled, i.e. if ``replication >= 1``, then items
        will be inserted into this hashring at ``replication`` number of
        positions, in a uniform distribution.

        For example, if we said that each item should be replicated around the
        hashring four times (``replication = 4``), then, for example,
        ``Item A`` would end up in four positions, distributed uniformly
        around the ring, like so::

                                   _-´¯¯`-_A
                               A ,´        `.
                                /            \
                                |            |
                                \            /
                                 `.        ,´A
                                  A`--__--´

        So in this example, ``Item A`` would be positioned at those four
        points on the ring.

        :type key: bytes
        :param key: The HMAC key, generated with
            :func:`bridgedb.crypto.getKey`.
        :param int replications: The number of times to insert each item into
            this hashring.
        """
        self.bridges = {}
        self.bridgesByID = {}
        self.hmac = getHMACFunc(key, hex=False)
        self.isSorted = False
        self.sortedKeys = []

        self.setName("Ring")

    def setName(self, name):
        """Tag a unique name to this hashring for identification.

        :param string name: The name for this hashring.
        """
        self.name = name
        for tp, val, _, subring in self.subrings:
            if tp == 'port':
                subring.setName("%s (port-%s subring)" % (name, val))
            else:
                subring.setName("%s (%s subring)" % (name, val))

    def __len__(self):
        """Get the number of unique bridges this hashring contains."""
        return len(self.bridges)

    def clear(self):
        """Remove all bridges and mappings from this hashring and subrings."""
        self.bridges = {}
        self.bridgesByID = {}
        self.isSorted = False
        self.sortedKeys = []

        for tp, val, count, subring in self.subrings:
            subring.clear()

    def insert(self, bridge):
        """Add a **bridge** to this hashring.

        The bridge's position in the hashring is dependent upon the HMAC of
        the raw hash digest of the bridge's ID key. The function used to
        generate the HMAC, :ivar:`BridgeRing.hmac`, is unique to each
        individual hashring.

        If the (presumably same) bridge is already at that determined position
        in this hashring, replace the old one.

        :type bridge: :class:`~bridgedb.Bridges.Bridge`
        :param bridge: The bridge to insert into this hashring.
        """
        for tp, val, _, subring in self.subrings:
            if tp == 'port':
                if val == bridge.orport:
                    subring.insert(bridge)
            else:
                assert tp == 'flag' and val == 'stable'
                if val == 'stable' and bridge.stable:
                    subring.insert(bridge)

        ident = bridge.getID()
        pos = self.hmac(ident)
        if not self.bridges.has_key(pos):
            self.sortedKeys.append(pos)
            self.isSorted = False
        self.bridges[pos] = bridge
        self.bridgesByID[ident] = bridge
        logging.debug("Adding %s to %s" % (bridge.ip, self.name))

    def _sort(self):
        """Helper: put the keys in sorted order."""
        if not self.isSorted:
            self.sortedKeys.sort()
            self.isSorted = True

    def _getBridgeKeysAt(self, pos, N=1):
        """Bisect a list of bridges at a specified position, **pos**, and
        retrieve bridges from that point onwards, wrapping around the hashring
        if necessary.

        If the number of bridges requested, **N**, is larger that the size of
        this hashring, return the entire ring. Otherwise:

          1. Sort this bridges in this hashring, if it is currently unsorted.

          2. Bisect the sorted bridges. If the bridge at the desired position,
             **pos**, already exists within this hashring, the the bisection
             result is the bridge at position **pos**. Otherwise, the bisection
             result is the first position after **pos** which has a bridge
             assigned to it.

          3. Try to obtain **N** bridges, starting at (and including) the
             bridge in the requested position, **pos**.

               a. If there aren't **N** bridges after **pos**, wrap back
                  around to the beginning of the hashring and obtain bridges
                  until we have **N** bridges.

          4. Check that the number of bridges obtained is indeed **N**, then
             return them.

        :param bytes pos: The position to jump to. Any bridges returned will
                          start at this position in the hashring, if there is
                          a bridge assigned to that position. Otherwise,
                          indexing will start at the first position after this
                          one which has a bridge assigned to it.
        :param int N: The number of bridges to return.
        :rtype: list
        :returns: A list of :class:`~bridgedb.Bridges.Bridge`s.
        """
        assert len(pos) == DIGEST_LEN
        if N >= len(self.sortedKeys):
            return self.sortedKeys
        if not self.isSorted:
            self._sort()
        idx = bisect.bisect_left(self.sortedKeys, pos)
        r = self.sortedKeys[idx:idx+N]
        if len(r) < N:
            # wrap around as needed.
            r.extend(self.sortedKeys[:N - len(r)])
        assert len(r) == N
        return r

    def getBridges(self, pos, N=1, countryCode=None):
        """Return **N** bridges appearing in this hashring after a position.

        :param bytes pos: The position to jump to. Any bridges returned will
                          start at this position in the hashring, if there is
                          a bridge assigned to that position. Otherwise,
                          indexing will start at the first position after this
                          one which has a bridge assigned to it.
        :param int N: The number of bridges to return.
        :type countryCode: str or None
        :param countryCode: DOCDOC
        :rtype: list
        :returns: A list of :class:`~bridgedb.Bridges.Bridge`s.
        """
        # XXX This can be removed after we determine if countryCode is ever
        # actually being used. It seems the countryCode should be passed in
        # from bridgedb.HTTPServer.WebResource.getBridgeRequestAnswer() in
        # order to hand out bridges which are believed to not be blocked in a
        # given country.
        if countryCode:
            logging.debug("getBridges: countryCode=%r" % countryCode)

        forced = []
        for _, _, count, subring in self.subrings:
            if len(subring) < count:
                count = len(subring)
            forced.extend(subring._getBridgeKeysAt(pos, count))

        keys = [ ]
        for k in forced + self._getBridgeKeysAt(pos, N):
            if k not in keys:
                keys.append(k)
            else:
                logging.debug(
                    "Got duplicate bridge %r in main hashring for position %r."
                    % (logSafely(k.encode('hex')), pos.encode('hex')))
        keys = keys[:N]
        keys.sort()

        #Do not return bridges from the same /16
        bridges = [ self.bridges[k] for k in keys ]

        return bridges

    def getBridgeByID(self, fp):
        """Return the bridge whose identity digest is fp, or None if no such
           bridge exists."""
        for _,_,_,subring in self.subrings:
            b = subring.getBridgeByID(fp)
            if b is not None:
                return b

        return self.bridgesByID.get(fp)

    def dumpAssignments(self, f, description=""):
        logging.info("Dumping bridge assignments for %s..." % self.name)
        for b in self.bridges.itervalues():
            desc = [ description ]
            ident = b.getID()
            for tp,val,_,subring in self.subrings:
                if subring.getBridgeByID(ident):
                    desc.append("%s=%s"%(tp,val))
            f.write("%s %s\n"%( toHex(ident), " ".join(desc).strip()))

    exportToFile = dumpAssignments

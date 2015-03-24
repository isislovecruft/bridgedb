# -*- coding: utf-8 ; test-case-name: bridgedb.test.test_Bridges -*-
#
# This file is part of BridgeDB, a Tor bridge distribution system.
#
# :authors: see AUTHORS file
# :copyright: (c) 2007-2015, The Tor Project, Inc.
# :license: 3-Clause BSD, see LICENSE for licensing information

"""This module has low-level functionality for parsing bridges and arranging
them into hashrings for distributors.
"""

import bisect
import logging
import re
import hashlib
import socket
import time
import ipaddr
import random

import bridgedb.Storage
import bridgedb.Bucket

from bridgedb.bridges import Bridge
from bridgedb.crypto import getHMACFunc
from bridgedb.parse import addr
from bridgedb.parse.fingerprint import toHex
from bridgedb.parse.fingerprint import fromHex
from bridgedb.parse.fingerprint import isValidFingerprint
from bridgedb.safelog import logSafely

try:
    from cStringIO import StringIO
except ImportError:
    from io import StringIO


ID_LEN = 20  # XXX Only used in commented out line in Storage.py
DIGEST_LEN = 20
PORTSPEC_LEN = 16

re_ipv6 = re.compile("\[([a-fA-F0-9:]+)\]:(.*$)")
re_ipv4 = re.compile("((?:\d{1,3}\.?){4}):(.*$)")


def parseCountryBlockFile(f):
    """Generator. Parses a blocked-bridges file 'f', and yields
       a fingerprint (ID), address, a list of ports, and a list of country
       codes where the bridge is blocked for each valid line:
       address, port [], countrycode []"""
    for line in f:
        ID = address = fields = portlist = countries = None
        line = line.strip()
        try:
            ID, addrspec, countries = line.split()
            if isValidFingerprint(ID):
                ID = fromHex(ID)
                logging.debug("Parsed ID: %s", ID)
            else:
                print "failed to parse ID!"
                continue # skip this line

            for regex in [re_ipv4, re_ipv6]:
                m = regex.match(addrspec)
                if m:
                    address = ipaddr.IPAddress(m.group(1))
                    portlist = addr.PortList(m.group(2))
                    countries = countries.split(',')
                    logging.debug("Parsed address: %s", address)
                    logging.debug("Parsed portlist: %s", portlist)
                    logging.debug("Parsed countries: %s", countries)
        except (IndexError, ValueError):
            logging.debug("Skipping line")
            continue # skip this line
        if ID and address and portlist and countries:
            yield ID, address, portlist, countries

class BridgeHolder(object):
    """Abstract base class for all classes that hold bridges."""
    def insert(self, bridge):
        raise NotImplementedError

    def clear(self):
        pass

    def dumpAssignments(self, f, description=""):
        pass


class BridgeRingParameters(object):
    """Store validated settings on minimum number of Bridges with certain
    attributes which should be included in any generated subring of a
    hashring.

    :ivar list needPorts: List of two-tuples of desired port numbers and their
        respective minimums.
    :ivar list needFlags: List of two-tuples of desired flags_ assigned to a
        Bridge by the Bridge DirAuth.

    .. _flags: https://gitweb.torproject.org/torspec.git/blob/HEAD:/dir-spec.txt#l1696
    """

    def __init__(self, needPorts=[], needFlags=[]):
        """Control the creation of subrings by including a minimum number of
        bridges which possess certain attributes.

        :type needPorts: iterable
        :param needPorts: An iterable of two-tuples. Each two tuple should
            contain ``(port, minimum)``, where ``port`` is an integer
            specifying a port number, and ``minimum`` is another integer
            specifying the minimum number of Bridges running on that ``port``
            to include in any new subring.
        :type needFlags: iterable
        :param needFlags: An iterable of two-tuples. Each two tuple should
            contain ``(flag, minimum)``, where ``flag`` is a string specifying
            an OR flag_, and ``minimum`` is an integer for the minimum number
            of Bridges which have acquired that ``flag`` to include in any new
            subring.
        :raises: An :exc:`TypeError` if an invalid port number, a minimum less
            than one, or an "unsupported" flag is given. "Stable" appears to
            be the only currently "supported" flag.
        """
        for port, count in needPorts:
            if not (1 <= port <= 65535):
                raise TypeError("Port %s out of range." % port)
            if count <= 0:
                raise TypeError("Count %s out of range." % count)
        for flag, count in needFlags:
            flag = flag.lower()
            if flag not in ["stable", "running",]:
                raise TypeError("Unsupported flag %s" % flag)
            if count <= 0:
                raise TypeError("Count %s out of range." % count)

        self.needPorts = needPorts[:]
        self.needFlags = [(flag.lower(), count) for flag, count in needFlags[:]]

class BridgeRing(BridgeHolder):
    """Arranges bridges into a hashring based on an hmac function."""

    def __init__(self, key, answerParameters=None):
        """Create a new BridgeRing, using key as its hmac key.

        :type key: bytes
        :param key: The HMAC key, generated with
                    :func:`bridgedb.crypto.getKey`.
        :type answerParameters: :class:`BridgeRingParameters`
        :param answerParameters: DOCDOC
        :ivar dict bridges: A dictionary which maps HMAC keys to
                            :class:`~bridgedb.Bridges.Bridge`s.
        :ivar dict bridgesByID: A dictionary which maps raw hash digests of
                                bridge ID keys to
                                :class:`~bridgedb.Bridges.Bridge`s.
        :type hmac: callable
        :ivar hmac: An HMAC function, which uses the **key** parameter to
                    generate new HMACs for storing, inserting, and retrieving
                    :class:`~bridgedb.Bridges.Bridge`s within mappings.
        :ivar bool isSorted: ``True`` if ``sortedKeys`` is currently sorted.
        :ivar list sortedKeys: A sorted list of all of the HMACs.
        :ivar str name: A string which identifies this hashring, used mostly
                        for differentiating this hashring in log messages, but
                        it is also used for naming subrings. If this hashring
                        is a subring, the ``name`` will include whatever
                        distinguishing parameters differentiate that
                        particular subring (i.e. ``'(port-443 subring)'`` or
                        ``'(Stable subring)'``)
        :type subrings: list
        :ivar subrings: A list of other ``BridgeRing``s, each of which
                        contains bridges of a particular type. For example, a
                        subring might contain only ``Bridge``s which have been
                        given the "Stable" flag, or it might contain only IPv6
                        bridges. Each item in this list should be a 4-tuple:

                          ``(type, value, count, ring)``

                        where:

                          * ``type`` is a string which describes what kind of
                            parameter is used to determine if a ``Bridge``
                            belongs in that subring, i.e. ``'port'`` or
                            ``'flag'``.

                          * ``value`` is a specific value pertaining to the
                            ``type``, e.g. ``type='port'; value=443``.

                          * ``count`` is an integer for the current total
                             number of bridges in the subring.

                          * ``ring`` is a
                            :class:`~bridgedb.Bridges.BridgeRing`; it is the
                            sub hashring which contains ``count`` number of
                            :class:`~bridgedb.Bridges.Bridge`s of a certain
                            ``type``.
        """
        self.bridges = {}
        self.bridgesByID = {}
        self.hmac = getHMACFunc(key, hex=False)
        self.isSorted = False
        self.sortedKeys = []
        if answerParameters is None:
            answerParameters = BridgeRingParameters()
        self.answerParameters = answerParameters

        self.subrings = []
        for port,count in self.answerParameters.needPorts:
            #note that we really need to use the same key here, so that
            # the mapping is in the same order for all subrings.
            self.subrings.append( ('port',port,count,BridgeRing(key,None)) )
        for flag,count in self.answerParameters.needFlags:
            self.subrings.append( ('flag',flag,count,BridgeRing(key,None)) )

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
                if val == bridge.orPort:
                    subring.insert(bridge)
            else:
                assert tp == 'flag' and val == 'stable'
                if val == 'stable' and bridge.flags.stable:
                    subring.insert(bridge)

        ident = bridge.getID()
        pos = self.hmac(ident)
        if not self.bridges.has_key(pos):
            self.sortedKeys.append(pos)
            self.isSorted = False
        self.bridges[pos] = bridge
        self.bridgesByID[ident] = bridge
        logging.debug("Adding %s to %s" % (bridge.address, self.name))

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

class FixedBridgeSplitter(BridgeHolder):
    """A bridgeholder that splits bridges up based on an hmac and assigns
       them to several sub-bridgeholders with equal probability.
    """
    def __init__(self, key, rings):
        self.hmac = getHMACFunc(key, hex=True)
        self.rings = rings[:]
        for r in self.rings:
            assert(isinstance(r, BridgeHolder))

    def insert(self, bridge):
        # Grab the first 4 bytes
        digest = self.hmac(bridge.getID())
        pos = long( digest[:8], 16 )
        which = pos % len(self.rings)
        self.rings[which].insert(bridge)

    def clear(self):
        """Clear all bridges from every ring in ``rings``."""
        for r in self.rings:
            r.clear()

    def __len__(self):
        """Returns the total number of bridges in all ``rings``."""
        total = 0
        for ring in self.rings:
            total += len(ring)
        return total

    def dumpAssignments(self, filename, description=""):
        """Write all bridges assigned to this hashring to ``filename``.

        :param string description: If given, include a description next to the
            index number of the ring from :attr:`FilteredBridgeHolder.rings`
            the following bridges were assigned to. For example, if the
            description is ``"IPv6 obfs2 bridges"`` the line would read:
            ``"IPv6 obfs2 bridges ring=3"``.
        """
        for index, ring in zip(xrange(len(self.rings)), self.rings):
            ring.dumpAssignments(filename, "%s ring=%s" % (description, index))

class UnallocatedHolder(BridgeHolder):
    """A pseudo-bridgeholder that ignores its bridges and leaves them
       unassigned.
    """
    def __init__(self):
        self.fingerprints = []

    def insert(self, bridge):
        logging.debug("Leaving %s unallocated", bridge.fingerprint)
        if not bridge.fingerprint in self.fingerprints:
            self.fingerprints.append(bridge.fingerprint)

    def __len__(self):
        return len(self.fingerprints)

    def clear(self):
        self.fingerprints = []

    def dumpAssignments(self, f, description=""):
        with bridgedb.Storage.getDB() as db:
            allBridges = db.getAllBridges()
            for bridge in allBridges:
                if bridge.hex_key not in self.fingerprints:
                    continue
                dist = bridge.distributor
                desc = [ description ]
                if dist.startswith(bridgedb.Bucket.PSEUDO_DISTRI_PREFIX):
                    dist = dist.replace(bridgedb.Bucket.PSEUDO_DISTRI_PREFIX, "")
                    desc.append("bucket=%s" % dist)
                elif dist != "unallocated":
                    continue
                f.write("%s %s\n" % (bridge.hex_key, " ".join(desc).strip()))

class BridgeSplitter(BridgeHolder):
    """A BridgeHolder that splits incoming bridges up based on an hmac,
       and assigns them to sub-bridgeholders with different probabilities.
       Bridge-to-bridgeholder associations are recorded in a store.
    """
    def __init__(self, key):
        self.hmac = getHMACFunc(key, hex=True)
        self.ringsByName = {}
        self.totalP = 0
        self.pValues = []
        self.rings = []
        self.pseudoRings = []
        self.statsHolders = []

    def __len__(self):
        n = 0
        for r in self.ringsByName.values():
            n += len(r)
        return n

    def addRing(self, ring, ringname, p=1):
        """Add a new bridgeholder.
           ring -- the bridgeholder to add.
           ringname -- a string representing the bridgeholder.  This is used
               to record which bridges have been assigned where in the store.
           p -- the relative proportion of bridges to assign to this
               bridgeholder.
        """
        assert isinstance(ring, BridgeHolder)
        self.ringsByName[ringname] = ring
        self.pValues.append(self.totalP)
        self.rings.append(ringname)
        self.totalP += p

    def addPseudoRing(self, ringname):
        """Add a pseudo ring to the list of pseudo rings.
        """
        self.pseudoRings.append(bridgedb.Bucket.PSEUDO_DISTRI_PREFIX + ringname)

    def addTracker(self, t):
        """Adds a statistics tracker that gets told about every bridge we see.
        """
        self.statsHolders.append(t)

    def clear(self):
        for r in self.ringsByName.values():
            r.clear()

    def insert(self, bridge):
        assert self.rings

        for s in self.statsHolders:
            s.insert(bridge)

        # The bridge must be running to insert it:
        if not bridge.flags.running:
            return

        bridgeID = bridge.fingerprint

        # Determine which ring to put this bridge in if we haven't seen it
        # before.
        pos = self.hmac(bridgeID)
        n = int(pos[:8], 16) % self.totalP
        pos = bisect.bisect_right(self.pValues, n) - 1
        assert 0 <= pos < len(self.rings)
        ringname = self.rings[pos]
        logging.info("%s placing bridge %s into hashring %s (via n=%s, pos=%s)."
                     % (self.__class__.__name__, bridge, ringname, n, pos))

        validRings = self.rings + self.pseudoRings

        with bridgedb.Storage.getDB() as db:
            ringname = db.insertBridgeAndGetRing(bridge, ringname, time.time(), 
                                             validRings)
            db.commit()

            # Pseudo distributors are always held in the "unallocated" ring
            if ringname in self.pseudoRings:
                ringname = "unallocated"

            ring = self.ringsByName.get(ringname)
            ring.insert(bridge)

    def dumpAssignments(self, f, description=""):
        for name,ring in self.ringsByName.iteritems():
            ring.dumpAssignments(f, "%s %s" % (description, name))


class FilteredBridgeSplitter(BridgeHolder):
    """A configurable BridgeHolder that filters bridges into subrings.

    The set of subrings and conditions used to assign :class:`Bridge`s should
    be passed to :meth:`~FilteredBridgeSplitter.addRing`.
    """

    def __init__(self, key, max_cached_rings=3):
        """Create a hashring which filters bridges into sub hashrings.

        :type key: DOCDOC
        :param key: An HMAC key.
        :param int max_cached_rings: XXX max_cached_rings appears to not be
             used anywhere.

        :ivar filterRings: A dictionary of subrings which has the form
             ``{ringname: (filterFn, subring)}``, where:
                 - ``ringname`` is a unique string identifying the subring.
                 - ``filterFn`` is a callable which filters Bridges in some
                   manner, i.e. by whether they are IPv4 or IPv6, etc.
                 - ``subring`` is a :class:`BridgeHolder`.
        :ivar hmac: DOCDOC
        :ivar bridges: DOCDOC
        :type distributorName: str
        :ivar distributorName: The name of this splitter's distributor. See
             :meth:`bridgedb.Dist.IPBasedDistributor.setDistributorName`.
        """
        self.key = key
        self.filterRings = {}
        self.hmac = getHMACFunc(key, hex=True)
        self.bridges = []
        self.distributorName = ''

        #XXX: unused
        self.max_cached_rings = max_cached_rings

    def __len__(self):
        return len(self.bridges)

    def clear(self):
        self.bridges = []
        self.filterRings = {}

    def insert(self, bridge):
        """Insert a bridge into all appropriate sub-hashrings.

        For all sub-hashrings, the ``bridge`` will only be added iff it passes
        the filter functions for that sub-hashring.

        :type bridge: :class:`~bridgedb.Bridges.Bridge`
        :param bridge: The bridge to add.
        """
        # The bridge must be running to insert it:
        if not bridge.flags.running:
            logging.warn(
                "Skipping hashring insertion for non-running bridge: '%s'"
                % logSafely(bridge.fingerprint))
            return

        index = 0
        logging.debug("Inserting %s into splitter"
                      % (logSafely(bridge.fingerprint)))
        for old_bridge in self.bridges[:]:
            if bridge.fingerprint == old_bridge.fingerprint:
                self.bridges[index] = bridge
                break
            index += 1
        else:
            self.bridges.append(bridge)
        for ringname, (filterFn, subring) in self.filterRings.items():
            if filterFn(bridge):
                subring.insert(bridge)
                logging.debug("Inserted bridge '%s' into '%s' sub hashring"
                              % (logSafely(bridge.fingerprint), ringname))

    def extractFilterNames(self, ringname):
        """Get the names of the filters applied to a particular sub hashring.

        :param str ringname: A unique name identifying a sub hashring.
        :rtype: list
        :returns: A sorted list of strings, all the function names of the
                  filters applied to the sub hashring named **ringname**.
        """
        filterNames = []

        for filterName in [x.func_name for x in list(ringname)]:
            # Using `filterAssignBridgesToRing.func_name` gives us a messy
            # string which includes all parameters and memory addresses. Get
            # rid of this by partitioning at the first `(`:
            realFilterName = filterName.partition('(')[0]
            filterNames.append(realFilterName)

        filterNames.sort()
        return filterNames

    def addRing(self, subring, ringname, filterFn, populate_from=None):
        """Add a subring to this hashring.

        :type subring: :class:`BridgeHolder`
        :param subring: The subring to add.
        :param str ringname: A unique name for identifying the new subring.
        :param filterFn: A function whose input is a :class:`Bridge`, and
                         returns True/False based on some filtration criteria.
        :type populate_from: iterable or None
        :param populate_from: A group of :class:`Bridge`s. If given, the newly
                              added subring will be populated with these
                              bridges.
        :rtype: bool
        :returns: False if there was a problem adding the subring, True
                  otherwise.
        """
        # XXX I think subring and ringname are switched in this function, or
        # at least that whatever is passed into this function as as the
        # `ringname` parameter from somewhere else is odd; for example, with
        # the original code, which was `log.debug("Inserted %d bridges into
        # hashring '%s'!" % (inserted, ringname))`, this log message appears:
        #
        # Jan 04 23:18:37 [INFO] Inserted 12 bridges into hashring
        # frozenset([<function filterBridgesByIP4 at 0x2d67cf8>, <function
        # filterAssignBridgesToRing(<function hmac_fn at 0x3778398>, 4, 0) at
        # 0x37de578>])!
        #
        # I suppose since it contains memory addresses, it *is* technically
        # likely to be a unique string, but it is messy.

        logging.debug("Adding '%s' subring to %s..."
                      % (ringname, self.__class__.__name__))

        if not isinstance(subring, BridgeHolder):
            logging.fatal("%s hashring can't add invalid subring: %r"
                          % (self.distributorName, subring))
            return False
        if ringname in self.filterRings.keys():
            logging.fatal("%s hashring already has a subring named '%s'!"
                          % (self.distributorName, ringname))
            return False

        filterNames = self.extractFilterNames(ringname)
        subringName = [self.distributorName]
        for filterName in filterNames:
            if filterName != 'filterAssignBridgesToRing':
                subringName.append(filterName.strip('filterBridgesBy'))
        subringName = '-'.join([x for x in subringName])
        subring.setName(subringName)

        logging.info("Adding subring to %s hashring..." % subring.name)
        logging.info("  Subring filters: %s" % filterNames)

        #TODO: drop LRU ring if len(self.filterRings) > self.max_cached_rings
        self.filterRings[ringname] = (filterFn, subring)

        if populate_from:
            inserted = 0
            for bridge in populate_from:
                if isinstance(bridge, Bridge) and filterFn(bridge):
                    subring.insert(bridge)
                    inserted += 1
            logging.info("Bridges inserted into %s subring: %d"
                         % (subring.name, inserted))

        return True

    def dumpAssignments(self, f, description=""):
        # one ring per filter set
        # bridges may be present in multiple filter sets
        # only one line should be dumped per bridge

        for b in self.bridges:
            # gather all the filter descriptions
            desc = []
            for n,(g,r) in self.filterRings.items():
                if g(b):
                    # ghetto. get subring flags, ports
                    for tp,val,_,subring in r.subrings:
                        if subring.getBridgeByID(b.getID()):
                            desc.append("%s=%s"%(tp,val))
                    try:
                        desc.extend(g.description.split())
                    except TypeError:
                        desc.append(g.description)

            # add transports
            logging.debug("%s supports %d transports" % (b, len(b.transports)))
            for transport in b.transports:
                desc.append("transport=%s"%(transport.methodname))

            # dedupe and group
            desc = set(desc)
            grouped = dict()
            for kw in desc:
                l,r = kw.split('=')
                try:
                    grouped[l] = "%s,%s"%(grouped[l],r)
                except KeyError:
                    grouped[l] = kw

            # add to assignments
            desc = "%s %s" % (description.strip(),
                    " ".join([v for k,v in grouped.items()]).strip())
            f.write("%s %s\n"%( toHex(b.getID()), desc))

class BridgeBlock(object):
    """Base class that abstracts bridge blocking.

    .. TODO:: This should be a zope.interface specification.
    """
    def __init__(self):
        pass

    def insert(self, fingerprint, blockingRule):
        raise NotImplementedError

    def clear(self):
        pass

class CountryBlock(BridgeBlock):
    """Countrywide bridge blocking"""
    def __init__(self):
        self.db = bridgedb.Storage.getDB()

    def clear(self):
        assert self.db
        self.db.cleanBridgeBlocks()
        self.db.commit()

    def insert(self, fingerprint, blockingRule):
        """ insert a country based blocking rule """
        assert self.db
        countryCode = blockingRule
        self.db.addBridgeBlock(fingerprint, countryCode)
        self.db.commit()

    def getBlockingCountries(self, fingerprint):
        """ returns a list of country codes where this fingerprint is blocked"""
        assert self.db
        if fingerprint is not None:
            return self.db.getBlockingCountries(fingerprint) 

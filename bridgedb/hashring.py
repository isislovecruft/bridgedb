# -*- coding: utf-8 ; test-case-name: bridgedb.test.test_hashring ; -*-
#_____________________________________________________________________________
#
# This file is part of BridgeDB, a Tor bridge distribution system.
#
# :authors: Isis Lovecruft 0xA3ADB67A2CDB8B35 <isis@torproject.org>
#           please also see AUTHORS file
# :copyright: (c) 2013-2015, Isis Lovecruft
#             (c) 2007-2015, The Tor Project, Inc.
# :license: see LICENSE for licensing information
#_____________________________________________________________________________

"""Hashring structures.

.. warn:: This module contains classes and interfaces which provide low-level
    functionality for arranging items into hashrings.  You shouldn't need to
    touch anything in this module in order to write a new
    :class:`~bridgedb.distribute.Distributor`.  Touching this code can cause
    very grave, difficult-to-debug issues.  You have been warned.

BridgeDB's various :class:`~bridgedb.distribute.Distributor`s may use various
combinations of different types of :class:`~bridgedb.hashring.Hashring`s in
order to structure their distribution strategy.  In fact, BridgeDB itself also
uses a :class:`ProportionalHashring` in order to allocate the
:class:`~bridgedb.bridges.Bridge`s proportionately to each of the different
:class:`~bridgedb.distribute.Distributor`s (for example, some proportion of
all :class:`~bridgedb.bridges.Bridge`s go to the
:class:`~bridgedb.email.distributor.EmailDistributor`, some other proportion
go to the :class:`~bridgedb.https.distributor.HTTPSDistributor`, while the
remainder go to :class:`~bridgedb.unallocated.UnallocatedDistributor`).

The :class:`~bridgedb.hashring.Hashring`s within this module are meant to be
elementary building blocks for any distribution strategy.  If it seems that
some type of elementary building block is missing, then it should be taken
into account that multiple types of :class:`~bridgedb.hashring.Hashring`s
combined can likely be combined to produce the same functionality (with
little-to-no loss in efficiency).  If that is still not the case, then there
is a bug in the design of this module.  Additionally, if using the hashrings
within this module feels awkward, then that could also be a bug in the API
design.

.. seealso:: Tor trac tickets `#12505`_ and `#12029`_.
.. _#12505: https://bugs.torproject.org/12505
.. _#12029: https://bugs.torproject.org/12029
"""

import bisect
import logging
import math
import random
import time

from twisted.internet import task
from twisted.python import components
from zope.interface import Attribute
from zope.interface import Interface
from zope.interface import implementer

import bridgedb.Storage

from bridgedb.bridges import Bridge
from bridgedb.crypto import DIGEST
from bridgedb.crypto import getHMACFunc
from bridgedb.interfaces import IName
from bridgedb.interfaces import Named
from bridgedb.util import Cache


class HashringException(Exception):
    """General error class for all exceptions and errors regarding hashrings."""


class HashringInsertionError(HashringException, IndexError):
    """Raised when we cannot insert an item into the hashring."""


class IHashring(IName):
    """An interface specification for a hashring."""

    subrings = Attribute(
        ("A list of sub-hashrings of this hashring. Sub-hashrings should "
         "contain some subset of all the items contained within this "
         "hashring. Sub-hashrings should *also* be implementers of IHashring."))
    key = Attribute(
        ("The master HMAC key for this hashring, used for generating HMACs "
         "via this class's ``hmac`` function."))

    def __contains__(item):
        """Returns true if this hashring contains **item**.
        """
    def __len__():
        """Determine the cumulative number of items in this hashring and all of
        its sub-hashrings.
        """
    def addSubring(subring):
        """Add a subring to this hashring.
        """
    def clear():
        """Clear all items this hashring.
        """
    def hmac(value):
        """Create an HMAC of **value** using this HashRing's ``key``.
        """
    def insert(item):
        """Insert an **item** into this hashring.
        """
    def exportToFile(filename, description="", mode=""):
        """Dump the hashring assignments to a **filename**, optionally with a
        **description**.
        """

class IConstrainHashring(IHashring):
    """An interface specification for a hashring which accepts items based
    upon some set of constraints.
    """
    constraints = Attribute(
        ("A list of instances which implement IConstrain. This is used to "
         "filter for only the items which meet the conditional constraint."))


@implementer(IHashring)
class Hashring(Named):
    """A basic hashring.

    In a hashring, the items are hashed (with a keyed hash digest called an
    HMAC), and it is by this hash that they are looked up.  The hash space is
    large, and is treated as if it wraps around to form a circle - hence the
    term hashring.  The process of creating a hash for each item is equivalent
    to placing it at a point on the circumference of this hash space circle.

    When an item needs to be looked up (or in BridgeDB's case, when a client
    makes a request for bridges) then the item/client-data is hashed, which
    again corresponds to another point on the circle.  In order to find the
    items for the client, one then simply moves around the circle clockwise
    from that point until the next N items are found.  If the "end" of the
    hash space is reached before N items can be retrieved, then first item is
    used - this is the "wrapping round" that makes the hash space circular.

    :type subrings: list
    :ivar subrings: A list of :class:`Hashring`s which act as sub-hashrings.
       If a :class:`Hashrings` has any sub-hashrings, then items will be
       stored *only* in the sub-hashrings (with recursion to
       sub-sub-hashrings, etc.) and not in the primary hashring.
    :type cache: :class:`Cache`
    :ivar cache: A LRU cache for dynamically generated sub-hashrings.
    """

    digest = DIGEST

    def __init__(self, key, hex=True, cacheSize=10):
        """Create a new hashring.

        :type key: bytes
        :param key: The HMAC key, generated with
            :func:`bridgedb.crypto.getKey`.
        :param bool hex: If ``True``, our :func:`hmac` function will return
            hash digests encoded as hexadecimal.  If ``False``, then the
            output is binary.
        :param int cacheSize: The number of sub-hashrings (usually particular
            to a certain :class:`Constraint` or set of ``Constraint``s) to
            keep cached. Later, if a constrained sub-hashring is needed, and
            it is found within the cache, the cached sub-hashring will be used
            rather than generating a new one.
        """
        self.key = key
        self.hmac = getHMACFunc(key, hex=hex, digest=self.digest)
        self.subrings = []
        self.cache = Cache(cacheSize)
        self._keys = []
        self._keyToName = {}
        self._ring = {}
        self.name = str()

    def __contains__(self, item):
        """x.__contains__(y) ←→ y in x"""
        if self.subrings:
            return bool(item in self._getSubring(item))
        else:
            return bool(self.calculateKey(item) in self._keys)

    def __getitem__(self, key):
        """x.__getitem__(y) ←→ x[y]"""
        if isinstance(key, str):    # The positions in the ring are hex strings
            return self._ring[key]
        elif isinstance(key, int):  # An index into the ring, i.e. hashring[0]
            return self._ring[self._keys[0]]

    def __setitem__(self, key, item):
        """Insert **item** into data:`_ring` at a certain **key**, and update
        the list of :data:`_keys` and the :data:`_keyToName` mapping.
        """
        bisect.insort(self._keys, key)
        name = IName(item).name
        self._keyToName[key] = name
        self._ring[key] = item

    def __delitem__(self, key):
        """Delete a **key** from :data:`_keys` and :data:`_keyToName`, and also
        delete it and its item from :data:`_ring`.
        """
        del self._keyToName[key]
        del self._ring[key]
        del self._keys[bisect.bisect_right(self._keys, key)]  # XXX bisect_left?

    def __iter__(self):
        """x.__iter__() <==> iter(x)"""
        if self.subrings:
            return iter(item for ring in self.subrings for item in ring)
        else:
            return iter(self._ring.values())

    def __len__(self):
        """Returns the total number of bridges in this hashring and all
        :data:`subrings`.
        """
        return sum([len(ring) for ring in self.subrings]) + len(self._keys)

    def __str__(self):
        """Returns a pretty string representation of this class."""
        return self.name or self.__class__.__name__

    def _getSubringIndex(self, item):
        """If we have subrings, get the index for the subring in
        :data:`subrings` that the **item** should be inserted into.

        :rtype: int
        """
        return int(self.calculateKey(item), 16) % len(self.subrings)

    def _getSubring(self, item):
        """If we have subrings, retrieve the proper subring for an **item**."""
        return self.subrings[self._getSubringIndex(item)]

    def addSubring(self, subring, name=None, importFrom=None):
        """Add a **subring** to this hashring.

        :type subring: :class:`~bridgedb.Bridges.Hashring`
        :param subring: The sub-hashring to add to :ivar:`subrings`.
        :param str name: A name to give to the subring.
        :param importFrom: Another :class:`Hashring` or iterable to insert
            items from.
        """
        if not IHashring.providedBy(subring):
            raise TypeError(("Subring %r doesn't implement IHashring. "
                             "Cannot add to %r" % (subring, self)))

        name = [name] if name is not None else []

        if IConstrainHashring.providedBy(subring):
            name.append('-'.join(subring.constraints))

        subring.name = "{0} ({1})".format(self.name, ' '.join(name).strip()).strip()

        if importFrom:
            logging.debug("Importing items from %s with length %d" %
                          (importFrom.__class__.__name__, len(importFrom)))
            subring.insert(*importFrom)

        logging.info("Adding %s subring to %s." % (subring.name, self.name))
        self.subrings.append(subring)

    def calculateKey(self, item):
        """Get the key for use in :data:`_keys` for the **item**.

        .. todo:: The keys in :data:`_keys`, in this case are 32-bit integers,
            so we take only the first 4-bytes (8 bytes here, since it's
            hexadecimal-encoded), then we convert it into a long.

            Python (since 2.2, see :pep:`237`) ``int``s are actually C
            ``long``s, and Python ``long``s are actually C ``long long``s.
            (See ``sys.maxint`` if you don't believe me.)  So why are we still
            using a Python ``long`` here, i.e. 64-bits after we've just
            truncated to 32-bits?  Can we change it to an ``int``?

        :param item: The item to calculate a hashring key for.
        :rtype: long
        """
        #return long(self.hmac(IName(item).name)[:8], 16) # XXX
        return self.hmac(IName(item).name)

    def clear(self):
        """Clear all bridges from every ring in :data:`subrings`."""
        self._keys = []
        self._keyToName = {}
        self._ring = {}

        for subring in self.subrings:
            subring.clear()

    def insert(self, *items):
        """Get the key for each item in **items**, then :api:`bisect.insort` the key
        into :data:`_keys` and insert the **item** into that position in that
        position in hashring.

        :param items: The :class:`~bridgedb.interfaces.Named` item to insert
            into this hashring.  The **item** *must* be an instance of a class
            which implements :interface:`~bridgedb.interfaces.IName`, or be
            adapted to behave as it it does.  (See
            :class:`bridgedb.bridges.AdaptedBridge` for an example adapter.)
        """
        for item in items:
            key = self.calculateKey(item)
            if key in self._ring:
                self[key] = item
                return # XXX should we also insert in subrings?
            if self.subrings:
                self._getSubring(item).insert(item)
            else:
                self[key] = item

    def exportToFile(self, filename, description="", mode='w'):
        """Export all items in this hashring to **filename**, optionally with a
        description.

        .. warning:: This function outputs a *horribly* unparseable format,
            for example, for storing bridges, the output to **filename** will
            look something like::

                79883F82833F23C22CB34A8E1549D56300161207 Non-xyzzy distributor Ring (bar subring)
                C1F70E25F9E3586AA0489E485E60F700BAA982DB Non-xyzzy distributor Ring (bar subring)
                193A3A771E20E1BD69D8365426A598F58193B2F2 Non-xyzzy distributor Ring (bar subring)
                49E884ADF5036405FFFC67C5C6B6CE89DEAFE6EA Non-xyzzy distributor Ring (bar subring)
                62541AAC19192D62D7FE137867E97FD08A2ACFFB Non-xyzzy distributor Ring (baz subring)
                42FAB4D88CEFE886E4FF0C411C417B2E168266C8 Non-xyzzy distributor Ring (baz subring)

            And, as one can see, the output is only grouped by sub-hashring
            name, and not sorted by item name, item key, nor any other sort order.

            Additionally, note that the output **description** can have spaces
            in it, which obviously makes safe parsing a total bitch when
            you're dealing with a supposedly-space–separated data format.

        .. todo:: Create key-value stores in Redis for this data, and provide
            authenticated-and-encrypted access to those key-value stores for
            exporting the data the Tor Metrics server, with optional
            `EVALSHA`_ Redis scripts for doing additonal computation on them.

        .. _EVALSHA: http://redis.io/commands/evalsha

        :param str filename: The name of the file to write to.
        :param str description: See the complaints in the "Warning" section
            above.
        :param str mode: The mode to open **filename** with.
        """
        logging.info("Exporting %s hashring to file: %s" % (self.name, filename))

        with open(filename, mode) as fh:
            if self.subrings:
                for subring in self.subrings:
                    describe = []
                    if IConstrainHashring.providedBy(subring):
                        describe.extend(subring.constraints)
                    for item in subring:
                        d = describe + [description, subring.name]
                        d = " ".join([str(x) for x in d])
                        fh.write("%s %s\n" % (IName(item).name, d))
            else:
                # XXX was producing lines like:
                # 84C4692F21289BA58C5DD55BBED8F4EEE4F88135 ipv4  ring=1 ring=0 Email (yahoo.com) (ipv4)
                #description = description + self.name
                for item in self:
                    fh.write("%s %s\n" % (IName(item).name, description))

    def remove(self, *items):
        """Remove each item in **items** from this hashring.

        :param items: The :class:`~bridgedb.interfaces.Named` item to remove
            from this hashring.  The **item** *must* be an instance of a class
            which implements :interface:`~bridgedb.interfaces.IName`, or be
            adapted to behave as it it does.  (See
            :class:`bridgedb.bridges.AdaptedBridge` for an example adapter.)
        :raises KeyError: if there isn't anything stored at any of the
            position(s) for the HMACed **key**.
        """
        for item in items:
            del self[self.calculateKey(item)]

    def retrieve(self, position, N=1):
        """Get **N** items from this hashring after given a **position**.

        Bisect the items in this hashring at a specified **position**, and
        retrieve **N** items from that point onwards, wrapping around the
        hashring if necessary.

        If the number of items requested, **N**, is larger that the size of
        this hashring, return the entire ring. Otherwise:

          1. Bisect the sorted items. If the item at the desired position,
             **position**, already exists within this hashring, then the
             bisection result is the item at **position**. Otherwise, the
             bisection result is the first position which has an item assigned
             to it, after **position**.

          2. Try to obtain **N** items, starting at (and including) the
             item in the resultant bisection index from step 1.

               a. If there aren't **N** items after **position**, wrap back
                  around to the beginning of the hashring and obtain items
                  until we have **N** items.

          3. Check that the number of items obtained is indeed **N**, then
             return them.

        :param str position: The position to jump to. Any items returned
             will start at this position in the hashring, if there is an item
             assigned there.  Otherwise, indexing will start at the next
             position afterwards which has an item assigned to it.
        :param int N: The number of items to return.
        :raises ValueError: if **position** isn't the same length as the
            length of the hash digest used for positions..
        :raises ArithmeticError: if there is a problem returning **N** items.
        :rtype: list
        :returns: A list of **N** items from this hashring.
        """
        if N >= len(self._keys):
            return self._ring.values()

        keys = []
        index = bisect.bisect_right(self._keys, position)
        while len(keys) < N:
            try:
                key = self._keys[index]
            except IndexError:
                index = 0   # Wrap around to origin
                keys.append(self._keys[index])
            else:
                if key not in keys:
                    keys.append(key)
                else:
                    logging.debug(
                        "Got duplicate item %r in hashring for position %r."
                        % (logSafely(key.encode('hex')), position))
            index += 1

        items = [self._ring[key] for key in keys]

        if len(items) != N:
            raise ArithmeticError("Can't retrieve %d items from hashring %s!" %
                                  (N, self.name))

        return items

    def setCacheSize(self, size):
        """Resize this :class:`Hashring`'s :class:`~bridgedb.util.Cache`."""
        self.cache.size = size

    def tree(self):
        nl = "\n"
        sp = " "
        width = 80
        tree = [nl]

        def typeAndLength(hashring):
            return "{0} [{1}]".format(hashring.__class__.__name__, len(hashring))

        formatted = typeAndLength(self)
        tree.append(formatted.center(width))
        tree.append(nl)

        if isinstance(self, ProportionalHashring):
            formatted = "(" + ":".join([str(p) for p in self.proportions]) + ")"
            tree.append(formatted.center(width))
            tree.append(nl)

        for subring in self.subrings:
            formatted = typeAndLength(subring)
            tree.append(formatted.center(width / len(self.subrings)))
        tree.append(nl)

        subsubrings = [subring.subrings for subring in self.subrings]
        rows = zip(*[subsub for subsub in subsubrings])
        for row in rows:
            separator = sp * (width / int(math.e * len(self.subrings)))
            formatted = separator.join([typeAndLength(item) for item in row])
            tree.append(formatted.center(width))
            tree.append(nl)

        return str().join(tree)


class ConsistentHashring(Hashring):
    """Arranges items into a hashring at regularly spaced intervals.

    A :class:`ConsistentHashring` is a data structure which uses `consistent
    hashing`_ in order to map keys to values which are points lying on the
    edges of a circle.  The keys in a hashring are usually produced via some
    digested output of a random hashing function (i.e. SHA256, etc.).  The
    values may be any objects, but often they are nodes in a distributed
    network.

    When a value is to be distributed, a new key is created (i.e. a new hash
    digest), and this key is again mapped to a point on the edge of the
    circle, and then the node nearest to that point is allocated for
    distribution.

    .. note:: This is essentially the revised, proper implementation
        of what was previously ``bridgedb.Bridges.BridgeRing``.

    .. _consistent hashing:
         http://www.tomkleinpeter.com/2008/03/17/programmers-toolbox-part-3-consistent-hashing/
    """

    def __init__(self, key, replications=1, **kwargs):
        """Create a new ConsistentHashring, using **key** as its HMAC key.

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
        super(ConsistentHashring, self).__init__(key, hex=False, **kwargs)
        if replications and isinstance(replications, int):
            self.replications = replications

    def calculateKey(self, item, replica=0):
        """Get the key for use in :data:`_keys` for the **item**.

        .. todo:: The keys are ``long``s again, and should probably be
            ``int``s.

        :param item: The item to calculate a hashring key for.
        :param int replica: Which replication of the **item** this key is for.
        :rtype: long
        """
        return long(self.hmac("%s:%s" % (IName(item).name, replica))[:8], 16)

    def iterateReplicas(item):
        """Given an **item**, return an iterator of the keys for the **item**
        and all its replication points in this hashring.

        rtype: iter
        returns: An iterator which produces the position of the **item** and
            all of that **item**'s replicated positions.
        """
        return (self.calculateKey(item, replica)
                for replica in range(self.replications))

    def insert(self, *items):
        """Get all the replicated positions for each item in **items** and
        ``bisect()`` then ``insert()`` the item into place in the hashring.

        :param items: The :class:`~bridgedb.interfaces.Named` item to insert
            into this hashring.  The **item** *must* be an instance of a class
            which implements :interface:`~bridgedb.interfaces.IName`, or be
            adapted to behave as it it does.  (See
            :class:`bridgedb.bridges.AdaptedBridge` for an example adapter.)
        :raises HashringInsertionError: if this hashring already has an item
            in with that key. (XXX is this the behaviour we want?)
        """
        for item in items:
            for key in self.iterateReplicas(item):
                if key in self._ring:
                    self[key] = item
                    return # XXX should we also insert in subrings?
                if self.subrings:
                    self._getSubring(item).insert(item)
                else:
                    self[key] = item

    def remove(self, *items):
        """Get all the replicated positions for the **item** and delete them.

        :param items: The :class:`~bridgedb.interfaces.Named` item to remove
            from this hashring.  The **item** *must* be an instance of a class
            which implements :interface:`~bridgedb.interfaces.IName`, or be
            adapted to behave as it it does.  (See
            :class:`bridgedb.bridges.AdaptedBridge` for an example adapter.)
        :raises KeyError: if there isn't anything stored at any of the
            position(s) for the HMACed **key**.
        """
        for item in items:
            for key in self.iterateReplicas(item):
                del self[key]


class ProportionalHashring(Hashring):
    """Places bridges in subrings proportionately.

    .. info:: This is a proper implementation of what used to be the
        :class:`bridgedb.Bridges.FixedBridgeSplitter` and the
        :class:`bridgedb.Bridges.BridgeSplitter`.
    """

    def __init__(self, key, **kwargs):
        super(ProportionalHashring, self).__init__(key, **kwargs)
        #: A list of proportions for each subring in :data:`subrings`.
        self.proportions = []

    def _getSubring(self, item):
        """Retrieve the proper subring for an **item**.

        :param item: The item to determine which subring it belongs in.
        :raises: :exc:`HashringInsertionError` if the proper subring for the
            **item** could not be determined.
        :rtype: :class:`Hashring`
        :returns: The subring from :data:`subrings` which the **item** should
            be inserted into.
        """
        # First, deterministically pick an integer within the range
        # [0, totalProportion], inclusive.
        pick = int(int(self.calculateKey(item), 16) % self.totalProportion)
        index = bisect.bisect_right(self.proportions, pick)
        totheleft = self.proportions[index - 1]

        if self.proportions.count(totheleft) > 1:
            # If totalProportions has several of the same proportion values in
            # a row (and they *will* be in a row, since the proportions are
            # sorted), e.g. if pick=1 and we have:
            #
            #     proportions = [1, 1, 1, 3, 8]
            #
            # then we cannot simply bisect into the list of proportions,
            # because if we did, then we'd end up always picking the rightmost
            # of the run of identical proportion values (in the above example,
            # if ``pick==1``, then we'd always choose ``proportions[2]``).
            # Instead, we pick one of the identical proportion values at
            # random:
            first = self.proportions.index(totheleft)
            last = bisect.bisect(self.proportions, totheleft) - 1
            which = random.randint(first, last)
        else:
            which = bisect.bisect(self.proportions, pick)
        # We 1-index subrings (in their names, at least), so add one here to
        # get the real subring number:
        if which >= len(self.subrings):
            which = len(self.subrings) - 1
        logging.debug("Chose subring %d/%d." % (which + 1, len(self.subrings)))

        if not 0 <= which < len(self.subrings):
            raise HashringInsertionError(
                "Cannot insert %s into subring %s in a hashring with %s subrings!"
                % (IName(item).name, which + 1, len(self.subrings)))

        # And then switch back to 0-indexing when actually indexing:
        subring = self.subrings[which - 1]
        logging.info("Placing %s into %s." % (IName(item).name, subring.name))

        return subring

    @property
    def totalProportion(self):
        """The total sum of all :ivar:`proportions` for all sub-hashrings."""
        return sum([proportion for proportion in self.proportions])

    def addSubring(self, subring, name=None, importFrom=None, proportion=1):
        """Add a **subring** to this hashring.

        :type subring: :class:`~bridgedb.Bridges.Hashring`
        :param subring: The sub-hashring to add to :ivar:`subrings`.
        :param str name: A name to give to the subring.
        :param importFrom: Another :class:`Hashring` or iterable to insert
            items from.
        :param int proportion: The relative proportion of bridges to assign to
            the **subring**.
        """
        logging.debug("Adding subring %s with proportion %d/%d..." %
                      (subring, proportion, self.totalProportion + proportion))
        super(ProportionalHashring, self).addSubring(subring, name, importFrom)
        index = bisect.bisect(self.proportions, proportion)
        self.proportions.insert(index, proportion)
        self.subrings.pop()
        self.subrings.insert(index, subring)

    def exportToFile(self, filename, description="", mode='w'):
        for i, subring in zip(range(len(self.subrings)), self.subrings):
            subring.exportToFile(
                filename, " ".join([description, "ring=%d" % i]), mode='a')

    def insert(self, *items):
        for item in items:
            subring = self._getSubring(item)
            # XXX
            #now = time.time()
            #valid = [subring.name for subring in self.subrings]
            #logging.debug("Subring was: %s" % subring)
            #with bridgedb.Storage.getDB() as db:
            #    # XXX this might fuckup with the current schema
            #    name = db.insertBridgeAndGetRing(item, subring.name, now, valid)
            #    db.commit()
            #for s in self.subrings:
            #    subring = s if s.name == name else subring
            #logging.debug("Subring now: %s" % subring)
            subring.insert(item)


@implementer(IConstrainHashring)
class ConstrainedHashring(Hashring):
    """Arranges bridges into a hashring based on some :class:`Constraint`s."""

    def __init__(self, key, *constraints, **kwargs):
        super(ConstrainedHashring, self).__init__(key, **kwargs)
        self.constraints = {}
        #self.regenerator = task.LoopingCall(self.regenerateCache)
        #self.regenerator.start(30)

        for constraint in constraints:
            self.addConstraint(constraint)

    def addConstraint(self, constraint):
        """These apply to all bridges stored by this hashring."""
        if not self.constraints.get(constraint.name):
            self.name += constraint.name
        self.constraints[constraint.name] = constraint
        self.addToCache(constraint)

        # Overwrite ourself with the filtered version of ourself:
        self._keys = self.cache.peek(constraint.name)._keys
        self._keyToName = self.cache.peek(constraint.name)._keyToName
        self._ring = self.cache.peek(constraint.name)._ring

    #def cacheFilteredSubring(self, constraint):
    #def filterAndCache(self, constraint):
    def addToCache(self, constraint):
        """This caches a copy of this hashring, which some additional
        constraints applied.
        """
        filtered = filter(constraint, self._ring.values())
        constrained = Hashring(self.key)
        constrained.name = constraint.name
        constrained.insert(*filtered)
        self.cache[constraint.name] = constrained
        return constrained

    def regenerateCache(self):
        for name, constraint in self.constraints.items():
            logging.debug("Regenerating caches for %s constraint %s..." %
                          (self.name, name))
            self.addToCache(constraint)

    def reduce(self, *filters):
        """Reduce this :class:`ConstrainedHashring` into a new
        :class:`Hashring` which contains only the items which pass all of the
        **filters**, and then :data:`cache` it.

        :type filters: callable
        :param filters: A callable object which can act as a :api:`filter` for
            the items stored in this hashring.
        :rtype: :class:`Hashring`
        :returns: A :class:`Hashring` which contains only the items which pass
            all of the **filters**
        """
        if not filters:
            return self.cache[self.constraints[0].name]

        name = [n for f in filters for n in f.name.split()]
        name = " ".join(sorted(list(set(name))))
        constrained = self.cache.get(name)

        if not constrained:
            logging.debug("Reducing %s by filtering for %s..." %
                          (self.name, name))
            # Because *args is a tuple and we want to use list methods:
            filters = list(filters)

            # Pick the first filtered subring that we've got in the cache:
            filtre = filters.pop()
            if filtre in self.cache:
                subring = self.cache[filtre]
            else:
                subring = self.addToCache(filtre)

            # And continue to reduce it by all the rest of the filters:
            filtered = subring._ring.values()
            for filtre in filters:
                filtered = filter(filtre, filtered)

            # Finally, create a hashring with the filtered items, and cache it
            # rather than adding it as a subring:
            constrained = Hashring(self.key)
            constrained.name = name
            constrained.insert(*filtered)
            self.cache[name] = constrained

        return constrained

    def retrieve(self, position, N=1):
        """Return **N** bridges appearing in this hashring after a position, where
        **N** follows this hashrings's :data:`constraints`.

        :param str position: The position to bisect to.  Any items returned
            will start at this position in the hashring, if there is a item
            assigned to this position.  Otherwise, indexing will start at the
            first position after (i.e. to the right of) this **position**
            that has an item assigned to it.
        :param int N: The number of items to return.
        :rtype: list
        :returns: A list of **N** items from this hashring.
        """
        items = []

        while len(items) < N:
            logging.debug("Global hashring Constraints are %r" % self.constraints)
            for name, constraint in self.constraints.items():
                n = N
                logging.debug(("Attempting to retrieve %s items which satisfy "
                               "constraint %s...") % (n, constraint))
                # Retrieve items filtered by the constraint until the
                # constraint is satisfied:
                while not constraint.metBy(items): # XXX metBy doesn't exist
                    if not name in self.cache:
                        logging.debug("%s cache miss %s" % (self.name, name))
                        self.addToCache(constraint)
                    filtered = self.cache[name]
                    items.extend(filtered.retrieve(position, n))
                    n += constraint.count
                else:
                    break
            # After we've gone through all the constraints, retrieve any
            # item(s), until we have N items total:
            need = N - len(items)
            unfiltered = super(ConstrainedHashring, self).retrieve(position, need)
            items.extend(unfiltered)
            # Break here to catch edge cases, e.g. where there aren't enough
            # bridges in the (sub)hashrings:
            break

        return items

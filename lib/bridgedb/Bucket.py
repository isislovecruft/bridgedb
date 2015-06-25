# -*- coding: utf-8 -*-

"""This module is responsible for everything concerning file bucket bridge
distribution. File bucket bridge distribution means that unallocated bridges 
are allocated to a certain bucket and later written to a file.

For example, the following is a dict of bridge buckets with the total number
of bridges which each bucket should contain:

        FILE_BUCKETS = { "name1": 10, "name2": 15, "foobar": 3 }

This configuration for buckets would result in 3 files being created for bridge
distribution: name1-2010-07-17.brdgs, name2-2010-07-17.brdgs and 
foobar-2010-07-17.brdgs. The first file would contain 10 bridges from BridgeDB's
'unallocated' pool. The second file would contain 15 bridges from the same pool
and the third one similarly 3 bridges. These files can then be handed out to 
trusted parties via mail or fed to other distribution mechanisms such as 
twitter.

Note that in BridgeDB slang, the _distributor_ would still be 'unallocated',
even though in the database, the 'distributor' for a bridge within one of
these buckets would be :data:`BUCKET_PREFIX` + 'name1', etc.
"""

import logging
import time

from sqlite3 import DatabaseError

import bridgedb.Storage

from bridgedb.unallocated import BUCKET_PREFIX


# Set to rediculously high number
BUCKET_MAX_BRIDGES = 1000000


class BucketData(object):
    """Configures a bridge bucket with the number of bridges which should be
    allocated, the name of the bucket, and other similar data.

    :param str name: The name of this bucket (from the config file). This will
        be prefixed by the :data:`BUCKET_PREFIX`.
    :type needed: str or int
    :param needed: The number of bridges needed for this bucket (also from the
        config file).
    :param int allocated: Number of bridges already allocated for this bucket.
    """
    def __init__(self, name, needed):
        self.name = name
        if needed == "*":
            needed = BUCKET_MAX_BRIDGES
        self.needed = int(needed)
        self.allocated = 0


class BucketManager(object):
    """BucketManager reads a number of file bucket identifiers from the config.

    They're expected to be in the following format::

        FILE_BUCKETS = { "name1": 10, "name2": 15, "foobar": 3 }

    This syntax means that certain buckets ("name1", "name2" and so on) are
    given a number of bridges (10, 15 and so on). Names can be anything.  The
    name will later be the prefix of the file that is written with the
    assigned number of bridges in it. Instead of a number, a wildcard item
    ("*") is allowed, too. This means that the corresponsing bucket file will
    get the maximum number of possible bridges (as many as are left in the
    unallocated bucket).

    The files will be written in ip:port format, one bridge per line.

    The way this works internally is as follows:

    First of all, the assignBridgesToBuckets() routine runs through the
    database of bridges and looks up the 'distributor' field of each
    bridge. Unallocated bridges are sent to a pool for later assignement.
    Already allocated bridges for file bucket distribution are sorted and
    checked.  They're checked for whether their bucket identifier still exists
    in the current config and also whether the number of assigned bridges is
    still valid. If either the bucket identifier is not existing anymore or
    too many bridges are currently assigned to it, bridges will go to the
    unassigned pool.

    In the second step, after bridges are sorted and the unassigned pool is
    ready, the assignBridgesToBuckets() routine assigns one bridge from the
    unassigned pool to a known bucket identifier at a time until it either
    runs out of bridges in the unallocated pool or the number of needed
    bridges for that bucket is reached.

    When all bridges are assigned in this way, they can then be dumped into
    files by calling the dumpBridges() routine.

    :type cfg: :class:`bridgedb.persistent.Conf`
    :ivar cfg: The central configuration instance.
    :ivar list bucketList: A list of BucketData instances, holding all
        configured (and thus requested) buckets with their respective numbers.
    :ivar list unallocatedList: Holds all bridges from the 'unallocated' pool.
    :ivar bool unallocated_available: Is at least one unallocated bridge
        available?
    :ivar str _prefix: The 'distributor' field in the database will
        hold the name of this bucket, prefixed by this string. By default,
        this uses :data:`BUCKET_PREFIX`.
    :ivar db: The bridge database instance.
    """

    def __init__(self, cfg):
        """Create a ``BucketManager``.

        :type cfg: :class:`bridgedb.persistent.Conf`
        :param cfg: The central configuration instance.
        """
        self.cfg = cfg
        self.bucketList = []
        self.unallocatedList = []
        self.unallocated_available = False
        self.distributor_prefix = BUCKET_PREFIX

    def addToUnallocatedList(self, hex_key):
        """Add a bridge by **hex_key** into the unallocated pool."""
        with bridgedb.Storage.getDB() as db:
            try:
                db.updateDistributorForHexKey("unallocated", hex_key)
            except:
                db.rollback()
                raise
            else:
                db.commit()
        self.unallocatedList.append(hex_key)
        self.unallocated_available = True

    def getBucketByIdent(self, bucketIdent):
        """If we know this bucket identifier, then return the corresponding
        :class:`BucketData` object.
        """
        for d in self.bucketList:
            if d.name == bucketIdent:
                return d
        return None

    def assignUnallocatedBridge(self, bucket):
        """Assign an unallocated bridge to a certain **bucket**."""
        hex_key = self.unallocatedList.pop()
        # Mark pseudo-allocators in the database as such
        allocator_name = bucket.name
        #print "KEY: %d NAME: %s" % (hex_key, allocator_name)
        logging.debug("Moving %s to %s" % (hex_key, allocator_name))
        with bridgedb.Storage.getDB() as db:
            try:
                db.updateDistributorForHexKey(allocator_name, hex_key)
            except:
                db.rollback()
                logging.warn("Failed to move %s to new distributor (%s)"
                             % (hex_key, allocator_name))

                # Ok, this seems useless, but for consistancy's sake, we'll
                # re-assign the bridge from this missed db update attempt to the
                # unallocated list. Remember? We pop()'d it before.
                self.addToUnallocatedList(hex_key)
                raise
            else:
                db.commit()
        bucket.allocated += 1
        if len(self.unallocatedList) < 1:
            self.unallocated_available = False
        return True

    def assignBridgesToBuckets(self):
        """Read file bucket identifiers from the configuration, sort them, and
        write necessary changes to the database.
        """
        logging.debug("Assigning bridges to buckets for pseudo-distributors")
        # Build distributor list
        for k, v in self.cfg.FILE_BUCKETS.items():
            prefixed_key = self.distributor_prefix + k
            d = BucketData(prefixed_key, v)
            self.bucketList.append(d)

        # Loop through all bridges and sort out distributors
        with bridgedb.Storage.getDB() as db:
            allBridges = db.getAllBridges()
        for bridge in allBridges:
            if bridge.distributor == "unallocated":
                self.addToUnallocatedList(bridge.hex_key)
                continue

            # Filter non-pseudo distributors (like 'https' and 'email') early,
            # too
            if not bridge.distributor.startswith(self.distributor_prefix):
                continue

            # Return the bucket in case we know it already
            d = self.getBucketByIdent(bridge.distributor)
            if d is not None:
                # Does this distributor need another bridge? If not, re-inject
                # it into the 'unallocated' pool for for later assignment
                if d.allocated < d.needed:
                    d.allocated += 1
                else:
                    # Bucket has enough members already, free this one
                    self.addToUnallocatedList(bridge.hex_key)
            # We don't know it. Maybe an old entry. Free it.
            else:
                self.addToUnallocatedList(bridge.hex_key)

        # Loop through bucketList while we have and need unallocated
        # bridges, assign one bridge at a time
        while self.unallocated_available and len(self.bucketList) > 0:
            logging.debug("We have %d unallocated bridges and %d buckets to " \
                          "fill. Let's do it."
                          % (len(self.unallocatedList), len(self.bucketList)))
            for d in self.bucketList:
                if d.allocated < d.needed:
                    try:
                        if not self.assignUnallocatedBridge(d):
                            break
                    except sqlite3.DatabaseError as e:
                        dist = d.name.replace(self.distributor_prefix, "")
                        logging.warn("Couldn't assign unallocated bridge to " \
                                     "%s: %s" % (dist, e))
                else:
                    # When we have enough bridges, remove bucket identifier 
                    # from list
                    self.bucketList.remove(d)


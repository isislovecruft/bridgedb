# -*- coding: utf-8 -*-

"""
This module is responsible for everything concerning file bucket bridge 
distribution. File bucket bridge distribution means that unallocated bridges 
are allocated to a certain pseudo-distributor and later written to a file.

For example, the following is a dict of pseudo-distributors (also called 
'bucket identifiers') with numbers of bridges assigned to them:

        FILE_BUCKETS = { "name1": 10, "name2": 15, "foobar": 3 }

This configuration for buckets would result in 3 files being created for bridge
distribution: name1-2010-07-17.brdgs, name2-2010-07-17.brdgs and 
foobar-2010-07-17.brdgs. The first file would contain 10 bridges from BridgeDB's
'unallocated' pool. The second file would contain 15 bridges from the same pool
and the third one similarly 3 bridges. These files can then be handed out to 
trusted parties via mail or fed to other distribution mechanisms such as 
twitter.

Note that in BridgeDB slang, the _distributor_ would still be 'unallocated',
even though in the database, there would now by 'name1', 'name2' or 'foobar'
instead of 'unallocated'. This is why they are called pseudo-distributors.
"""

import logging
import time
import bridgedb.Storage
import bridgedb.Bridges 
import binascii
import sqlite3
from gettext import gettext as _
toHex = binascii.b2a_hex


# What should pseudo distributors be prefixed with in the database so we can
# distinguish them from real distributors?
PSEUDO_DISTRI_PREFIX = "pseudo_"

# Set to rediculously high number
BUCKET_MAX_BRIDGES = 1000000


class BucketData(object):
    """Configures a bridge bucket with the number of bridges which should be
    allocated, the name of the bucket, and other similar data.

    :param str name: The name of this bucket (from the config file). This will
        be prefixed by the :data:`PSEUDO_DISTRIBUTOR_PREFIX`.
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
    :ivar str distributor_prefix: The 'distributor' field in the database will
        hold the name of our pseudo-distributor, prefixed by this string. By
        default, this uses :data:`PSEUDO_DISTRIBUTOR_PREFIX`.
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
        self.distributor_prefix = PSEUDO_DISTRI_PREFIX

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

    def dumpBridgesToFile(self, filename, bridges):
        """Dump a list of given **bridges** into **filename**."""
        logging.debug("Dumping bridge assignments to file: %r" % filename)
        # get the bridge histories and sort by Time On Same Address
        bridgeHistories = []
        with bridgedb.Storage.getDB() as db:
            for b in bridges:
                if self.cfg.COLLECT_TIMESTAMPS:
                    bh = db.getBridgeHistory(b.hex_key)
                    if bh: bridgeHistories.append(bh)
                    bridgeHistories.sort(lambda x,y: cmp(x.weightedFractionalUptime,
                                     y.weightedFractionalUptime))

            # for a bridge, get the list of countries it might not work in
            blocklist = dict()
            if getattr(self.cfg, "COUNTRY_BLOCK_FILE", None) is not None:
                f = open(self.cfg.COUNTRY_BLOCK_FILE, 'r')
                for ID,address,portlist,countries in bridgedb.Bridges.parseCountryBlockFile(f):
                    blocklist[toHex(ID)] = countries
                f.close()

            try:
                f = open(filename, 'w')
                if self.cfg.COLLECT_TIMESTAMPS:
                    for bh in bridgeHistories:
                        days = bh.tosa / long(60*60*24)
                        line = "%s:%s\t(%d days at this address)" %  \
                               (bh.ip, bh.port, days)
                        if str(bh.fingerprint) in blocklist.keys():
                            line = line + "\t(Might be blocked): (%s)" % \
                                   ",".join(blocklist[bh.fingerprint])
                        f.write(line + '\n')
                else:
                    for bridge in bridges:
                        line = "%s:%d %s" \
                               % (bridge.address, bridge.or_port, bridge.hex_key)
                        f.write(line + '\n')
                f.close()
            except IOError:
                print "I/O error: %s" % filename

    def dumpBridges(self):
        """Dump all known file distributors to files, sorted by distributor."""
        logging.info("Dumping all distributors to file.")
        with bridgedb.Storage.getDB() as db:
            allBridges = db.getAllBridges()
        bridgeDict = {}
        # Sort returned bridges by distributor
        for bridge in allBridges:
            dist = str(bridge.distributor)
            if dist in bridgeDict.keys():
                bridgeDict[dist].append(bridge)
            else:
                bridgeDict[dist] = [bridge]

        # Now dump to file(s)
        for k in bridgeDict.keys():
            dist = k
            if (dist.startswith(self.distributor_prefix)):
                # Subtract the pseudo distributor prefix
                dist = dist.replace(self.distributor_prefix, "")
            # Be safe. Replace all '/' in distributor names
            dist = dist.replace("/", "_")
            filename = dist + "-" + time.strftime("%Y-%m-%d") + ".brdgs"
            self.dumpBridgesToFile(filename, bridgeDict[k])

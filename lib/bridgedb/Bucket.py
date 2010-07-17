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

import time

import bridgedb.Storage

class BucketData:
    """A file bucket value class.
       name      - Name of the bucket (From config)
       needed    - Needed number of bridges for that bucket (From config)
       allocated - Number of already allocated bridges for that bucket
    """
    def __init__(self, name, needed):
        self.name = name
        if needed == "*":
            # Set to rediculously high number
            needed = 1000000
        self.needed = int(needed)
        self.allocated = 0

class BucketManager:
    """BucketManager reads a number of file bucket identifiers from the config.
       They're expected to be in the following format:

       FILE_BUCKETS = { "name1": 10, "name2": 15, "foobar": 3 }

       This syntax means that certain buckets ("name1", "name2" and so on)
       are given a number of bridges (10, 15 and so on). Names can be anything.
       The name will later be the prefix of the file that is written with the
       assigned number of bridges in it. Instead of a number, a wildcard item
       ("*") is allowed, too. This means that the corresponsing bucket file 
       will get the maximum number of possible bridges (as many as are left in 
       the unallocated bucket).

       The files will be written in ip:port format, one bridge per line.

       The way this works internally is as follows:

       First of all, the assignBridgesToBuckets() routine runs through
       the database of bridges and looks up the 'distributor' field of each 
       bridge. Unallocated bridges are sent to a pool for later assignement.
       Already allocated bridges for file bucket distribution are sorted and 
       checked.
       They're checked for whether their bucket identifier still exists in the 
       current config and also whether the number of assigned bridges is still 
       valid. If either the bucket identifier is not existing anymore or too 
       many bridges are currently assigned to it, bridges will go to the 
       unassigned pool.

       In the second step, after bridges are sorted and the unassigned pool is
       ready, the assignBridgesToBuckets() routine assigns one bridge
       from the unassigned pool to a known bucket identifier at a time until it
       either runs out of bridges in the unallocated pool or the number of
       needed bridges for that bucket is reached.

       When all bridges are assigned in this way, they can then be dumped into
       files by calling the dumpBridges() routine.
    """

    def __init__(self, cfg):
        self.cfg = cfg
        self.bucketList = []
        self.unallocatedList = []
        self.unallocated_available = False
        self.db = bridgedb.Storage.Database(self.cfg.DB_FILE+".sqlite",
                                            self.cfg.DB_FILE)

    def __del__(self):
        self.db.close()

    def addToUnallocatedList(self, hex_key):
        """Add a bridge by hex_key into the unallocated pool
        """
        try:
            self.db.updateDistributorForHexKey("unallocated", hex_key)
        except:
            self.db.rollback()
            raise
        else:
            self.db.commit()
        self.unallocatedList.append(hex_key)
        self.unallocated_available = True

    def isBucketIdentKnown(self, bucketIdent):
        """Do we know this bucket identifier?
        """
        for d in self.bucketList:
            if d.name == bucketIdent:
                return d
        return None

    def assignUnallocatedBridge(self, bucket):
        """Assign an unallocated bridge to a certain bucket
        """
        bucket.allocated += 1
        hex_key = self.unallocatedList.pop()
        #print "KEY: %d NAME: %s" % (hex_key, bucket.name)
        try:
            self.db.updateDistributorForHexKey(bucket.name, hex_key)
        except:
            self.db.rollback()
            raise
        else:
            self.db.commit()
        if len(self.unallocatedList) < 1:
            self.unallocated_available = False
        return True

    def assignBridgesToBuckets(self):
        """Read file bucket identifiers from the configuration, sort them and 
           write necessary changes to the database
        """
        # Build distributor list
        for k, v in self.cfg.FILE_BUCKETS.items():
            d = BucketData(k, v)
            self.bucketList.append(d)

        # Loop through all bridges and sort out our distributors
        allBridges = self.db.getAllBridges()
        for bridge in allBridges:
            if bridge.distributor == "unallocated":
                self.addToUnallocatedList(bridge.hex_key)
                continue

            # Check if we know this distributor
            d = self.isBucketIdentKnown(bridge.distributor)
            if d is not None:
                # Does this distributor need another one?
                # We assume that d.allocated is 0 in the beginning
                if d.allocated < d.needed:
                    d.allocated += 1
                else:
                    self.addToUnallocatedList(bridge.hex_key)
            # We don't know it. Maybe an old entry. Free it.
            else:
                # DON'T free https or email allocations!
                if bridge.distributor != "https" and \
                   bridge.distributor != "email":
                    self.addToUnallocatedList(bridge.hex_key)

        # Loop though bucketList while we have and need unallocated 
        # bridges, assign one bridge at a time
        while self.unallocated_available and len(self.bucketList) > 0:
            for d in self.bucketList:
                if d.allocated < d.needed:
                    if not self.assignUnallocatedBridge(d):
                        print "Couldn't assign unallocated bridge to %s" % d.name
                else:
                    # When we have enough bridges, remove bucket identifier 
                    # from list
                    self.bucketList.remove(d)
         

    def dumpBridges(self):
        """Dump all known file distributors to files
        """
        buckets = self.cfg.FILE_BUCKETS
        # Dump https, email and unreserved, too
        buckets["https"] = 0
        buckets["email"] = 0
        buckets["unallocated"] = 0
        # Loop through all bucket identifiers and dump their bridges to files
        for bucketId, _ in buckets.items():
            fileName = bucketId + "-" + time.strftime("%Y-%m-%d") + ".brdgs"
            f = open(fileName, 'w')
            #f.write("Here are your bridges, %s:\n" % bucketId)
            bForBucket = self.db.getBridgesForDistributor(bucketId) 
            # Skip empty (pseudo-)distributors
            if len(bForBucket) < 1:
                continue
            print "Dumping %d bridges for %s to %s" % (len(bForBucket), bucketId, fileName)
            for bridge in bForBucket:
                line = "%s:%s" % (bridge.address, bridge.or_port)
                f.write(line + '\n')
            f.close

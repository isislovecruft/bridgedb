#!/usr/bin/env python2
# -*- coding: utf-8 -*-
#
# This file is part of BridgeDB, a Tor bridge distribution system.
#
# :authors: Isis Lovecruft 0xA3ADB67A2CDB8B35 <isis@torproject.org>
#           please also see AUTHORS file
# :copyright: (c) 2013-2018 Isis Lovecruft
#             (c) 2007-2018, The Tor Project, Inc.
#             (c) 2007-2018, all entities within the AUTHORS file
# :license: 3-clause BSD, see included LICENSE for information

"""Assign all unallocated bridges to another distributor."""

from __future__ import print_function

import argparse
import logging

import bridgedb.Storage

#: The path to the sqlite database file containing bridges.
DB_FILENAME = "bridgedist.db.sqlite"

logger = logging.getLogger("assign-reserve-bridges")
logger.setLevel(logging.DEBUG)

def setDBFilename(filename):
    global DB_FILENAME
    DB_FILENAME = filename

def getDBFilename():
    return DB_FILENAME

def getOptions():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "distributor", type=type(''),
        help="The new distributor to assign the unallocated bridges to")
    parser.add_argument(
        "-f", "--db-filename", type=type(''),
        help="The path to the database file")

    return parser.parse_args()

def checkOptions(options):
    assert options.distributor
    assert options.distributor in ["https", "email", "moat"]
    return options

def getDB():
    return bridgedb.Storage.Database(getDBFilename())

def assignBridgesToDistributor(db, distributor):
    unallocated = db.getBridgesForDistributor('unallocated')

    logging.info("Assigning %d unallocated bridges to distributor %s"
                 % (len(unallocated), distributor))
    print("Assigning %d unallocated bridges to distributor %s"
                 % (len(unallocated), distributor))

    for bridge in unallocated:
        db.updateDistributorForHexKey(distributor, bridge.hex_key)
        db.commit()

    remaining_bridges = db.getBridgesForDistributor('unallocated')
    assert len(remaining_bridges) == 0

    logging.info("Done!")
    print("Done!")


if __name__ == "__main__":
    options = checkOptions(getOptions())
    
    if options.db_filename:
        setDBFilename(options.db_filename)

    db = getDB()

    assignBridgesToDistributor(db, options.distributor)

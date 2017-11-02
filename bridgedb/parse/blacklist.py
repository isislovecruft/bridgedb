# -*- coding: utf-8 ; test-case-name: bridgedb.test.test_parse_descriptors ; -*-
#_____________________________________________________________________________
#
# This file is part of BridgeDB, a Tor bridge distribution system.
#
# :authors: Isis Lovecruft 0xA3ADB67A2CDB8B35 <isis@torproject.org>
#           please also see AUTHORS file
# :copyright: (c) 2007-2017, The Tor Project, Inc.
#             (c) 2014-2017, Isis Lovecruft
# :license: see LICENSE for licensing information
#_____________________________________________________________________________

"""Parsers for bridge blacklist files.


.. py:module:: bridgedb.parse.blacklist
    :synopsis: Parsers for bridge blacklist files.

bridgedb.parse.blacklist
===========================
::

 parseBridgeBlacklistFile - Parse a bridge blacklist file.
..
"""

from __future__ import print_function

import logging

from bridgedb.parse.fingerprint import isValidFingerprint


def parseBridgeBlacklistFile(filename):
    """Parse a file of fingerprints of blacklisted bridges.

    This file should be specified in ``bridgedb.conf`` under the
    ``NO_DISTRIBUTION_FILE`` setting, and each line in it should be
    formatted in the following manner:

        FINGERPRINT [SP REASON]

    :type filename: str or None
    :param filename: The path to or filename of the file containing
        fingerprints of blacklisted bridges.
    :returns: A dict whose keys are bridge fingerprints and values are
        reasons for being blacklisted.
    """
    fh = None
    blacklist = {}

    if filename:
        logging.info("Parsing bridge blacklist file: %s" % filename)

        try:
            fh = open(filename)
        except (OSError, IOError) as error:
            logging.error("Error opening bridge blacklist file %s" % filename)
        else:
            for line in fh.readlines():
                fields = line.split(' ', 1)

                if len(fields) == 2:
                    fingerprint, reason = fields[0].strip(), fields[1].strip()
                else:
                    fingerprint, reason = fields[0].strip(), ""

                if isValidFingerprint(fingerprint):
                    logging.info("Blacklisted %s. Reason: \"%s\"" %
                                 (fingerprint, reason))
                    blacklist[fingerprint] = reason
                else:
                    logging.warn(("Can't blacklist %s (for reason \"%s\"): "
                                  "invalid fingerprint") %
                                 (fingerprint, reason))

    return blacklist

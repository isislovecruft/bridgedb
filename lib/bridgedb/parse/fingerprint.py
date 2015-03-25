# -*- coding: utf-8 ; test-case-name: bridgedb.test.test_parse_fingerprint ; -*-
#_____________________________________________________________________________
#
# This file is part of BridgeDB, a Tor bridge distribution system.
#
# :authors: Isis Lovecruft 0xA3ADB67A2CDB8B35 <isis@torproject.org>
#           please also see AUTHORS file
# :copyright: (c) 2007-2015, The Tor Project, Inc.
#             (c) 2014-2015, Isis Lovecruft
# :license: see LICENSE for licensing information
#_____________________________________________________________________________


import binascii
import logging


#: The required length for hexidecimal representations of hash digest of a
#: Tor relay's public identity key (a.k.a. its fingerprint).
HEX_FINGERPRINT_LEN = 40


#: (callable) Convert a value from binary to hexidecimal representation.
toHex = binascii.b2a_hex

#: (callable) Convert a value from hexidecimal to binary representation.
fromHex = binascii.a2b_hex

def isValidFingerprint(fingerprint):
    """Determine if a Tor relay fingerprint is valid.

    :param str fingerprint: The hex-encoded hash digest of the relay's
        public identity key, a.k.a. its fingerprint.
    :rtype: bool
    :returns: ``True`` if the **fingerprint** was valid, ``False`` otherwise.
    """
    try:
        if len(fingerprint) != HEX_FINGERPRINT_LEN:
            raise ValueError("Fingerprint has incorrect length: %r"
                             % repr(fingerprint))
        fromHex(fingerprint)
    except (TypeError, ValueError):
        logging.debug("Invalid hex fingerprint: %r" % repr(fingerprint))
    else:
        return True
    return False

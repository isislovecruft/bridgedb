# -*- coding: utf-8 ; test-case-name: bridgedb.test.test_Util -*-
#
# This file is part of BridgeDB, a Tor bridge distribution system.
#
# :authors: Isis Lovecruft 0xA3ADB67A2CDB8B35 <isis@torproject.org>
#           Matthew Finkel 0x017DD169EA793BE2 <sysrqb@torproject.org>
# :copyright: (c) 2013-2014, Isis Lovecruft
#             (c) 2013-2014, Matthew Finkel
#             (c) 2007-2014, The Tor Project, Inc.
# :license: 3-Clause BSD, see LICENSE for licensing information

"""Common utilities for BridgeDB."""

safe_logging = True

def set_safe_logging(safe):
    global safe_logging
    safe_logging = safe

def logSafely(val):
    if safe_logging:
        return "[scrubbed]"
    else:
        return val

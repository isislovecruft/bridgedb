# -*- coding: utf-8 -*-
#
# This file is part of BridgeDB, a Tor bridge distribution system.
#
# :authors: please also see AUTHORS file
# :copyright: (c) 2007-2013, The Tor Project, Inc.
#             (c) 2007-2013, all entities within the AUTHORS file
# :license: 3-Clause BSD, see LICENSE for licensing information


#: If True, scrub IP and email addresses from logs.
safe_logging = True

def set_safe_logging(safe=True):
    """Enable or disable scrubbing of information in the logs.

    :param safe: If ``True``, use :meth:`bridgedb.log.safe` to scrub logs.
    """
    global safe_logging
    safe_logging = safe

def logSafely(val):
    """Scrub a string or return the original string.

    :rtype: str
    :returns: '[scrubbed]' if SAFE_LOGGING is enabled, else ``val``.
    """
    if safe_logging:
        return "[scrubbed]"
    return val

def logSafelyDigested(val):
    """Returns a hexidecimal string representing the SHA-1 digest of ``val``.

    This is useful for safely logging bridge fingerprints, using the same
    method used by the tools for metrics.torproject.org.

    :param str val: The value to digest.
    :rtype: str
    :returns: A 40-byte hexidecimal representation of the SHA-1 digest.
    """
    if safe_logging:
        import sha
        return sha.new(val).hexdigest()
    return val

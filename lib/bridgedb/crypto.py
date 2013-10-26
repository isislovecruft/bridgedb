# -*- coding: utf-8 -*-
#
# This file is part of BridgeDB, a Tor bridge distribution system.
#
# :authors: Isis Lovecruft 0xA3ADB67A2CDB8B35 <isis@torproject.org>
#           please also see AUTHORS file
# :copyright: (c) 2007-2013, The Tor Project, Inc.
#             (c) 2007-2013, all entities within the AUTHORS file
# :license: 3-clause BSD, see included LICENSE for information


from __future__ import absolute_import
from __future__ import unicode_literals

import logging
log = logging.getLogger(__name__)

import os

import OpenSSL.rand


def getKey(filename):
    """Load the key stored in ``filename``, or create a new key.

    If ``filename`` does not exist, create a new 32-byte key and store it in
    ``filename``.

    >>> name = os.tmpnam()
    >>> os.path.exists(name)
    False
    >>> k1 = getKey(name)
    >>> os.path.exists(name)
    True
    >>> open(name).read() == k1
    True
    >>> k2 = getKey(name)
    >>> k1 == k2
    True

    :param string filename: The filename to store the secret key in.
    :rtype: bytes
    :returns: A byte string containing the secret key.
    """
    try:
        fh = open(filename, 'rb')
    except IOError:
        log.debug("getKey(): Creating new secret key.")
        key = OpenSSL.rand.bytes(32)
        flags = os.O_WRONLY | os.O_TRUNC | os.O_CREAT | getattr(os, "O_BIN", 0)
        fd = os.open(filename, flags, 0400)
        os.write(fd, key)
        os.fsync(fd)
        fd.close()
    else:
        log.debug("getKey(): Secret key file found. Loading...")
        key = fh.read()
        fh.close()
    return key

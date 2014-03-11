# -*- coding: utf-8 -*-
#
# This file is part of BridgeDB, a Tor bridge distribution system.
#
# :authors: Isis Lovecruft 0xA3ADB67A2CDB8B35 <isis@torproject.org>
# :copyright: (c) 2007-2014, The Tor Project, Inc.
#             (c) 2013-2014, Isis Lovecruft
#             (c) 2007-2014, all entities within the AUTHORS file
# :license: 3-clause BSD, see included LICENSE for information

"""crypto - BridgeDB general cryptographic utilities.

**Module Overview:**

..
  crypto
   |_getKey() - Load the master key from a file, or create a new one.
   |
   \_SSLVerifyingContextFactory - OpenSSL.SSL.Context factory which verifies
      |                           certificate chains and matches hostnames.
      |_getContext() - Retrieve an SSL context configured for certificate
      |                verification.
      |_getHostnameFromURL() - Parses the hostname from the request URL.
      \_verifyHostname() - Check that the cert CN matches the request
                           hostname.

"""

from __future__ import absolute_import
from __future__ import unicode_literals

import hashlib
import hmac
import logging
import os

import OpenSSL.rand


#: The hash digest to use for HMACs.
DIGESTMOD = hashlib.sha1


def writeKeyToFile(key, filename):
    """Write **key** to **filename**, with ``0400`` permissions.

    If **filename** doesn't exist, it will be created. If it does exist
    already, and is writable by the owner of the current process, then it will
    be truncated to zero-length and overwritten.

    :param bytes key: A key (or some other private data) to write to
        **filename**.
    :param str filename: The path of the file to write to.
    :raises: Any exceptions which may occur.
    """
    logging.info("Writing key to file: %r" % filename)
    flags = os.O_WRONLY | os.O_TRUNC | os.O_CREAT | getattr(os, "O_BIN", 0)
    fd = os.open(filename, flags, 0400)
    os.write(fd, key)
    os.fsync(fd)
    os.close(fd)

def getKey(filename):
    """Load the key stored in ``filename``, or create a new key.

    If ``filename`` does not exist, create a new 32-byte key and store it in
    ``filename``.

    >>> import os
    >>> from bridgedb import crypto
    >>> name = 'doctest_getKey'
    >>> os.path.exists(name)
    False
    >>> k1 = crypto.getKey(name)
    >>> os.path.exists(name)
    True
    >>> open(name).read() == k1
    True
    >>> k2 = crypto.getKey(name)
    >>> k1 == k2
    True

    :param string filename: The filename to store the secret key in.
    :rtype: bytes
    :returns: A byte string containing the secret key.
    """
    try:
        fh = open(filename, 'rb')
    except IOError:
        logging.debug("getKey(): Creating new secret key.")
        key = OpenSSL.rand.bytes(32)
        writeKeyToFile(key, filename)
    else:
        logging.debug("getKey(): Secret key file found. Loading...")
        key = fh.read()
        fh.close()
    return key

def getHMAC(key, value):
    """Return the HMAC of **value** using the **key**."""
    h = hmac.new(key, value, digestmod=DIGESTMOD)
    return h.digest()

def getHMACFunc(key, hex=True):
    """Return a function that computes the HMAC of its input using the **key**.

    :param bool hex: If True, the output of the function will be hex-encoded.
    :rtype: callable
    :returns: A function which can be uses to generate HMACs.
    """
    h = hmac.new(key, digestmod=DIGESTMOD)
    def hmac_fn(value):
        h_tmp = h.copy()
        h_tmp.update(value)
        if hex:
            return h_tmp.hexdigest()
        else:
            return h_tmp.digest()
    return hmac_fn

# -*- coding: utf-8 ; test-case-name: bridgedb.test.test_distributors_common_http -*-
#
# This file is part of BridgeDB, a Tor bridge distribution system.
#
# :authors: please see included AUTHORS file
# :copyright: (c) 2017, The Tor Project, Inc.
#             (c) 2017, Isis Lovecruft
# :license: see LICENSE for licensing information

"""
.. py:module:: bridgedb.distributors.common.http
    :synopsis: Common utilities for HTTP-based distributors.

bridgedb.distributors.common.http
==================================

Common utilities for HTTP-based distributors.
"""

import logging
import os

from bridgedb.parse.addr import isIPAddress
from bridgedb.parse.addr import isLoopback


#: The fully-qualified domain name for any and all web servers we run.
SERVER_PUBLIC_FQDN = None


def setFQDN(fqdn, https=True):
    """Set the global :data:`SERVER_PUBLIC_FQDN` variable.

    :param str fqdn: The public, fully-qualified domain name of the HTTP
        server that will serve this resource.
    :param bool https: If ``True``, then ``'https://'`` will be prepended to
        the FQDN.  This is primarily used to create a
        ``Content-Security-Policy`` header that will only allow resources to
        be sourced via HTTPS, otherwise, if ``False``, it allow resources to
        be sourced via any transport protocol.
    """
    if https:
        fqdn = 'https://' + fqdn

    logging.info("Setting HTTP server public FQDN to %r" % fqdn)

    global SERVER_PUBLIC_FQDN
    SERVER_PUBLIC_FQDN = fqdn

def getFQDN():
    """Get the setting for the HTTP server's public FQDN from the global
    :data:`SERVER_PUBLIC_FQDN variable.

    :rtype: str or None
    """
    return SERVER_PUBLIC_FQDN

def getClientIP(request, useForwardedHeader=False, skipLoopback=False):
    """Get the client's IP address from the ``'X-Forwarded-For:'``
    header, or from the :api:`request <twisted.web.server.Request>`.

    :type request: :api:`twisted.web.http.Request`
    :param request: A ``Request`` for a :api:`twisted.web.resource.Resource`.
    :param bool useForwardedHeader: If ``True``, attempt to get the client's
        IP address from the ``'X-Forwarded-For:'`` header.
    :param bool skipLoopback: If ``True``, and ``useForwardedHeader`` is
        also ``True``, then skip any loopback addresses (127.0.0.1/8) when
        parsing the X-Forwarded-For header.
    :rtype: ``None`` or :any:`str`
    :returns: The client's IP address, if it was obtainable.
    """
    ip = None

    if useForwardedHeader:
        header = request.getHeader("X-Forwarded-For")
        if header:
            index = -1
            ip = header.split(",")[index].strip()
            if skipLoopback:
                logging.info(("Parsing X-Forwarded-For again, ignoring "
                              "loopback addresses..."))
                while isLoopback(ip):
                    index -= 1
                    ip = header.split(",")[index].strip()
            if not skipLoopback and isLoopback(ip):
               logging.warn("Accepting loopback address: %s" % ip)
            else:
                if not isIPAddress(ip):
                    logging.warn("Got weird X-Forwarded-For value %r" % header)
                    ip = None
    else:
        ip = request.getClientIP()

    return ip

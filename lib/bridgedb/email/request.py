# -*- coding: utf-8; test-case-name: bridgedb.test.test_email_request; -*-
#_____________________________________________________________________________
#
# This file is part of BridgeDB, a Tor bridge distribution system.
#
# :authors: Nick Mathewson <nickm@torproject.org>
#           Isis Lovecruft <isis@torproject.org> 0xA3ADB67A2CDB8B35
#           Matthew Finkel <sysrqb@torproject.org>
#           please also see AUTHORS file
# :copyright: (c) 2007-2015, The Tor Project, Inc.
#             (c) 2013-2015, Isis Lovecruft
# :license: see LICENSE for licensing information
#_____________________________________________________________________________

"""
.. py:module:: bridgedb.email.request
    :synopsis: Classes for parsing and storing information about requests for
               bridges which are sent to the email distributor.

bridgedb.email.request
======================

Classes for parsing and storing information about requests for bridges
which are sent to the email distributor.

::

  bridgedb.email.request
   | |_ determineBridgeRequestOptions - Figure out which filters to apply, or
   |                                    offer help.
   |_ EmailBridgeRequest - A request for bridges which was received through
                           the email distributor.
..
"""

from __future__ import print_function
from __future__ import unicode_literals

import logging
import re

from bridgedb import bridgerequest
from bridgedb.Dist import EmailRequestedHelp
from bridgedb.Dist import EmailRequestedKey


#: A regular expression for matching the Pluggable Transport method TYPE in
#: emailed requests for Pluggable Transports.
TRANSPORT_REGEXP = ".*transport ([a-z][_a-z0-9]*)"
TRANSPORT_PATTERN = re.compile(TRANSPORT_REGEXP)

#: A regular expression that matches country codes in requests for unblocked
#: bridges.
UNBLOCKED_REGEXP = ".*unblocked ([a-z]{2,4})"
UNBLOCKED_PATTERN = re.compile(UNBLOCKED_REGEXP)


def determineBridgeRequestOptions(lines):
    """Figure out which :class:`Bridges.BridgeFilter`s to apply, or offer help.

    .. note:: If any ``'transport TYPE'`` was requested, or bridges not
        blocked in a specific CC (``'unblocked CC'``), then the ``TYPE``
        and/or ``CC`` will *always* be stored as a *lowercase* string.

    :param list lines: A list of lines from an email, including the headers.
    :raises EmailRequestedHelp: if the client requested help.
    :raises EmailRequestedKey: if the client requested our GnuPG key.
    :rtype: :class:`EmailBridgeRequest`
    :returns: A :class:`~bridgerequst.BridgeRequest` with all of the requested
        parameters set. The returned ``BridgeRequest`` will have already had
        its filters generated via :meth:`~EmailBridgeRequest.generateFilters`.
    """
    request = EmailBridgeRequest()
    skippedHeaders = False

    for line in lines:
        line = line.strip().lower()
        # Ignore all lines before the first empty line:
        if not line: skippedHeaders = True
        if not skippedHeaders: continue

        if ("help" in line) or ("halp" in line):
            raise EmailRequestedHelp("Client requested help.")

        if "get" in line:
            request.isValid(True)
            logging.debug("Email request was valid.")
        if "key" in line:
            request.wantsKey(True)
            raise EmailRequestedKey("Email requested a copy of our GnuPG key.")
        if "ipv6" in line:
            request.withIPv6()
        if "transport" in line:
            request.withPluggableTransportType(line)
        if "unblocked" in line:
            request.withoutBlockInCountry(line)

    logging.debug("Generating hashring filters for request.")
    request.generateFilters()
    return request


class EmailBridgeRequest(bridgerequest.BridgeRequestBase):
    """We received a request for bridges through the email distributor."""

    def __init__(self):
        """Process a new bridge request received through the
        :class:`~bridgedb.Dist.EmailBasedDistributor`.
        """
        super(EmailBridgeRequest, self).__init__()
        self._isValid = False
        self._wantsKey = False

    def isValid(self, valid=None):
        """Get or set the validity of this bridge request.

        If called without parameters, this method will return the current
        state, otherwise (if called with the **valid** parameter), it will set
        the current state of validity for this request.

        :param bool valid: If given, set the validity state of this
            request. Otherwise, get the current state.
        """
        if valid is not None:
            self._isValid = bool(valid)
        return self._isValid

    def wantsKey(self, wantsKey=None):
        """Get or set whether this bridge request wanted our GnuPG key.

        If called without parameters, this method will return the current
        state, otherwise (if called with the **wantsKey** parameter set), it
        will set the current state for whether or not this request wanted our
        key.

        :param bool wantsKey: If given, set the validity state of this
            request. Otherwise, get the current state.
        """
        if wantsKey is not None:
            self._wantsKey = bool(wantsKey)
        return self._wantsKey

    def withoutBlockInCountry(self, line):
        """This request was for bridges not blocked in **country**.

        Add any country code found in the **line** to the list of
        ``notBlockedIn``. Currently, a request for a transport is recognized
        if the email line contains the ``'unblocked'`` command.

        :param str country: The line from the email wherein the client
            requested some type of Pluggable Transport.
        """
        unblocked = None

        logging.debug("Parsing 'unblocked' line: %r" % line)
        try:
            unblocked = UNBLOCKED_PATTERN.match(line).group(1)
        except (TypeError, AttributeError):
            pass

        if unblocked:
            self.notBlockedIn.append(unblocked)
            logging.info("Email requested bridges not blocked in: %r"
                         % unblocked)

    def withPluggableTransportType(self, line):
        """This request included a specific Pluggable Transport identifier.

        Add any Pluggable Transport method TYPE found in the **line** to the
        list of ``transports``. Currently, a request for a transport is
        recognized if the email line contains the ``'transport'`` command.

        :param str line: The line from the email wherein the client
            requested some type of Pluggable Transport.
        """
        transport = None
        logging.debug("Parsing 'transport' line: %r" % line)

        try:
            transport = TRANSPORT_PATTERN.match(line).group(1)
        except (TypeError, AttributeError):
            pass

        if transport:
            self.transports.append(transport)
            logging.info("Email requested transport type: %r" % transport)

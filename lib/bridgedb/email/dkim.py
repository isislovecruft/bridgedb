# -*- coding: utf-8 ; test-case-name: bridgedb.test.test_email_dkim -*-
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
.. py:module:: bridgedb.email.dkim
    :synopsis: Functions for checking DKIM verification results in email
               headers.

bridgedb.email.dkim
===================

Functions for checking DKIM verification results in email headers.

::

 bridgedb.email.dkim
  |_ checkDKIM - Check the DKIM verification results header.
..
"""

from __future__ import unicode_literals

import logging


def checkDKIM(message, rules):
    """Check the DKIM verification results header.

    This check is only run if the incoming email, **message**, originated from
    a domain for which we're configured (in the ``EMAIL_DOMAIN_RULES``
    dictionary in the config file) to check DKIM verification results for.

    Returns ``False`` if:

    1. We're supposed to expect and check the DKIM headers for the
       client's email provider domain.
    2. Those headers were *not* okay.

    Otherwise, returns ``True``.

    :type message: :api:`twisted.mail.smtp.rfc822.Message`
    :param message: The incoming client request email, including headers.
    :param dict rules: The list of configured ``EMAIL_DOMAIN_RULES`` for the
        canonical domain which the client's email request originated from.
    :rtype: bool
    :returns: ``False`` if the checks failed, ``True`` otherwise.
    """
    logging.info("Checking DKIM verification results...")
    logging.debug("Domain has rules: %s" % ', '.join(rules))

    if 'dkim' in rules:
        # getheader() returns the last of a given kind of header; we want
        # to get the first, so we use getheaders() instead.
        dkimHeaders = message.getheaders("X-DKIM-Authentication-Results")
        dkimHeader = "<no header>"
        if dkimHeaders:
            dkimHeader = dkimHeaders[0]
        if not dkimHeader.startswith("pass"):
            logging.info("Rejecting bad DKIM header on incoming email: %r "
                         % dkimHeader)
            return False
    return True

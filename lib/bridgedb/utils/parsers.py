# -*- coding: utf-8 -*-
#
# This file is part of BridgeDB, a Tor bridge distribution system.
#
# :authors: Isis Lovecruft 0xA3ADB67A2CDB8B35 <isis@torproject.org>
#           please also see AUTHORS file
# :copyright: (c) 2007-2013, The Tor Project, Inc.
#             (c) 2007-2013, all entities within the AUTHORS file
# :license: 3-Clause BSD, see LICENSE for licensing information

"""XXX DOCDOC """


def isEmailAddress(token):
    """Validate a token as an email address according to RFC 2822.

    Parsing and validating the actual email address is quite slow, so avoid
    putting non-email addresses though ``valid_email_address()``.  The more we
    can turn parsers into generators, and the more we avoid using the
    :mod:`re` module, the faster the parsing will go.

    :param string token: A chunk of text to parse. It MUST be split on
        whitespace, i.e. ' fu' is a token, while ' fu bar' is not. It should
        be ``strip()``ed, but it isn't strictly necessary.
    :returns: True if ``token`` is an email address, False otherwise.
    """
    from importlib import import_module
    parser = import_module('email_validation')

    if token.find('@'):
        return parser.valid_email_address(token)
    return False

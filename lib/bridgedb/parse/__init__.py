# -*- coding: utf-8 -*-
#
# This file is part of BridgeDB, a Tor bridge distribution system.
#
# :authors: Isis Lovecruft 0xA3ADB67A2CDB8B35 <isis@torproject.org>
#           please also see AUTHORS file
# :copyright: (c) 2013 Isis Lovecruft
#             (c) 2007-2013, The Tor Project, Inc.
#             (c) 2007-2013, all entities within the AUTHORS file
# :license: 3-clause BSD, see included LICENSE for information

'''Package containing modules for parsing data.

.. py:module:: bridgedb.parse
    :synopsis: Package containing modules for parsing data.
'''

from __future__ import absolute_import
from __future__ import print_function
from __future__ import unicode_literals

import binascii


class InvalidBase64(ValueError):
    """Raised if parsing or decoding cannot continue due to invalid base64."""


def padBase64(b64string):
    """Re-add any stripped equals sign character padding to a b64 string.

    :param string b64string: A base64-encoded string which might have had its
        trailing equals sign (``=``) padding removed.
    :raises ValueError: if there was any error while manipulating the string.
    :returns: A properly-padded (according to the base64 spec: :rfc:`4648`)
        string.
    """
    addchars  = 0
    try:
        b64string = b64string.strip()
        remainder = len(b64string) % 4
        if 2 <= remainder <= 3:
            addchars = 4 - remainder
    except AttributeError as error:
        raise ValueError(error)
    else:
        if not addchars:
            raise ValueError("Invalid base64-encoded string: %r" % b64string)
        b64string += '=' * addchars

    return b64string

def parseUnpaddedBase64(field):
    """Parse an unpadded, base64-encoded field.

    The **field** will be re-padded, if need be, and then base64 decoded.

    :param str field: Should be some base64-encoded thing, with any trailing
        ``=``-characters removed.
    :raises InvalidBase64: if there is an error in either unpadding or decoding
        **field**.
    :rtype: str
    :returns: The base64-decoded **field**.
    """
    if field.endswith('='):
        raise InvalidBase64("Unpadded, base64-encoded networkstatus field "\
                            "must not end with '=': %r" % field)

    try:
        paddedField = padBase64(field)  # Add the trailing equals sign back in
    except ValueError as error:
        raise InvalidBase64(error)

    debasedField = binascii.a2b_base64(paddedField)
    if not debasedField:
        raise InvalidBase64("Base64-encoded networkstatus field %r is invalid!"
                            % field)

    return debasedField

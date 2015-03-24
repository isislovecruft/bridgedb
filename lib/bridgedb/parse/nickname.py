# -*- coding: utf-8 -*-
#
# This file is part of BridgeDB, a Tor bridge distribution system.
#
# :authors: Isis Lovecruft 0xA3ADB67A2CDB8B35 <isis@torproject.org>
#           please also see AUTHORS file
# :copyright: (c) 2013-2015 Isis Lovecruft
#             (c) 2007-2015, The Tor Project, Inc.
#             (c) 2007-2015, all entities within the AUTHORS file
# :license: 3-clause BSD, see included LICENSE for information

"""Parsers for bridge nicknames.

.. py:module:: bridgedb.parse.nickname
   :synopsis: Parsers for Tor bridge nicknames.

bridgedb.parse.nicknames
========================
::

  nicknames
   |_ isValidRouterNickname - Determine if a nickname is according to spec
..
"""

import logging
import string


class InvalidRouterNickname(ValueError):
    """Router nickname doesn't follow tor-spec."""


def isValidRouterNickname(nickname):
    """Determine if a router's given nickname meets the specification.

    :param string nickname: An OR's nickname.
    :rtype: bool
    :returns: ``True`` if the nickname is valid, ``False`` otherwise.
    """
    ALPHANUMERIC = string.letters + string.digits

    try:
        if not (1 <= len(nickname) <= 19):
            raise InvalidRouterNickname(
                "Nicknames must be between 1 and 19 characters: %r" % nickname)
        for letter in nickname:
            if not letter in ALPHANUMERIC:
                raise InvalidRouterNickname(
                    "Nicknames must only use [A-Za-z0-9]: %r" % nickname)
    except InvalidRouterNickname as error:
        logging.error(str(error))
    except TypeError:  # The nickname was probably still set to ``None``
        pass
    else:
        return True

    return False

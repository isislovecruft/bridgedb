# -*- coding: utf-8 -*-
#
# This file is part of BridgeDB, a Tor bridge distribution system.
#
# :authors: Isis Lovecruft 0xA3ADB67A2CDB8B35 <isis@torproject.org>
#           please also see AUTHORS file
# :copyright: (c) 2007-2013, The Tor Project, Inc.
#             (c) 2007-2013, all entities within the AUTHORS file
# :license: 3-clause BSD, see included LICENSE for information

"""_langs.py - Storage for information on installed language support."""


def get_langs():
    """Return a list of two-letter country codes of translations which were
    installed (if we've already been installed).
    """
    return supported


#: This list will be rewritten by :func:`get_supported_langs` in setup.py at
#: install time, so that the :attr:`bridgedb.__langs__` will hold a list of
#: two-letter country codes for languages which were installed.
supported = []

# -*- coding: utf-8 -*-
#
# This file is part of BridgeDB, a Tor bridge distribution system.
#
# :authors: Isis Lovecruft 0xA3ADB67A2CDB8B35 <isis@torproject.org>
#           please also see AUTHORS file
# :copyright: (c) 2012-2017 Isis Lovecruft
#             (c) 2007-2017, The Tor Project, Inc.
#             (c) 2007-2017, all entities within the AUTHORS file
# :license: 3-clause BSD, see included LICENSE for information

'''Package containing modules for BridgeDB's email bridge distributor.

.. py:module:: bridgedb.distributors.email
    :synopsis: Package containing modules for BridgeDB's email bridge
        distributor.
'''

import autoresponder
import distributor
import dkim
import request
import server
import templates

# -*- coding: utf-8 ; test-case-name: bridgedb.test.test_database_rpc ; -*-
#_____________________________________________________________________________
#
# This file is part of BridgeDB, a Tor bridge distribution system.
#
# :authors: Isis Lovecruft 0xA3ADB67A2CDB8B35 <isis@torproject.org>
#           please also see AUTHORS file
# :copyright: (c) 2007-2016, The Tor Project, Inc.
#             (c) 2014-2016, Isis Lovecruft
# :license: see LICENSE for licensing information
#_____________________________________________________________________________

"""Remote Procedure Calls (RPC) between BridgeDB's distributors and
the database mod:`~bridgedb.database.manager`.
"""

import capnp

# Disable pycapnp's hook into `import` for loading a file named foo.capnp by
# doing `import foo_capnp`.  We don't want to accidentally load a bad schema
# from somewhere else in the system's PYTHONPATH.
capnp.remove_import_hook()

# Load our desired schemas:
protobufs = capnp.load("bridgedb.capnp")


def formatBridgeRequest(request):
    """Format a :class:`~bridgedb.bridgerequest.BridgeRequest` into a Cap'n'Proto
    object.

    :param request: :class:`bridgedb.bridgerequest.BridgeRequest`
    :rtype: :class:`capnp._DynamicStructBuilder` or `None`
    :returns: An object capable of being serialised and used within
        Cap'n'Proto RPC.
    """
    if request.isValid():
        brs = protobufs.BridgeRequest.new_message()
        brs.ipversion = request.ipversion
        brs.transports = request.transports
        brs.notblockedin = request.notblockedin
        brs.client = request.client
        return brs

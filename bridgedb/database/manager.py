# -*- coding: utf-8 ; test-case-name: bridgedb.test.test_database_manager ; -*-
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

"""A RPC server which handles getting or storing data in databases.

This database manager should be run as a separate process.
"""

import paisley

from bridgedb.database import rpc


class BridgeRetrievalException(Exception):
    """Raised when there was an error retrieving bridges from the database."""


class DatabaseManager(rpc.protobufs.DatabaseManager):
    """A implementation of the Cap'n'Proto DatabaseManager interface."""

    # XXX what's Couch's default port?
    def __init__(self, databaseHost="127.0.0.1", databasePort=6666,
                 databaseUser="manager", databasePassword=None):
        """Initialise a server for processing requests intended for the database
        which are sent from a :class:`~bridgedb.distribute.Distributor`.

        :todo: We should evaluate the speed/security tradeoffs of storing each
            Distributor's hashring in the Distributor itself or in the
            DatabaseManager.

        :param str databaseHost: The IP address which the database listens on.
        :param int databasePort: The port which the database listens on.
        :param str databaseUser: The login name for the database.
        :param str databasePassword: The password for authenticating to the
            database.
        """
        self.database = paisley.CouchDB(host=databaseHost,
                                        port=databasePort,
                                        username=databaseUser,
                                        password=databasePassword,
                                        dbName="bridges")

    def processBridgeRequest(self, request):
        """Process a serialised
        :class:`~bridgedb.database.rpc.protobufs.BridgeRequest` by requesting
        the desired information from the database and formatting the
        database's response back into protobufs to return to the
        :class:`~bridgedb.distribute.Distributor`.

        :type request: :class:`~bridgedb.database.rpc.protobufs.BridgeRequest`
        :param request: A serialised protobuf containing a valid request for
            bridge data.
        :rtype: :class:`~bridgedb.database.rpc.protobufs.Bridges`
        """
        def processBridgeRequestCB(response):
            return request

        def processBridgeRequestEB(response):
            # XXX get more error info if available
            return BridgeRetrievalException("Could not retrieve bridges.")

        # Deserialise the protobuf and send the request
        requestArgs = request.to_dict()
        response = self.database.openView(docId, viewId, **requestArgs)

        response.addCallback(processBridgeRequestCB)
        response.addErrback(processBridgeRequestEB)

        return response

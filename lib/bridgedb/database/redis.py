# -*- coding: utf-8 ; test-case-name: bridgedb.test.test_database_redis ; -*-
#_____________________________________________________________________________
#
# This file is part of BridgeDB, a Tor bridge distribution system.
#
# :authors: Isis Lovecruft 0xA3ADB67A2CDB8B35 <isis@torproject.org>
#           please also see AUTHORS file
# :copyright: (c) 2007-2014, The Tor Project, Inc.
#             (c) 2014, Isis Lovecruft
# :license: see LICENSE for licensing information
#_____________________________________________________________________________

from __future__ import print_function
from __future__ import unicode_literals

import logging
import os

from twisted.internet import defer
from twisted.internet import endpoints
from twisted.internet import protocol
from twisted.internet import reactor
from twisted.internet.error import ConnectionLost
from twisted.spread import jelly

from txredis.client import RedisClient
from txredis.client import RedisClientFactory

from bridgedb import safelog

REDIS_HOST = '127.0.0.1'
REDIS_PORT = 6379

#: The number of seconds to expire strored bridge networkstatus documents
#: after. (default: 604800, i.e. 1 week)
DESC_EXPIRE = 7 * 24 * 60 * 60

#: The separator between fields comprising a key in Redis. This is inserted
#: between each of the fields in :func:`createRedisKey`.
REDIS_KEY_FIELD_SEPARATOR = '_'


class ExternallyQueuedRedisClient(RedisClient):
    def connectionLost(self, reason):
        """Fixes a stupid design flaw in ``txredis``.

        This fixes a problem where, after a ``txredis.RedisClient`` has
        successfully sent a ``QUIT`` command to the Redis server, the server
        properly tears down the connection, and Twisted properly calls
        ``txredis.RedisClient.connectionLost``, which calls
        ``txredis.RedisClient.failRequests``, the later of which propagates
        the :api`~twisted.internet.error.ConnectionLost` to all requests in
        its internal queue (``txredis.RedisClient._request_queue``), without
        seemingly bothering to check if these requests have already succeeded.
        This causes the deferred transactions in the internal queue to assume
        that their overarching ``RedisClient`` has a half-terminated TCP
        connection, causing thousands of errbacks to get propagated for NO
        GOOD REASON.

        Technically, the ``ConnectionLost`` is not really an error, it's just
        a signal sent from Twisted that the other end tore down the
        connection. This is *precisely* what *is* supposed to happen when you
        send ``QUIT``, so this is really a design error by ``txredis``.
        """
        trapped = reason.trap(ConnectionLost)
        if trapped:
            logging.debug(
                ("Trap prevented ConnectionLost from propagating to "
                 "`RedisClient.failRequests()`. All's well."))
        else:
            super(ExternallyQueuedRedisClient, self).connectionLost(reason)


def connectServer(host=REDIS_HOST, port=REDIS_PORT, password=None, **kwargs):
    """Create a `txredis.client.RedisClient`_, connected to a Redis_ server.

    .. info:: Uses ``REDIS_DBFILE`` and ``REDIS_PASSWORD`` config variables.

    .. _`txredis.client.RedisClient`:
        https://github.com/deldotdr/txRedis/blob/master/txredis/client.py
    .. _Redis: http://redis.io

    :param str host: The hostname or IP address of the Redis server.
    :param int port: The port of the Redis server.
    :param str password: A password to authenticate to the Redis server.
    :kwargs: will be passed to the instantiation of the
        ``txredis.client.RedisClient`` which is returned.
    :rtype: ``txredis.client.RedisClient``
    :returns: A ``RedisClient`` connected to the Redis server at
        **host**:**port** (and optionally authenticated, if a **password** was
        supplied), such that it is ready to interact with the server and begin
        issuing commands.
    """
    logging.debug("REDIS: Connecting to server: %s:%d" % (host, port))

    def cb(result):
        logging.debug("REDIS: Connection successful: %s" % hash(result))
        if password:
            logging.debug("REDIS: AUTH %s" % safelog.logSafely(password))
            result.auth(password)
        return result

    creator = protocol.ClientCreator(reactor, ExternallyQueuedRedisClient,
                                     password=password, **kwargs)
    redis = creator.connectTCP(host, port)
    redis.addCallbacks(cb, logging.error)
    return redis

def createRedisKey(*fields):
    """Create a key for storing some value in Redis.

    >>> from bridgedb.database.redis import createRedisKey
    >>> bridgeFingerprint = 'ABCDEF0123456789ABCDEF0123456789ABCDEF01'
    >>> bridgeNickname = 'somefakebridge'
    >>> redisKey = createRedisKey(bridgeFingerprint, bridgeNickname)
    ABCDEF0123456789ABCDEF0123456789ABCDEF01_somefakebridge

    :param fields: Arbitrary fields which should go into the key. These should
        be some simple to obtain (but guaranteed to be unique) things which
        describe whatever value is going to be stored in Redis.
    :param separator:
    :rtype: str or None
    :returns: A suitable key for storing a value in Redis, comprised of the
        **fields** joined by the **separator**. Or ``None``, if an encoding
        issue meant that we couldn't create the key.
    """
    try:
        key = REDIS_KEY_FIELD_SEPARATOR.join(fields)
    # TypeError happens if one of *fields was ``None``, or something else
    # which shouldn't be stringified.
    except (UnicodeError, TypeError), error:
        logging.error(error)
    else:
        return key

def getNetworkStatusKey(fingerprint):
    """Create a key for storing a networkstatus descriptor in Redis, based upon
    the router's **fingerprint**.

    :param str fingerprint: The router's identity fingerprint.
    :raises ValueError: if :func:`createRedisKey` could make a key for us.
    :rtype: str
    :returns: The **fingerprint** with ``'_ns'`` appended to it.
    """
    key = createRedisKey(fingerprint, 'ns')
    if not key:
        raise ValueError("Unsuitable key for storing data in Redis: '%r'"
                         % fingerprint)
    return key

def setNetworkStatuses(routers, **kwargs):
    """Given a bunch of parsed networkstatus documents, create a single
    ``RedisClient`` which pipelines the handling of atomic database
    transactions for storing each document by it corresponding router
    fingerprint.

    :param dict routers: A mapping of [bridge-]router fingerprints to
        :api:`~stem.descriptor.router_status_entry._RouterStatusEntryV2`
        instances, as returned from from the ``routers`` attribute of a
        :api:`~stem.descriptor.networkstatus.BridgeNetworkStatusDocument`.
    :kwargs: are passed to :func:`connectServer`, which creates the
        ``RedisClient``.
    """
    logging.info(("REDIS: Attempting to store %d bridge networkstatus "
                  "documents.") % (len(routers.keys())))

    def storeDescriptor(redis, router):
        """Store the networkstatus descriptor in Redis using SETEX.

        :type redis: ``txredis.client.RedisClient``
        :param redis: A ``RedisClient`` connected to a Redis server, i.e. the
            result of the ``Deferred`` returned from :func:`connectServer`.
        :type router:
            :api:`~stem.descriptor.router_status_entry.RouterStatusEntryV2`
        :param router: A single parsed networkstatus document (for a single
            router) from Stem.
        """
        fingerprint, descriptor = router

        # Stem stores the entire file which a networkstatus descriptor
        # originated from in every single descriptor's ``document`` property,
        # while it's ``__str__()`` method will produce the single descriptor.
        #
        # We don't want to serialise and store the entire file that the single
        # networkstatus document originated from, so we need to override the
        # ``document`` attribute with just the single descriptor:
        descriptor.document = str(descriptor)

        # Basic sanity check, make sure we're not shoving massive amounts of
        # data into the database:
        descriptorLength = len(str(descriptor))
        if descriptorLength >= 1000:
            logging.warn("Got huge networkstatus descriptor with length=%d: %s"
                         % (descriptorLength, str(descriptor)))

        key = getNetworkStatusKey(fingerprint)
        jellied = jelly.jelly(descriptor)
        logging.debug("REDIS: SETEX %s ..." % (key))
        response = redis.set(key, jellied, expire=DESC_EXPIRE)
        result = (redis, key, response)
        return result

    def storeDescriptorEB(fail):
        """Log and swallow failures stemming from :func:`storeDescriptor`."""
        logging.error(fail.getTraceback())
        return fail

    def transactionsResults(results):
        """Count the successes and handle the failures in the list of results
        returned from the :api:`~twisted.internet.defer.DeferredList` of Redis
        transactions.

        .. info: This function send the ``QUIT`` command to the
            ``RedisClient``.

        :param list results: A list of 2-tuples. The first value in each tuple
            is a boolean, representing whether the transaction was
            successful. The second is the result value for the underlying
            deferred.
        :rtype: :api:`~twisted.internet.defer.Deferred`
        :returns: A deferred which will eventually fire back with the result
            of the final ``QUIT`` command for the ``RedisClient``.
        """
        okay = 0
        fails = []
        redis = results[0][1][0]

        # The `success` here is a boolean, while the `value` is the returned
        # result of :func:`storeDescriptor`, i.e.::
        #   (<RedisClient at 0x1234>, key, <Deferred at 0x5678>)
        for (success, value) in results:
            if success:
                okay += 1
                logging.debug("REDIS: %s: OK" % value[1])
            else:
                fails.append(value)

        logging.info("REDIS: %d success, %d failed" % (okay, len(fails)))
        [logging.warn("REDIS: %r" % repr(fail)) for fail in fails]
        logging.debug("REDIS: QUIT %s" % hash(redis))
        d = redis.quit()
        return d

    def redisCB(redis, transactions):
        """Callback every waiting database transaction in the ``DeferredList``
        with the ready ``RedisClient``, when the later has finished connecting
        to the Redis server.

        :type redis: ``txredis.client.RedisClient``
        :param redis: A ``RedisClient`` connected to a Redis server, i.e. the
            result of the ``Deferred`` returned from :func:`connectServer`.
        """
        [d.callback(redis) for d in transactions]
        return redis

    transactions = []
    for router in routers.items():
        d = defer.Deferred()
        d.addCallback(setDescriptor, router)
        d.addCallbacks(defer.passthru, setDescriptorEB)
        transactions.append(d)

    redis = connectServer(**kwargs)
    dl = defer.DeferredList(transactions, consumeErrors=True)
    dl.addCallback(transactionsResults)
    redis.addCallback(redisCB)
    return redis


if __name__ == "__main__":
    logging.getLogger().setLevel(10)

    from bridgedb.parse import descriptors

    password = "bridgedbtestingbridgedbtestingbridgedbtesting"
    rundir = '/home/isis/code/torproject/bridgedb/run-manual'
    filename = "%s/250_networkstatus-bridges" % rundir
    bridgeNetworkStatusDocument = descriptors.parseNetworkStatusFile(filename)
    bridgeRouters = bridgeNetworkStatusDocument.routers

    setNetworkStatuses(bridgeRouters, password=password)
    reactor.callLater(2, reactor.stop)
    reactor.run()

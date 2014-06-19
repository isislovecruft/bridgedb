

from __future__ import print_function
from __future__ import unicode_literals

import logging
import os

from twisted.internet import defer
from twisted.internet import endpoints
from twisted.internet import protocol
from twisted.internet import reactor
from twisted.spread import jelly

from txredis.client import RedisClient
from txredis.client import RedisClientFactory

from bridgedb import safelog

REDIS_HOST = '127.0.0.1'
REDIS_PORT = 6379

#: The number of seconds to expire strored bridge networkstatus documents
#: after. (default: 604800, i.e. 1 week)
DESC_EXPIRE = 7 * 24 * 60 * 60


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

    creator = protocol.ClientCreator(reactor, RedisClient, password=password, **kwargs)
    redis = creator.connectTCP(host, port)
    redis.addCallbacks(cb, logging.error)
    return redis

def getNetworkStatusKey(fingerprint):
    """Create a key for storing a networkstatus descriptor in Redis, based upon
    the router's **fingerprint**.

    :param str fingerprint: The router's identity fingerprint.
    :rtype: str
    :returns: The **fingerprint** with ``'_ns'`` appended to it. If for some
        reason, the fingerprint is ``None`` (this seems to happen sometimes),
        then ``None`` is returned.
    """
    if fingerprint:
        return u"%s_ns" % fingerprint

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

    def setDescriptor(redis, router):
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
        # We don't want to serialise the entire file that the single
        # networkstatus document originated from, so we need to override this
        # attribute with just the single descriptor before serialisation:
        descriptor.document = str(descriptor)
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

    def setDescriptorEB(fail):
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
        # result of :func:`setDescriptor`, i.e.::
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

    def redisCB(redis):
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

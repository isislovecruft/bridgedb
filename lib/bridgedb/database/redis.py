

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

#: This will be our global ``txredis.client.RedisClientFactory``, created with
#: :func:`buildClientFactory`.
theFactory = None

def buildClientFactory(db=None, password=None, clock=None):
    """DOCDOC

    .. info:: Uses ``REDIS_DBFILE`` and ``REDIS_PASSWORD`` config variables.

    .. note:: The returned factory is a subclass of
        :api:`twisted.internet.protocol.ReconnectingClientFactory`, meaning
        that it will attempt to reconnect if a connection is dropped with an
        error or otherwise not immediately connection when
        ``factory.buildProtocol()`` is called.

    :param str db: The path to an `.rdb` Redis database file to use.
    :param str password: The string to use in the client AUTH message to the
        Redis server. The corresponding Redis setting in `redis.conf` for
        setting this on the server side is ``requirepass``.
    :param clock: A provider of
        :api:`twisted.internet.interfaces.IReactorTime`, to be used only for
        unittesting purposes.
    :rtype: ``txredis.client.RedisClientFactory``
    :returns: A client factory which will load the specified **db** file, and
        optionally AUTH with the given **password**.
    """
    logging.info("REDIS: Creating RedisClientFactory...")
    logging.info("REDIS: Using database file: %s" % db)
    if password:
        logging.info("REDIS: Clients will AUTH with password: %s"
                     % safelog.logSafely(password))
    factory = RedisClientFactory(db=db, password=password,
                                 charset='utf8', errors='strict')
    if clock:  # pragma: no cover
        factory.clock = clock

    return factory

def setClientFactory(factory=None, **kwargs):
    """Set :data:`theFactory` to the given **factory**.

    :type factory: ``txredis.client.RedisClientFactory``
    :param factory: An initialised client factory for connecting to a Redis
        server.
    :kwargs: Are passed to :func:`buildClientFactory`.
    :rtype: bool
    :returns: ``True`` if we were able to set the global :data:`theFactory`,
        and ``False`` otherwise.
    """
    try:
        if factory is None:
            factory = buildClientFactory(**kwargs)
        global theFactory
        theFactory = factory
    except Exception as error:  # pragma: no cover
        logging.exception(error)
        return False
    return True

if not theFactory:
    setClientFactory()

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

def storeNetworkStatus(router, **kwargs):
    def storeDescriptor(db, router):
        fingerprint, descriptor = router

        # We don't want to serialise the entire file that the single
        # networkstatus document originated from, so we need to override this
        # attribute with just the single descriptor:
        descriptor.document = str(descriptor)

        descriptorLength = len(str(descriptor))
        if descriptorLength >= 1000:
            logging.warn("Got huge networkstatus descriptor with length=%d: %s"
                         % (descriptorLength, str(descriptor)))

        key = getNetworkStatusKey(fingerprint)
        jellied = jelly.jelly(descriptor)

        logging.debug("REDIS: SETEX %s ..." % (key))
        response = db.set(key, jellied, expire=DESC_EXPIRE)
        result = (db, key, response)

        return result

    def storeDescriptorCB(result):
        (db, key, response) = result

        def logResponse(response, key):
            logging.debug("REDIS: %s: %s" % (key, response))
        response.addCallback(logResponse, key)

        logging.debug("REDIS: QUIT %s" % hash(db))
        d = db.quit()
        return d

    def storeDescriptorEB(fail):
        logging.error(fail.getTraceback())

    d1 = connectServer(**kwargs)
    d2 = defer.Deferred()
    d2.addCallback(storeDescriptor, router)
    d2.addCallbacks(storeDescriptorCB, storeDescriptorEB)
    d1.chainDeferred(d2)
    return d1


if __name__ == "__main__":
    logging.getLogger().setLevel(10)

    from bridgedb.parse import descriptors

    password = "bridgedbtestingbridgedbtestingbridgedbtesting"
    rundir = '/home/isis/code/torproject/bridgedb/run-manual'
    filename = "%s/250_networkstatus-bridges" % rundir
    bridgeNetworkStatusDocument = descriptors.parseNetworkStatusFile(filename)
    bridgeRouters = bridgeNetworkStatusDocument.routers

    #     This version creates a client for every single transaction. For 250
    # networkstatus descriptors, the average runtime is 62ms.

    #for router in bridgeRouters.items():
    #    storeNetworkStatus(router, password=password)

    #     This version creates a single client, and creates a DeferredList,
    # which acts as a queue, feeding transactions onto the wire as fast as they
    # can be handled. For 250 networkstatus descriptors, the average runtime is
    # 20ms.

    setNetworkStatuses(bridgeRouters, password=password)

    reactor.callLater(2, reactor.stop)
    reactor.run()



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
    # This is really noisey:
    #logging.debug("REDIS: Connecting to server: %s:%d" % (host, port))

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
    return fingerprint + u'_ns'

#: The number of seconds to expire strored bridge networkstatus documents
#: after. (default: 604800, i.e. 1 week)
DESC_EXPIRE = 7 * 24 * 60 * 60

def setNetworkStatuses(routers, **kwargs):
    """DOCDOC

    :param dict routers: A mapping of [bridge-]router fingerprints to
        :api:`~stem.descriptor.router_status_entry._RouterStatusEntryV2`
        instances, as returned from from the ``routers`` attribute of a
        :api:`~stem.descriptor.networkstatus.BridgeNetworkStatusDocument`.
    """
    logging.info(("REDIS: Attempting to store %d bridge networkstatus "
                  "documents.") % (len(routers.keys())))
    redis = connectServer(**kwargs)

    def setDesc(db, router):
        fingerprint, descriptor = router
        key = getNetworkStatusKey(fingerprint)
        jellied = jelly.jelly(descriptor)
        logging.debug("REDIS: SETEX %s ..." % (key))
        response = db.set(key, jellied, expire=DESC_EXPIRE)
        return response

    def setDescEB(failure):
        tb = failure.getTraceback()
        logging.error(tb)

    responses = []
    for router in routers.items():
        d1 = connectServer(**kwargs)
        d1.addErrback(setDescEB)
        d2 = defer.Deferred()
        d2.addCallback(setDesc, router)
        d2.addErrback(setDescEB)
        d1.chainDeferred(d2)

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
        result = (db, response)

        return result

    def storeDescriptorCB(result):
        (db, response) = result

        def logResponse(response):
            logging.debug("REDIS: server response: %s" % response)
        response.addCallbacks(logResponse, logging.error)

        logging.debug("REDIS: QUIT %s" % hash(db))
        d = db.quit()
        d.addCallbacks(logResponse, logging.error)
        return d

    def storeDescriptorEB(fail):
        logging.error(fail.getTraceback())

    def killConnection(db):
        logging.debug("REDIS: QUIT %s" % db)
        db.quit()
        return db

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
    filename = "%s/10000_networkstatus-bridges" % rundir
    bridgeNetworkStatusDocument = descriptors.parseNetworkStatusFile(filename)
    bridgeRouters = bridgeNetworkStatusDocument.routers

    for router in bridgeRouters.items():
        storeNetworkStatus(router, password=password)

    reactor.run()

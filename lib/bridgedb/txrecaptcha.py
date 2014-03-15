# -*- coding: utf-8 ; test-case-name: bridgedb.test.test_txrecaptcha -*-
#
# This file is part of BridgeDB, a Tor bridge distribution system.
#
# :authors: Isis Lovecruft 0xA3ADB67A2CDB8B35 <isis@torproject.org>
# :copyright: (c) 2013-2014, Isis Lovecruft
#             (c) 2007-2014, The Tor Project, Inc.
# :license: 3-Clause BSD, see LICENSE for licensing information


import logging
import urllib

from recaptcha.client.captcha import API_SSL_SERVER
from recaptcha.client.captcha import RecaptchaResponse
from recaptcha.client.captcha import displayhtml

from twisted.internet import defer
from twisted.internet import protocol
from twisted.internet import reactor
from twisted.python import failure
from twisted.web import client
from twisted.web.http_headers import Headers
from twisted.web.iweb import IBodyProducer

from zope.interface import implements

from bridgedb.crypto import SSLVerifyingContextFactory


API_SERVER = API_SSL_SERVER
API_SSL_VERIFY_URL = "%s/verify" % API_SSL_SERVER

_pool = client.HTTPConnectionPool(reactor, persistent=False)
_pool.maxPersistentPerHost = 5
_pool.cachedConnectionTimeout = 30
_agent = client.Agent(reactor, pool=_pool)


def _setAgent(agent):
    """Set the global :attr:`agent`.

    :param agent: An :api:`twisted.web.client.Agent` for issuing requests.
    """
    global _agent
    _agent = agent

def _getAgent(reactor=reactor, url=API_SSL_VERIFY_URL, pool=_pool,
              connectTimeout=30, **kwargs):
    """Create a :api:`twisted.web.client.Agent` which will verify the
    certificate chain and hostname for the given **url**.

    :param reactor: A provider of the
        :api:`twisted.internet.interface.IReactorTCP` interface.
    :param str url: The full URL which will be requested with the
        ``Agent``. (default: :attr:`API_SSL_VERIFY_URL`)
    :param pool: An :api:`twisted.web.client.HTTPConnectionPool`
        instance. (default: :attr:`_pool`)
    :type connectTimeout: None or int
    :param connectTimeout: If not ``None``, the timeout passed to
        :api:`twisted.internet.reactor.connectTCP` or
        :api:`twisted.internet.reactor.connectSSL` for specifying the
        connection timeout. (default: ``30``)
    """
    return client.Agent(reactor,
                        contextFactory=SSLVerifyingContextFactory(url),
                        connectTimeout=connectTimeout,
                        pool=pool,
                        **kwargs)

_setAgent(_getAgent())


class RecaptchaResponseError(ValueError):
    """There was an error with the reCaptcha API server's response."""


class RecaptchaResponseProtocol(protocol.Protocol):
    """HTML parser which creates a :class:`RecaptchaResponse` from the body of
    the reCaptcha API server's response.
    """
    def __init__(self, finished):
        """Create a protocol for creating :class:`RecaptchaResponse`s.

        :type finished: :api:`~twisted.internet.defer.Deferred`
        :param finished: A deferred which will have its ``callback()`` called
             with a :class:`RecaptchaResponse`.
        """
        self.finished = finished
        self.remaining = 1024 * 10
        self.response = ''

    def dataReceived(self, data):
        """Called when some data is received from the connection."""
        if self.remaining:
            received = data[:self.remaining]
            self.response += received
            self.remaining -= len(received)

    def connectionLost(self, reason):
        """Called when the connection was closed.

        :type reason: :api:`twisted.python.failure.Failure`
        :param reason: A string explaning why the connection was closed,
            wrapped in a ``Failure`` instance.

        :raises: A :api:`twisted.internet.error.ConnectError` if the 
        """
        valid = False
        error = reason.getErrorMessage()
        try:
            (valid, error) = self.response.strip().split('\n', 1)
        except ValueError:
            error = "Couldn't parse response from reCaptcha API server"

        valid = bool(valid == "true")
        result = RecaptchaResponse(is_valid=valid, error_code=error)
        logging.debug(
            "ReCaptcha API server response: %s(is_valid=%s, error_code=%s)"
            % (result.__class__.__name__, valid, error))
        self.finished.callback(result)


class _BodyProducer(object):
    """I write a string into the HTML body of an open request."""
    implements(IBodyProducer)

    def __init__(self, body):
        self.body = body
        self.length = len(body)

    def startProducing(self, consumer):
        """Start writing the HTML body."""
        consumer.write(self.body)
        return defer.succeed(None)

    def pauseProducing(self):
        pass

    def stopProducing(self):
        pass

    def resumeProducing(self):
        pass


def _cbRequest(response):
    """Callback for a :api:`twisted.web.client.Agent.request` which delivers
    the result to a :class:`RecaptchaResponseProtocol`.

    :returns: A :api:`~twisted.internet.defer.Deferred` which will callback
    with a ``recaptcha.RecaptchaResponse`` for the request.
    """
    finished = defer.Deferred()
    response.deliverBody(RecaptchaResponseProtocol(finished))
    return finished

def _ebRequest(fail):
    """Errback for a :api:`twisted.web.client.Agent.request`.

    :param fail: A :api:`twisted.python.failure.Failure` which occurred during
        the request.
    """
    logging.debug("txrecaptcha._ebRequest() called with %r" % fail)
    error = fail.getErrorMessage() or "possible problem in _ebRequest()"
    return RecaptchaResponse(is_valid=False, error_code=error)

def _encodeIfNecessary(string):
    """Encode unicode objects in utf-8 if necessary."""
    if isinstance(string, unicode):
        return string.encode('utf-8')
    return string

def submit(recaptcha_challenge_field, recaptcha_response_field,
           private_key, remoteip, agent=_agent):
    """Submits a reCaptcha request for verification. This function is a patched
    version of the ``recaptcha.client.captcha.submit()`` function in
    reCaptcha's Python API.

    It does two things differently:
        1. It uses Twisted for everything.
        2. It uses SSL/TLS for everything.

    This function returns a :api:`~twisted.internet.defer.Deferred`. If you
    need a ``recaptcha.client.captcha.RecaptchaResponse`` to be returned, use
    the :func:`submit` function, which is an ``@inlineCallbacks`` wrapper for
    this function.

    :param str recaptcha_challenge_field: The value of the HTTP POST
        ``recaptcha_challenge_field`` argument from the form.
    :param recaptcha_response_field: The value of the HTTP POST
        ``recaptcha_response_field`` argument from the form.
    :param private_key: The reCAPTCHA API private key.
    :param remoteip: An IP address to give to the reCaptcha API server.
    :returns: A :api:`~twisted.internet.defer.Deferred` which will callback
        with a ``recaptcha.RecaptchaResponse`` for the request.
    """
    if not (recaptcha_response_field and
            recaptcha_challenge_field and
            len(recaptcha_response_field) and
            len(recaptcha_challenge_field)):
        return RecaptchaResponse(is_valid=False,
                                 error_code='incorrect-captcha-sol')

    params = urllib.urlencode({
        'privatekey': _encodeIfNecessary(private_key),
        'remoteip':   _encodeIfNecessary(remoteip),
        'challenge':  _encodeIfNecessary(recaptcha_challenge_field),
        'response':   _encodeIfNecessary(recaptcha_response_field)})
    body = _BodyProducer(params)
    headers = Headers({"Content-type": ["application/x-www-form-urlencoded"],
                       "User-agent": ["reCAPTCHA Python"]})
    d = agent.request('POST', API_SSL_VERIFY_URL, headers, body)
    d.addCallbacks(_cbRequest, _ebRequest)
    return d

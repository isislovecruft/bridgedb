# -*- coding: utf-8 ; test-case-name: bridgedb.test.test_distributors_moat_server -*-
#
# This file is part of BridgeDB, a Tor bridge distribution system.
#
# :authors: please see included AUTHORS file
# :copyright: (c) 2017, The Tor Project, Inc.
#             (c) 2017, Isis Lovecruft
# :license: see LICENSE for licensing information

"""
.. py:module:: bridgedb.distributors.moat.server
    :synopsis: Server which implements JSON API to interface with Tor Browser
               clients through a meek tunnel.

bridgedb.distributors.moat.server
=================================

Server which implements JSON API to interface with Tor Browser clients through a
meek tunnel.

.. inheritance-diagram:: JsonAPIResource JsonAPIErrorResource CustomErrorHandlingResource JsonAPIDataResource CaptchaResource CaptchaCheckResource CaptchaFetchResource
    :parts: 1
"""

from __future__ import print_function

import base64
import json
import logging
import time

from functools import partial

from ipaddr import IPAddress

from twisted.internet import reactor
from twisted.internet.error import CannotListenError
from twisted.web import resource
from twisted.web.server import Site

from bridgedb import captcha
from bridgedb import crypto
from bridgedb.distributors.common.http import setFQDN
from bridgedb.distributors.common.http import getFQDN
from bridgedb.distributors.common.http import getClientIP
from bridgedb.distributors.moat.request import MoatBridgeRequest
from bridgedb.qrcodes import generateQR
from bridgedb.schedule import Unscheduled
from bridgedb.schedule import ScheduledInterval
from bridgedb.util import replaceControlChars


#: The current version of the moat JSON API that we speak
MOAT_API_VERSION = '0.1.0'

#: The root path to resources for the moat server
SERVER_PUBLIC_ROOT = None

#: An ordered list of the preferred transports which moat should
#: distribute, in order from most preferable to least preferable.
TRANSPORT_PREFERENCE_LIST = None

#: All of the pluggable transports BridgeDB currently supports.
SUPPORTED_TRANSPORTS = None


def getFQDNAndRoot():
    """Get the server's public FQDN plus the root directory for the web server.
    """
    root = getRoot()
    fqdn = getFQDN()

    if not root.startswith('/') and not fqdn.endswith('/'):
        return '/'.join([fqdn, root])
    else:
        return ''.join([fqdn, root])

def setRoot(root):
    """Set the global :data:`SERVER_PUBLIC_ROOT` variable.

    :param str root: The path to the root directory for the web server.
    """
    logging.info("Setting Moat server public root to %r" % root)

    global SERVER_PUBLIC_ROOT
    SERVER_PUBLIC_ROOT = root

def getRoot():
    """Get the setting for the HTTP server's public FQDN from the global
    :data:`SERVER_PUBLIC_FQDN variable.

    :rtype: str or None
    """
    return SERVER_PUBLIC_ROOT

def setPreferredTransports(preferences):
    """Set the global ``TRANSPORT_PREFERENCE_LIST``."""
    global TRANSPORT_PREFERENCE_LIST
    TRANSPORT_PREFERENCE_LIST = preferences

def getPreferredTransports():
    """Get the global ``TRANSPORT_PREFERENCE_LIST``.

    :rtype: list
    :returns: A list of preferences for which pluggable transports to distribute
        to moat clients.
    """
    return TRANSPORT_PREFERENCE_LIST

def setSupportedTransports(transports):
    """Set the global ``SUPPORTED_TRANSPORTS``.

    :param dist transports: The ``SUPPORTED_TRANSPORTS`` dict from a
        bridgedb.conf file.
    """
    supported = [k for (k, v) in transports.items() if v]

    if not "vanilla" in supported:
        supported.append("vanilla")

    global SUPPORTED_TRANSPORTS
    SUPPORTED_TRANSPORTS = supported

def getSupportedTransports():
    """Get the global ``SUPPORTED_TRANSPORTS``.

    :rtype: list
    :returns: A list all pluggable transports we support.
    """
    return SUPPORTED_TRANSPORTS


class JsonAPIResource(resource.Resource):
    """A resource which conforms to the `JSON API spec <http://jsonapi.org/>`__.
    """

    def __init__(self, useForwardedHeader=True):
        resource.Resource.__init__(self)
        self.useForwardedHeader = useForwardedHeader

    def getClientIP(self, request):
        """Get the client's IP address from the ``'X-Forwarded-For:'``
        header, or from the :api:`request <twisted.web.server.Request>`.

        :type request: :api:`twisted.web.http.Request`
        :param request: A ``Request`` for a
            :api:`twisted.web.resource.Resource`.
        :rtype: ``None`` or :any:`str`
        :returns: The client's IP address, if it was obtainable.
        """
        return getClientIP(request, self.useForwardedHeader)

    def formatDataForResponse(self, data, request):
        """Format a dictionary of ``data`` into JSON and add necessary response
        headers.

        This method will set the appropriate response headers:
            * `Content-Type: application/vnd.api+json`
            * `Server: moat/VERSION`

        :type data: dict
        :param data: Some data to respond with.  This will be formatted as JSON.
        :type request: :api:`twisted.web.http.Request`
        :param request: A ``Request`` for a :api:`twisted.web.resource.Resource`.
        :returns: The encoded data.
        """
        request.responseHeaders.addRawHeader(b"Content-Type", b"application/vnd.api+json")
        request.responseHeaders.addRawHeader(b"Server", b"moat/%s" % MOAT_API_VERSION)

        if data:
            rendered = json.dumps(data)
        else:
            rendered = b""

        return rendered


class JsonAPIErrorResource(JsonAPIResource):
    """A JSON API resource which explains that some error has occured."""

    isLeaf = True

    def __init__(self, id=0, type="", code=200, status="OK", detail=""):
        """Create a :api:`twisted.web.resource.Resource` for a JSON API errors
        object.
        """
        resource.Resource.__init__(self)
        self.id = id
        self.type = type
        self.code = code
        self.status = status
        self.detail = detail

    def render_GET(self, request):
        # status codes and messages are at the JSON API layer, not HTTP layer:
        data = {
            'errors': [{
                'id': self.id,
                'type': self.type,
                'version': MOAT_API_VERSION,
                'code': self.code,
                'status': self.status,
                'detail': self.detail,
            }]
        }
        return self.formatDataForResponse(data, request)

    render_POST = render_GET


resource403 = JsonAPIErrorResource(code=403, status="Forbidden")
resource406 = JsonAPIErrorResource(code=406, status="Not Acceptable")
resource415 = JsonAPIErrorResource(code=415, status="Unsupported Media Type")
resource419 = JsonAPIErrorResource(code=419, status="No You're A Teapot")
resource501 = JsonAPIErrorResource(code=501, status="Not Implemented")


class CustomErrorHandlingResource(resource.Resource):
    """A :api:`twisted.web.resource.Resource` which wraps the
    :api:`twisted.web.resource.Resource.getChild` method in order to use
    custom error handling pages.
    """
    def getChild(self, path, request):
        logging.debug("[501] %s %s" % (request.method, request.uri))

        response = resource501
        response.detail = "moat version %s does not implement %s %s" % \
                          (MOAT_API_VERSION, request.method, request.uri)
        return response


class JsonAPIDataResource(JsonAPIResource):
    """A resource which returns some JSON API data."""

    def __init__(self, useForwardedHeader=True):
        JsonAPIResource.__init__(self, useForwardedHeader)

    def checkRequestHeaders(self, request):
        """The JSON API specification requires servers to respond with certain HTTP
        status codes and message if the client's request headers are inappropriate in
        any of the following ways:

        * Servers MUST respond with a 415 Unsupported Media Type status code if
          a request specifies the header Content-Type: application/vnd.api+json
          with any media type parameters.

        * Servers MUST respond with a 406 Not Acceptable status code if a
          request’s Accept header contains the JSON API media type and all
          instances of that media type are modified with media type parameters.
        """
        supports_json_api = False
        accept_json_api_header = False
        accept_header_is_ok = False

        if request.requestHeaders.hasHeader("Content-Type"):
            headers = request.requestHeaders.getRawHeaders("Content-Type")
            # The "pragma: no cover"s are because, no matter what I do, I cannot
            # for the life of me trick twisted's test infrastructure to not send
            # some variant of these headers. ¯\_(ツ)_/¯
            for contentType in headers:  # pragma: no cover
                # The request must have the Content-Type set to 'application/vnd.api+json':
                if contentType == 'application/vnd.api+json':
                    supports_json_api = True
                # The request must not specify a Content-Type with media parameters:
                if ';' in contentType:
                    supports_json_api = False

        if not supports_json_api:
            return resource415

        # If the request has an Accept header which contains
        # 'application/vnd.api+json' then at least one instance of that type
        # must have no parameters:
        if request.requestHeaders.hasHeader("Accept"):  # pragma: no cover
            headers = request.requestHeaders.getRawHeaders("Accept")
            for accept in headers:
                if accept.startswith('application/vnd.api+json'):
                    accept_json_api_header = True
                    if ';' not in accept:
                        accept_header_is_ok = True

        if accept_json_api_header and not accept_header_is_ok:  # pragma: no cover
            return resource406


class CaptchaResource(JsonAPIDataResource):
    """A CAPTCHA."""

    def __init__(self, hmacKey=None, publicKey=None, secretKey=None,
                 useForwardedHeader=True):
        JsonAPIDataResource.__init__(self, useForwardedHeader)
        self.hmacKey = hmacKey
        self.publicKey = publicKey
        self.secretKey = secretKey


class CaptchaFetchResource(CaptchaResource):
    """A resource to retrieve a CAPTCHA challenge."""

    isLeaf = True

    def __init__(self, hmacKey=None, publicKey=None, secretKey=None,
                 captchaDir="captchas", useForwardedHeader=True):
        """DOCDOC

        :param bytes hmacKey: The master HMAC key, used for validating CAPTCHA
            challenge strings in :meth:`captcha.GimpCaptcha.check`. The file
            where this key is stored can be set via the
            ``GIMP_CAPTCHA_HMAC_KEYFILE`` option in the config file.
            are stored. See the ``GIMP_CAPTCHA_DIR`` config setting.
        :param str secretkey: A PKCS#1 OAEP-padded, private RSA key, used for
            verifying the client's solution to the CAPTCHA. See
            :func:`bridgedb.crypto.getRSAKey` and the
            ``GIMP_CAPTCHA_RSA_KEYFILE`` config setting.
        :param str publickey: A PKCS#1 OAEP-padded, public RSA key, used for
            creating the ``captcha_challenge_field`` string to give to a
            client.
        :param str captchaDir: The directory where the cached CAPTCHA images
        :param bool useForwardedHeader: If ``True``, obtain the client's IP
            address from the ``X-Forwarded-For`` HTTP header.
        """
        CaptchaResource.__init__(self, hmacKey, publicKey, secretKey,
                                 useForwardedHeader)
        self.captchaDir = captchaDir
        self.supportedTransports = getSupportedTransports()

    def getCaptchaImage(self, request):
        """Get a random CAPTCHA image from our **captchaDir**.

        Creates a :class:`~bridgedb.captcha.GimpCaptcha`, and calls its
        :meth:`~bridgedb.captcha.GimpCaptcha.get` method to return a random
        CAPTCHA and challenge string.

        :type request: :api:`twisted.web.http.Request`
        :param request: A client's initial request for some other resource
            which is protected by this one (i.e. protected by a CAPTCHA).
        :returns: A 2-tuple of ``(image, challenge)``, where::
            - ``image`` is a string holding a binary, JPEG-encoded image.
            - ``challenge`` is a unique string associated with the request.
        """
        # Create a new HMAC key, specific to requests from this client:
        clientIP = self.getClientIP(request)
        clientHMACKey = crypto.getHMAC(self.hmacKey, clientIP)
        capt = captcha.GimpCaptcha(self.publicKey, self.secretKey,
                                   clientHMACKey, self.captchaDir)
        try:
            capt.get()
        except captcha.GimpCaptchaError as error:
            logging.debug(error)
        except Exception as impossible:
            logging.error("Unhandled error while retrieving Gimp captcha!")
            logging.error(impossible)

        return (capt.image, capt.challenge)

    def getPreferredTransports(self, supportedTransports):
        """Choose which transport a client should request, based on their list
        of ``supportedTransports``.

        :param list supportedTransports: A list of transports the client
            reported that they support (as returned from
            :meth:`~bridgedb.distributors.moat.server.CaptchaFetchResource.extractSupportedTransports`).
        :rtype: str or list
        :returns: A string specifying the chosen transport, provided there is an
            overlap between which transports BridgeDB and the client support.
            Otherwise, if there is no overlap, returns a list of all the
            transports which BridgeDB *does* support.
        """
        preferenceOrder = getPreferredTransports()
        preferred = None

        for pt in preferenceOrder:
            if pt in supportedTransports:
                preferred = pt

        # If we couldn't pick the best one that we both support, return the
        # whole list of what we're able to distribute:
        if not preferred:
            preferred = getSupportedTransports()

        return preferred

    def extractSupportedTransports(self, request):
        """Extract the transports a client supports from their POST request.

        :param str request: A JSON blob containing the following
            fields:
                * "version": The moat protocol version.
                * "type": "moat-transports".
                * "supported": ["TRANSPORT", … ]
            where:
                * ``TRANSPORT`` is a string identifying a transport, e.g.
                  "obfs3" or "obfs4". Currently supported transport identifiers
                  are: "vanilla", "fte", "obfs3", "obfs4", "scramblesuit".
        :rtype: list
        :returns: The list of transports the client supports.
        """
        supported = []

        try:
            encoded_data = request.content.read()
            data = json.loads(encoded_data)["data"][0]

            if data["type"] != "moat-transports":
                raise ValueError(
                    "Bad JSON API object type: expected %s got %s" %
                    ('moat-transports', data["type"]))
            elif data["version"] != MOAT_API_VERSION:
                raise ValueError(
                    "Client requested protocol version %s, but we're using %s" %
                    (data["version"], MOAT_API_VERSION))
            elif not data["supported"]:
                raise ValueError(
                    "Client didn't provide any supported transports")
            else:
                supported = data["supported"]
        except KeyError as err:
            logging.debug(("Error processing client POST request: Client JSON "
                           "API data missing '%s' field") % (err))
        except ValueError as err:
            logging.warn("Error processing client POST request: %s" % err)
        except Exception as impossible:
            logging.error("Unhandled error while extracting moat client transports!")
            logging.error(impossible)

        return supported

    def render_POST(self, request):
        """Retrieve a captcha from the moat API server and serve it to the client.

        :type request: :api:`twisted.web.http.Request`
        :param request: A ``Request`` object for a CAPTCHA.
        :rtype: str
        :returns: A JSON blob containing the following fields:
             * "version": The moat protocol version.
             * "image": A base64-encoded CAPTCHA JPEG image.
             * "challenge": A base64-encoded, encrypted challenge.  The client
               will need to hold on to the and pass it back later, along with
               their challenge response.
             * "error": An ASCII error message.
            Any of the above JSON fields may be "null".
        """
        error = self.checkRequestHeaders(request)

        if error:  # pragma: no cover
            return error.render(request)

        supported = self.extractSupportedTransports(request)
        preferred = self.getPreferredTransports(supported)
        image, challenge = self.getCaptchaImage(request)

        data = {
            'data': [{
                'id': 1,
                'type': 'moat-challenge',
                'version': MOAT_API_VERSION,
                'transport': preferred,
                'image': image,
                'challenge': challenge, # The challenge is already base64-encoded
            }]
        }

        try:
            data["data"][0]["image"] = base64.b64encode(image)
        except Exception as impossible:
            logging.error("Could not construct or encode captcha!")
            logging.error(impossible)

        return self.formatDataForResponse(data, request)


class CaptchaCheckResource(CaptchaResource):
    """A resource to verify a CAPTCHA solution and distribute bridges."""

    isLeaf = True

    def __init__(self, distributor, schedule, N=1,
                 hmacKey=None, publicKey=None, secretKey=None,
                 useForwardedHeader=True):
        """Create a new resource for checking CAPTCHA solutions and returning
        bridges to a client.

        :type distributor: :class:`MoatDistributor`
        :param distributor: The mechanism to retrieve bridges for this
            distributor.
        :type schedule: :class:`~bridgedb.schedule.ScheduledInterval`
        :param schedule: The time period used to tweak the bridge selection
            procedure.
        :param int N: The number of bridges to hand out per query.
        :param bool useForwardedHeader: Whether or not we should use the the
            X-Forwarded-For header instead of the source IP address.
        """
        CaptchaResource.__init__(self, hmacKey, publicKey, secretKey,
                                 useForwardedHeader)
        self.distributor = distributor
        self.schedule = schedule
        self.nBridgesToGive = N
        self.useForwardedHeader = useForwardedHeader

    def getBridgeLines(self, ip, data):
        """Get bridge lines for a client's HTTP request.

        :param str ip: The client's IP address.
        :param dict data: The decoded JSON API data from the client's request.
        :rtype: list or None
        :returns: A list of bridge lines.
        """
        bridgeLines = None
        interval = self.schedule.intervalStart(time.time())

        logging.debug("Replying to JSON API request from %s." % ip)

        if ip and data:
            bridgeRequest = MoatBridgeRequest()
            bridgeRequest.client = IPAddress(ip)
            bridgeRequest.isValid(True)
            bridgeRequest.withIPversion()
            bridgeRequest.withPluggableTransportType(data)
            bridgeRequest.withoutBlockInCountry(data)
            bridgeRequest.generateFilters()

            bridges = self.distributor.getBridges(bridgeRequest, interval)
            bridgeLines = [replaceControlChars(bridge.getBridgeLine(bridgeRequest))
                           for bridge in bridges]

        return bridgeLines

    def extractClientSolution(self, data):
        """Extract the client's CAPTCHA solution from a POST request.

        This is used after receiving a POST request from a client (which
        should contain their solution to the CAPTCHA), to extract the solution
        and challenge strings.

        :param dict data: The decoded JSON API data from the client's request.
        :returns: A redirect for a request for a new CAPTCHA if there was a
            problem. Otherwise, returns a 2-tuple of strings, the first is the
            client's CAPTCHA solution from the text input area, and the second
            is the challenge string.
        """
        qrcode = False
        transport = None
        challenge, solution = None, None

        try:
            if data["type"] != "moat-solution":
                raise ValueError(
                    "Bad JSON API object type: expected %s got %s" %
                    ("moat-solution", data["type"]))
            elif data["id"] != 2:
                raise ValueError(
                    "Bad JSON API data id: expected 2 got %s" %
                    (data["id"]))
            elif data["version"] != MOAT_API_VERSION:
                raise ValueError(
                    "Client requested protocol version %s, but we're using %s" %
                    (data["version"], MOAT_API_VERSION))
            elif data["transport"] not in getSupportedTransports():
                raise ValueError(
                    "Transport '%s' is not currently supported" %
                    data["transport"])
            else:
                qrcode = True if data["qrcode"] == "true" else False
                transport = type('')(data["transport"])
                challenge = type('')(data["challenge"])
                solution = type('')(data["solution"])
        except KeyError as err:
            logging.warn(("Error processing client POST request: "
                          "Client JSON API data missing '%s' field.") % err)
        except ValueError as err:
            logging.warn("Error processing client POST request: %s" % err.message)
        except Exception as impossible:
            logging.error(impossible)

        return (qrcode, transport, challenge, solution)

    def checkSolution(self, challenge, solution, clientIP):
        """Process a solved CAPTCHA via
        :meth:`bridgedb.captcha.GimpCaptcha.check`.

        :param str challenge: A base64-encoded, encrypted challenge.
        :param str solution: The client's solution to the captcha
        :param str clientIP: The client's IP address.
        :rtupe: bool
        :returns: True, if the CAPTCHA solution was valid; False otherwise.
        """
        valid = False
        clientHMACKey = crypto.getHMAC(self.hmacKey, clientIP)

        try:
            valid = captcha.GimpCaptcha.check(challenge, solution,
                                              self.secretKey, clientHMACKey)
        except Exception as impossible:
            logging.error(impossible)
            raise impossible
        finally:
            logging.debug("%sorrect captcha from %r: %r." %
                          ("C" if valid else "Inc", clientIP, solution))

        return valid

    def failureResponse(self, id, request):
        """Respond with status code "419 No You're A Teapot"."""
        error_response = resource419
        error_response.type = 'moat-bridges'

        if id == 4:
            error_response.id = 4
            error_response.detail = "The CAPTCHA solution was incorrect."
        elif id == 5:
            error_response.id = 5
            error_response.detail = "The CAPTCHA challenge timed out."

        return error_response.render(request)

    def render_POST(self, request):
        """Process a client's CAPTCHA solution.

        If the client's CAPTCHA solution is valid (according to
        :meth:`checkSolution`), process and serve their original
        request. Otherwise, redirect them back to a new CAPTCHA page.

        :type request: :api:`twisted.web.http.Request`
        :param request: A ``Request`` object, including POST arguments which
            should include two key/value pairs: one key being
            ``'captcha_challenge_field'``, and the other,
            ``'captcha_response_field'``. These POST arguments should be
            obtained from :meth:`render_GET`.
        :rtype: str
        :returns: A rendered HTML page containing a ReCaptcha challenge image
            for the client to solve.
        """
        valid = False
        error = self.checkRequestHeaders(request)

        if error:  # pragma: no cover
            return error.render(request)

        data = {
            "data": [{
                "id": 3,
                "type": 'moat-bridges',
                "version": MOAT_API_VERSION,
                "bridges": None,
                "qrcode": None,
            }]
        }

        try:
            encoded_client_data = request.content.read()
            client_data = json.loads(encoded_client_data)["data"][0]
            clientIP = self.getClientIP(request)

            (include_qrcode, transport,
             challenge, solution) = self.extractClientSolution(client_data)

            valid = self.checkSolution(challenge, solution, clientIP)
        except captcha.CaptchaExpired:
            logging.debug("The challenge had timed out")
            return self.failureResponse(5, request)
        except Exception as impossible:
            logging.warn("Unhandled exception while processing a POST /fetch request!")
            logging.error(impossible)
            return self.failureResponse(4, request)

        if valid:
            qrcode = None
            bridgeLines = self.getBridgeLines(clientIP, client_data)

            if include_qrcode:
                qrjpeg = generateQR(bridgeLines)
                if qrjpeg:
                    qrcode = 'data:image/jpeg;base64,%s' % base64.b64encode(qrjpeg)

            data["data"][0]["qrcode"] = qrcode
            data["data"][0]["bridges"] = bridgeLines

            return self.formatDataForResponse(data, request)
        else:
            return self.failureResponse(4, request)


def addMoatServer(config, distributor):
    """Set up a web server for moat bridge distribution.

    :type config: :class:`bridgedb.persistent.Conf`
    :param config: A configuration object from
         :mod:`bridgedb.main`. Currently, we use these options::
             GIMP_CAPTCHA_DIR
             SERVER_PUBLIC_FQDN
             SUPPORTED_TRANSPORTS
             MOAT_DIST
             MOAT_DIST_VIA_MEEK_ONLY
             MOAT_TLS_CERT_FILE
             MOAT_TLS_KEY_FILE
             MOAT_SERVER_PUBLIC_ROOT
             MOAT_HTTPS_IP
             MOAT_HTTPS_PORT
             MOAT_HTTP_IP
             MOAT_HTTP_PORT
             MOAT_BRIDGES_PER_ANSWER
             MOAT_TRANSPORT_PREFERENCE_LIST
             MOAT_USE_IP_FROM_FORWARDED_HEADER
             MOAT_ROTATION_PERIOD
             MOAT_GIMP_CAPTCHA_HMAC_KEYFILE
             MOAT_GIMP_CAPTCHA_RSA_KEYFILE
    :type distributor: :class:`bridgedb.distributors.moat.distributor.MoatDistributor`
    :param distributor: A bridge distributor.
    :raises SystemExit: if the servers cannot be started.
    :rtype: :api:`twisted.web.server.Site`
    :returns: A webserver.
    """
    captcha = None
    fwdHeaders = config.MOAT_USE_IP_FROM_FORWARDED_HEADER
    numBridges = config.MOAT_BRIDGES_PER_ANSWER

    logging.info("Starting moat servers...")

    setFQDN(config.SERVER_PUBLIC_FQDN)
    setRoot(config.MOAT_SERVER_PUBLIC_ROOT)
    setSupportedTransports(config.SUPPORTED_TRANSPORTS)
    setPreferredTransports(config.MOAT_TRANSPORT_PREFERENCE_LIST)

    # Get the master HMAC secret key for CAPTCHA challenges, and then
    # create a new HMAC key from it for use on the server.
    captchaKey = crypto.getKey(config.MOAT_GIMP_CAPTCHA_HMAC_KEYFILE)
    hmacKey = crypto.getHMAC(captchaKey, "Moat-Captcha-Key")
    # Load or create our encryption keys:
    secretKey, publicKey = crypto.getRSAKey(config.MOAT_GIMP_CAPTCHA_RSA_KEYFILE)
    sched = Unscheduled()

    if config.MOAT_ROTATION_PERIOD:
        count, period = config.MOAT_ROTATION_PERIOD.split()
        sched = ScheduledInterval(count, period)

    sitePublicDir = getRoot()

    meek = CustomErrorHandlingResource()
    moat = CustomErrorHandlingResource()
    fetch = CaptchaFetchResource(hmacKey, publicKey, secretKey,
                                 config.GIMP_CAPTCHA_DIR, fwdHeaders)
    check = CaptchaCheckResource(distributor, sched, numBridges,
                                 hmacKey, publicKey, secretKey, fwdHeaders)

    moat.putChild("fetch", fetch)
    moat.putChild("check", check)
    meek.putChild("moat", moat)

    root = CustomErrorHandlingResource()
    root.putChild("meek", meek)

    site = Site(root)
    site.displayTracebacks = False

    if config.MOAT_HTTP_PORT:  # pragma: no cover
        ip = config.MOAT_HTTP_IP or ""
        port = config.MOAT_HTTP_PORT or 80
        try:
            reactor.listenTCP(port, site, interface=ip)
        except CannotListenError as error:
            raise SystemExit(error)
        logging.info("Started Moat HTTP server on %s:%d" % (str(ip), int(port)))

    if config.MOAT_HTTPS_PORT:  # pragma: no cover
        ip = config.MOAT_HTTPS_IP or ""
        port = config.MOAT_HTTPS_PORT or 443
        try:
            from twisted.internet.ssl import DefaultOpenSSLContextFactory
            factory = DefaultOpenSSLContextFactory(config.MOAT_TLS_KEY_FILE,
                                                   config.MOAT_TLS_CERT_FILE)
            reactor.listenSSL(port, site, factory, interface=ip)
        except CannotListenError as error:
            raise SystemExit(error)
        logging.info("Started Moat TLS server on %s:%d" % (str(ip), int(port)))

    return site

# -*- coding: utf-8 ; test-case-name: bridgedb.test.test_HTTPServer -*-
#
# This file is part of BridgeDB, a Tor bridge distribution system.
#
# :authors: please see included AUTHORS file
# :copyright: (c) 2007-2015, The Tor Project, Inc.
#             (c) 2013-2015, Isis Lovecruft
# :license: see LICENSE for licensing information

"""
This module implements the web (http, https) interfaces to the bridge database.
"""

import base64
import gettext
import logging
import random
import re
import textwrap
import time
import os

from functools import partial

from ipaddr import IPv4Address
from ipaddr import IPv6Address
from ipaddr import IPAddress

import mako.exceptions
from mako.template import Template
from mako.lookup import TemplateLookup

from twisted.internet import reactor
from twisted.internet.error import CannotListenError
from twisted.python import filepath
from twisted.web import resource
from twisted.web import server
from twisted.web import static
from twisted.web.util import redirectTo

import bridgedb.Dist
import bridgedb.geo

from bridgedb import captcha
from bridgedb import crypto
from bridgedb import strings
from bridgedb import translations
from bridgedb import txrecaptcha
from bridgedb.Filters import filterBridgesByIP4
from bridgedb.Filters import filterBridgesByIP6
from bridgedb.Filters import filterBridgesByTransport
from bridgedb.Filters import filterBridgesByNotBlockedIn
from bridgedb.parse import headers
from bridgedb.parse.addr import isIPAddress
from bridgedb.qrcodes import generateQR
from bridgedb.safelog import logSafely


TEMPLATE_DIR = os.path.join(os.path.dirname(__file__), 'templates')
rtl_langs = ('ar', 'he', 'fa', 'gu_IN', 'ku')

# Setting `filesystem_checks` to False is recommended for production servers,
# due to potential speed increases. This means that the atimes of the Mako
# template files aren't rechecked every time the template is requested
# (otherwise, if they are checked, and the atime is newer, the template is
# recompiled). `collection_size` sets the number of compiled templates which
# are cached before the least recently used ones are removed. See:
# http://docs.makotemplates.org/en/latest/usage.html#using-templatelookup
lookup = TemplateLookup(directories=[TEMPLATE_DIR],
                        output_encoding='utf-8',
                        filesystem_checks=False,
                        collection_size=500)
logging.debug("Set template root to %s" % TEMPLATE_DIR)

def replaceErrorPage(error, template_name=None):
    """Create a general error page for displaying in place of tracebacks.

    Log the error to BridgeDB's logger, and then display a very plain "Sorry!
    Something went wrong!" page to the client.

    :type error: :exc:`Exception`
    :param error: Any exeption which has occurred while attempting to retrieve
                  a template, render a page, or retrieve a resource.
    :param str template_name: A string describing which template/page/resource
                              was being used when the exception occurred,
                              i.e. ``'index.html'``.
    :returns: A string containing HTML to serve to the client (rather than
              serving a traceback).
    """
    logging.error("Error while attempting to render %s: %s"
                  % (template_name or 'template',
                     mako.exceptions.text_error_template().render()))

    # TRANSLATORS: Please DO NOT translate the following words and/or phrases in
    # any string (regardless of capitalization and/or punctuation):
    #
    # "BridgeDB"
    # "pluggable transport"
    # "pluggable transports"
    # "obfs2"
    # "obfs3"
    # "scramblesuit"
    # "fteproxy"
    # "Tor"
    # "Tor Browser"
    #
    errmsg = _("Sorry! Something went wrong with your request.")
    rendered = """<html>
                    <head>
                      <link href="/assets/bootstrap.min.css" rel="stylesheet">
                      <link href="/assets/custom.css" rel="stylesheet">
                    </head>
                    <body>
                      <p>{0}</p>
                    </body>
                  </html>""".format(errmsg)

    return rendered


class CaptchaProtectedResource(resource.Resource):
    """A general resource protected by some form of CAPTCHA."""

    isLeaf = True

    def __init__(self, publicKey=None, secretKey=None,
                 useForwardedHeader=False, protectedResource=None):
        resource.Resource.__init__(self)
        self.publicKey = publicKey
        self.secretKey = secretKey
        self.useForwardedHeader = useForwardedHeader
        self.resource = protectedResource

    def getClientIP(self, request):
        """Get the client's IP address from the :header:`X-Forwarded-For`
        header, or from the :api:`request <twisted.web.server.Request>`.

        :rtype: None or str
        :returns: The client's IP address, if it was obtainable.
        """
        ip = None
        if self.useForwardedHeader:
            h = request.getHeader("X-Forwarded-For")
            if h:
                ip = h.split(",")[-1].strip()
                if not isIPAddress(ip):
                    logging.warn("Got weird X-Forwarded-For value %r" % h)
                    ip = None
        else:
            ip = request.getClientIP()
        return ip

    def getCaptchaImage(self, request=None):
        """Get a CAPTCHA image.

        :returns: A 2-tuple of ``(image, challenge)``, where ``image`` is a
                  binary, JPEG-encoded image, and ``challenge`` is a unique
                  string. If unable to retrieve a CAPTCHA, returns a tuple
                  containing two empty strings.
        """
        return ('', '')

    def extractClientSolution(self, request):
        """Extract the client's CAPTCHA solution from a POST request.

        This is used after receiving a POST request from a client (which
        should contain their solution to the CAPTCHA), to extract the solution
        and challenge strings.

        :type request: :api:`twisted.web.http.Request`
        :param request: A ``Request`` object for 'bridges.html'.
        :returns: A redirect for a request for a new CAPTCHA if there was a
            problem. Otherwise, returns a 2-tuple of strings, the first is the
            client's CAPTCHA solution from the text input area, and the second
            is the challenge string.
        """
        try:
            challenge = request.args['captcha_challenge_field'][0]
            response = request.args['captcha_response_field'][0]
        except Exception:  # pragma: no cover
            return redirectTo(request.URLPath(), request)
        return (challenge, response)

    def checkSolution(self, request):
        """Override this method to check a client's CAPTCHA solution.

        :rtype: bool
        :returns: ``True`` if the client correctly solved the CAPTCHA;
            ``False`` otherwise.
        """
        return False

    def render_GET(self, request):
        """Retrieve a ReCaptcha from the API server and serve it to the client.

        :type request: :api:`twisted.web.http.Request`
        :param request: A ``Request`` object for a page which should be
            protected by a CAPTCHA.
        :rtype: str
        :returns: A rendered HTML page containing a ReCaptcha challenge image
            for the client to solve.
        """
        rtl = False
        image, challenge = self.getCaptchaImage(request)

        try:
            langs = translations.getLocaleFromHTTPRequest(request)
            rtl = translations.usingRTLLang(langs)
            # TODO: this does not work for versions of IE < 8.0
            imgstr = 'data:image/jpeg;base64,%s' % base64.b64encode(image)
            template = lookup.get_template('captcha.html')
            rendered = template.render(strings,
                                       rtl=rtl,
                                       lang=langs[0],
                                       imgstr=imgstr,
                                       challenge_field=challenge)
        except Exception as err:
            rendered = replaceErrorPage(err, 'captcha.html')

        request.setHeader("Content-Type", "text/html; charset=utf-8")
        return rendered

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
        request.setHeader("Content-Type", "text/html; charset=utf-8")

        if self.checkSolution(request) is True:
            try:
                rendered = self.resource.render(request)
            except Exception as err:
                rendered = replaceErrorPage(err)
            return rendered

        logging.debug("Client failed a CAPTCHA; returning redirect to %s"
                      % request.uri)
        return redirectTo(request.uri, request)


class GimpCaptchaProtectedResource(CaptchaProtectedResource):
    """A web resource which uses a local cache of CAPTCHAs, generated with
    gimp-captcha_, to protect another resource.

    .. _gimp-captcha: https://github.com/isislovecruft/gimp-captcha
    """

    def __init__(self, hmacKey=None, captchaDir='', **kwargs):
        """Protect a resource via this one, using a local CAPTCHA cache.

        :param str secretkey: A PKCS#1 OAEP-padded, private RSA key, used for
            verifying the client's solution to the CAPTCHA. See
            :func:`bridgedb.crypto.getRSAKey` and the
            ``GIMP_CAPTCHA_RSA_KEYFILE`` config setting.
        :param str publickey: A PKCS#1 OAEP-padded, public RSA key, used for
            creating the ``captcha_challenge_field`` string to give to a
            client.
        :param bytes hmacKey: The master HMAC key, used for validating CAPTCHA
            challenge strings in :meth:`captcha.GimpCaptcha.check`. The file
            where this key is stored can be set via the
            ``GIMP_CAPTCHA_HMAC_KEYFILE`` option in the config file.
        :param str captchaDir: The directory where the cached CAPTCHA images
            are stored. See the ``GIMP_CAPTCHA_DIR`` config setting.
        :param bool useForwardedHeader: If ``True``, obtain the client's IP
            address from the ``X-Forwarded-For`` HTTP header.
        :type protectedResource: :api:`twisted.web.resource.Resource`
        :param protectedResource: The resource to serve if the client
            successfully passes the CAPTCHA challenge.
        """
        CaptchaProtectedResource.__init__(self, **kwargs)
        self.hmacKey = hmacKey
        self.captchaDir = captchaDir

    def checkSolution(self, request):
        """Process a solved CAPTCHA via :meth:`bridgedb.captcha.GimpCaptcha.check`.

        :type request: :api:`twisted.web.http.Request`
        :param request: A ``Request`` object, including POST arguments which
            should include two key/value pairs: one key being
            ``'captcha_challenge_field'``, and the other,
            ``'captcha_response_field'``. These POST arguments should be
            obtained from :meth:`render_GET`.
        :rtupe: bool
        :returns: True, if the CAPTCHA solution was valid; False otherwise.
        """
        valid = False
        challenge, solution = self.extractClientSolution(request)
        clientIP = self.getClientIP(request)
        clientHMACKey = crypto.getHMAC(self.hmacKey, clientIP)

        try:
            valid = captcha.GimpCaptcha.check(challenge, solution,
                                              self.secretKey, clientHMACKey)
        except captcha.CaptchaExpired as error:
            logging.warn(error)
            valid = False

        logging.debug("%sorrect captcha from %r: %r."
                      % ("C" if valid else "Inc", clientIP, solution))
        return valid

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
            logging.error(error)
        except Exception as error:  # pragma: no cover
            logging.error("Unhandled error while retrieving Gimp captcha!")
            logging.exception(error)

        return (capt.image, capt.challenge)

    def render_GET(self, request):
        """Get a random CAPTCHA from our local cache directory and serve it to
        the client.

        :type request: :api:`twisted.web.http.Request`
        :param request: A ``Request`` object for a page which should be
            protected by a CAPTCHA.
        :rtype: str
        :returns: A rendered HTML page containing a ReCaptcha challenge image
           for the client to solve.
        """
        return CaptchaProtectedResource.render_GET(self, request)

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
        return CaptchaProtectedResource.render_POST(self, request)


class ReCaptchaProtectedResource(CaptchaProtectedResource):
    """A web resource which uses the reCaptcha_ service.

    .. _reCaptcha: http://www.google.com/recaptcha
    """

    def __init__(self, remoteIP=None, **kwargs):
        CaptchaProtectedResource.__init__(self, **kwargs)
        self.remoteIP = remoteIP

    def _renderDeferred(self, checkedRequest):
        """Render this resource asynchronously.

        :type checkedRequest: tuple
        :param checkedRequest: A tuple of ``(bool, request)``, as returned
            from :meth:`checkSolution`.
        """
        try:
            valid, request = checkedRequest
        except Exception as err:
            logging.error("Error in _renderDeferred(): %s" % err)
            return

        logging.debug("Attemping to render %svalid request %r"
                      % ('' if valid else 'in', request))
        if valid is True:
            try:
                rendered = self.resource.render(request)
            except Exception as err:  # pragma: no cover
                rendered = replaceErrorPage(err)
        else:
            logging.info("Client failed a CAPTCHA; redirecting to %s"
                         % request.uri)
            rendered = redirectTo(request.uri, request)

        try:
            request.write(rendered)
            request.finish()
        except Exception as err:  # pragma: no cover
            logging.exception(err)

        return request

    def getCaptchaImage(self, request):
        """Get a CAPTCHA image from the remote reCaptcha server.

        :type request: :api:`twisted.web.http.Request`
        :param request: A client's initial request for some other resource
            which is protected by this one (i.e. protected by a CAPTCHA).
        :returns: A 2-tuple of ``(image, challenge)``, where::
            - ``image`` is a string holding a binary, JPEG-encoded image.
            - ``challenge`` is a unique string associated with the request.
        """
        capt = captcha.ReCaptcha(self.publicKey, self.secretKey)

        try:
            capt.get()
        except Exception as error:
            logging.fatal("Connection to Recaptcha server failed: %s" % error)

        if capt.image is None:
            logging.warn("No CAPTCHA image received from ReCaptcha server!")

        return (capt.image, capt.challenge)

    def getRemoteIP(self):
        """Mask the client's real IP address with a faked one.

        The fake client IP address is sent to the reCaptcha server, and it is
        either the public IP address of bridges.torproject.org (if the config
        option ``RECAPTCHA_REMOTE_IP`` is configured), or a random IP.

        :rtype: str
        :returns: A fake IP address to report to the reCaptcha API server.
        """
        if self.remoteIP:
            remoteIP = self.remoteIP
        else:
            # generate a random IP for the captcha submission
            remoteIP = IPv4Address(random.randint(0, 2**32-1)).compressed

        return remoteIP

    def checkSolution(self, request):
        """Process a solved CAPTCHA by sending it to the ReCaptcha server.

        The client's IP address is not sent to the ReCaptcha server; instead,
        a completely random IP is generated and sent instead.

        :type request: :api:`twisted.web.http.Request`
        :param request: A ``Request`` object, including POST arguments which
            should include two key/value pairs: one key being
            ``'captcha_challenge_field'``, and the other,
            ``'captcha_response_field'``. These POST arguments should be
            obtained from :meth:`render_GET`.
        :rtupe: :api:`twisted.internet.defer.Deferred`
        :returns: A deferred which will callback with a tuple in the following
            form:
                (:type:`bool`, :api:`twisted.web.server.Request`)
            If the CAPTCHA solution was valid, a tuple will contain::
                (True, Request)
            Otherwise, it will contain::
                (False, Request)
        """
        challenge, response = self.extractClientSolution(request)
        clientIP = self.getClientIP(request)
        remoteIP = self.getRemoteIP()

        logging.debug("Captcha from %r. Parameters: %r"
                      % (clientIP, request.args))

        def checkResponse(solution, request):
            """Check the :class:`txrecaptcha.RecaptchaResponse`.

            :type solution: :class:`txrecaptcha.RecaptchaResponse`.
            :param solution: The client's CAPTCHA solution, after it has been
                submitted to the reCaptcha API server.
            """
            # This valid CAPTCHA result from this function cannot be reliably
            # unittested, because it's callbacked to from the deferred
            # returned by ``txrecaptcha.submit``, the latter of which would
            # require networking (as well as automated CAPTCHA
            # breaking). Hence, the 'no cover' pragma.
            if solution.is_valid:  # pragma: no cover
                logging.info("Valid CAPTCHA solution from %r." % clientIP)
                return (True, request)
            else:
                logging.info("Invalid CAPTCHA solution from %r: %r"
                             % (clientIP, solution.error_code))
                return (False, request)

        d = txrecaptcha.submit(challenge, response, self.secretKey,
                               remoteIP).addCallback(checkResponse, request)
        return d

    def render_GET(self, request):
        """Retrieve a ReCaptcha from the API server and serve it to the client.

        :type request: :api:`twisted.web.http.Request`
        :param request: A ``Request`` object for 'bridges.html'.
        :rtype: str
        :returns: A rendered HTML page containing a ReCaptcha challenge image
            for the client to solve.
        """
        return CaptchaProtectedResource.render_GET(self, request)

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
        :returns: :api:`twisted.web.server.NOT_DONE_YET`, in order to handle
            the ``Deferred`` returned from :meth:`checkSolution`. Eventually,
            when the ``Deferred`` request is done being processed,
            :meth:`_renderDeferred` will handle rendering and displaying the
            HTML to the client.
        """
        d = self.checkSolution(request)
        d.addCallback(self._renderDeferred)
        return server.NOT_DONE_YET


class WebResourceOptions(resource.Resource):
    """A resource with additional options which a client may use to specify the
    which bridge types should be returned by :class:`WebResourceBridges`.
    """

    isLeaf = True

    def __init__(self):
        """Create a new WebResource for the Options page"""
        gettext.install("bridgedb", unicode=True)
        resource.Resource.__init__(self)

    def render_GET(self, request):
        rtl = False
        try:
            langs = translations.getLocaleFromHTTPRequest(request)
            rtl = translations.usingRTLLang(langs)
            template = lookup.get_template('options.html')
            rendered = template.render(strings, rtl=rtl, lang=langs[0])
        except Exception as err:  # pragma: no cover
            rendered = replaceErrorPage(err)
        request.setHeader("Content-Type", "text/html; charset=utf-8")
        return rendered

    render_POST = render_GET


class WebResourceHowto(resource.Resource):
    """A resource which explains how to use bridges."""

    isLeaf = True

    def __init__(self):
        """Create a new WebResource for the Options page"""
        gettext.install("bridgedb", unicode=True)
        resource.Resource.__init__(self)

    def render_GET(self, request):
        rtl = False
        try:
            langs = translations.getLocaleFromHTTPRequest(request)
            rtl = translations.usingRTLLang(langs)
            template = lookup.get_template('howto.html')
            rendered = template.render(strings, rtl=rtl, lang=langs[0])
        except Exception as err:  # pragma: no cover
            rendered = replaceErrorPage(err)
        request.setHeader("Content-Type", "text/html; charset=utf-8")
        return rendered

    render_POST = render_GET


class WebResourceBridges(resource.Resource):
    """This resource displays bridge lines in response to a request."""

    isLeaf = True

    def __init__(self, distributor, schedule, N=1, useForwardedHeader=False,
                 includeFingerprints=True):
        """Create a new resource for displaying bridges to a client.

        :type distributor: :class:`IPBasedDistributor`
        :param distributor: The mechanism to retrieve bridges for this
            distributor.
        :type schedule: :class:`~bridgedb.schedule.ScheduledInterval`
        :param schedule: The time period used to tweak the bridge selection
            procedure.
        :param int N: The number of bridges to hand out per query.
        :param bool useForwardedHeader: Whether or not we should use the the
            X-Forwarded-For header instead of the source IP address.
        :param bool includeFingerprints: Do we include the bridge's
            fingerprint in the response?
        """
        gettext.install("bridgedb", unicode=True)
        resource.Resource.__init__(self)
        self.distributor = distributor
        self.schedule = schedule
        self.nBridgesToGive = N
        self.useForwardedHeader = useForwardedHeader
        self.includeFingerprints = includeFingerprints

    def render(self, request):
        """Render a response for a client HTTP request.

        Presently, this method merely wraps :meth:`getBridgeRequestAnswer` to
        catch any unhandled exceptions which occur (otherwise the server will
        display the traceback to the client). If an unhandled exception *does*
        occur, the client will be served the default "No bridges currently
        available" HTML response page.

        :type request: :api:`twisted.web.http.Request`
        :param request: A ``Request`` object containing the HTTP method, full
            URI, and any URL/POST arguments and headers present.
        :rtype: str
        :returns: A plaintext or HTML response to serve.
        """
        try:
            response = self.getBridgeRequestAnswer(request)
        except Exception as err:
            logging.exception(err)
            response = self.renderAnswer(request)

        return response

    def getBridgeRequestAnswer(self, request):
        """Respond to a client HTTP request for bridges.

        :type request: :api:`twisted.web.http.Request`
        :param request: A ``Request`` object containing the HTTP method, full
            URI, and any URL/POST arguments and headers present.
        :rtype: str
        :returns: A plaintext or HTML response to serve.
        """
        # XXX why are we getting the interval if our distributor might be
        # using bridgedb.schedule.Unscheduled?
        interval = self.schedule.intervalStart(time.time())
        bridges = ( )
        ip = None
        countryCode = None

        # XXX this code is duplicated in CaptchaProtectedResource
        if self.useForwardedHeader:
            h = request.getHeader("X-Forwarded-For")
            if h:
                ip = h.split(",")[-1].strip()
                if not isIPAddress(ip):
                    logging.warn("Got weird forwarded-for value %r",h)
                    ip = None
        else:
            ip = request.getClientIP()

        # Look up the country code of the input IP
        if isIPAddress(ip):
            countryCode = bridgedb.geo.getCountryCode(IPAddress(ip))
        else:
            logging.warn("Invalid IP detected; skipping country lookup.")
            countryCode = None

        # XXX separate function again
        format = request.args.get("format", None)
        if format and len(format): format = format[0] # choose the first arg

        # do want any options?
        transport = ipv6 = unblocked = False

        ipv6 = request.args.get("ipv6", False)
        if ipv6: ipv6 = True # if anything after ?ipv6=

        # XXX oh dear hell. why not check for the '?transport=' arg before
        # regex'ing? And why not compile the regex once, somewhere outside
        # this function and class?
        try:
            # validate method name
            transport = re.match('[_a-zA-Z][_a-zA-Z0-9]*',
                    request.args.get("transport")[0]).group()
        except (TypeError, IndexError, AttributeError):
            transport = None

        try:
            unblocked = re.match('[a-zA-Z]{2,4}',
                    request.args.get("unblocked")[0]).group()
        except (TypeError, IndexError, AttributeError):
            unblocked = False

        logging.info("Replying to web request from %s. Parameters were %r"
                     % (ip, request.args))

        rules = []
        bridgeLines = None

        if ip:
            if ipv6:
                rules.append(filterBridgesByIP6)
                addressClass = IPv6Address
            else:
                rules.append(filterBridgesByIP4)
                addressClass = IPv4Address

            if transport:
                #XXX: A cleaner solution would differentiate between
                # addresses by protocol rather than have separate lists
                # Tor to be a transport, and selecting between them.
                rules = [filterBridgesByTransport(transport, addressClass)]

            if unblocked:
                rules.append(filterBridgesByNotBlockedIn(unblocked,
                    addressClass, transport))

            bridges = self.distributor.getBridgesForIP(ip, interval,
                                                       self.nBridgesToGive,
                                                       countryCode,
                                                       bridgeFilterRules=rules)
            bridgeLines = "".join("%s\n" % b.getConfigLine(
                includeFingerprint=self.includeFingerprints,
                addressClass=addressClass,
                transport=transport,
                request=bridgedb.Dist.uniformMap(ip)
                ) for b in bridges)

        answer = self.renderAnswer(request, bridgeLines, format)
        return answer

    def renderAnswer(self, request, bridgeLines=None, format=None):
        """Generate a response for a client which includes **bridges**.

        The generated response can be plaintext or HTML.

        :type request: :api:`twisted.web.http.Request`
        :param request: A ``Request`` object containing the HTTP method, full
            URI, and any URL/POST arguments and headers present.
        :type bridgeLines: list or None
        :param bridgeLines: A list of strings used to configure a Tor client
            to use a bridge.
        :type format: str or None
        :param format: If ``'plain'``, return a plaintext response. Otherwise,
            use the :file:`bridgedb/templates/bridges.html` template to render
            an HTML response page which includes the **bridges**.
        :rtype: str
        :returns: A plaintext or HTML response to serve.
        """
        rtl = False

        if format == 'plain':
            request.setHeader("Content-Type", "text/plain")
            rendered = bridgeLines
        else:
            request.setHeader("Content-Type", "text/html; charset=utf-8")
            qrcode = None
            qrjpeg = generateQR(bridgeLines)

            if qrjpeg:
                qrcode = 'data:image/jpeg;base64,%s' % base64.b64encode(qrjpeg)
            try:
                langs = translations.getLocaleFromHTTPRequest(request)
                rtl = translations.usingRTLLang(langs)
                template = lookup.get_template('bridges.html')
                rendered = template.render(strings,
                                           rtl=rtl,
                                           lang=langs[0],
                                           answer=bridgeLines,
                                           qrcode=qrcode)
            except Exception as err:
                rendered = replaceErrorPage(err)

        return rendered


class WebRoot(resource.Resource):
    """The parent resource of all other documents hosted by the webserver."""

    isLeaf = True

    def render_GET(self, request):
        """Handles requests for the webserver root document.

        For example, this function handles requests for
        https://bridges.torproject.org/.

        :type request: :api:`twisted.web.server.Request`
        :param request: An incoming request.
        """
        rtl = False
        try:
            langs = translations.getLocaleFromHTTPRequest(request)
            rtl = translations.usingRTLLang(langs)
            template = lookup.get_template('index.html')
            rendered = template.render(strings,
                                       rtl=rtl,
                                       lang=langs[0])
        except Exception as err:
            rendered = replaceErrorPage(err)

        return rendered


def addWebServer(cfg, dist, sched):
    """Set up a web server for HTTP(S)-based bridge distribution.

    :type cfg: :class:`bridgedb.persistent.Conf`
    :param cfg: A configuration object from
         :mod:`bridgedb.Main`. Currently, we use these options::
             HTTP_UNENCRYPTED_PORT
             HTTP_UNENCRYPTED_BIND_IP
             HTTP_USE_IP_FROM_FORWARDED_HEADER
             HTTPS_N_BRIDGES_PER_ANSWER
             HTTPS_INCLUDE_FINGERPRINTS
             HTTPS_KEY_FILE
             HTTPS_CERT_FILE
             HTTPS_PORT
             HTTPS_BIND_IP
             HTTPS_USE_IP_FROM_FORWARDED_HEADER
             RECAPTCHA_ENABLED
             RECAPTCHA_PUB_KEY
             RECAPTCHA_SEC_KEY
             RECAPTCHA_REMOTEIP
             GIMP_CAPTCHA_ENABLED
             GIMP_CAPTCHA_DIR
             GIMP_CAPTCHA_HMAC_KEYFILE
             GIMP_CAPTCHA_RSA_KEYFILE
    :type dist: :class:`bridgedb.Dist.IPBasedDistributor`
    :param dist: A bridge distributor.
    :type sched: :class:`bridgedb.schedule.ScheduledInterval`
    :param sched: The scheduled interval at which bridge selection, which
        are ultimately displayed on the :class:`WebResourceBridges` page, will
        be shifted.
    :raises SystemExit: if the servers cannot be started.
    :rtype: :api:`twisted.web.server.Site`
    :returns: A webserver.
    """
    captcha = None
    fwdHeaders = cfg.HTTP_USE_IP_FROM_FORWARDED_HEADER
    numBridges = cfg.HTTPS_N_BRIDGES_PER_ANSWER
    fprInclude = cfg.HTTPS_INCLUDE_FINGERPRINTS

    logging.info("Starting web servers...")

    httpdist = resource.Resource()
    httpdist.putChild('', WebRoot())
    httpdist.putChild('robots.txt',
                      static.File(os.path.join(TEMPLATE_DIR, 'robots.txt')))
    httpdist.putChild('keys',
                      static.File(os.path.join(TEMPLATE_DIR, 'bridgedb.asc')))
    httpdist.putChild('assets',
                      static.File(os.path.join(TEMPLATE_DIR, 'assets/')))
    httpdist.putChild('options', WebResourceOptions())
    httpdist.putChild('howto', WebResourceHowto())

    if cfg.RECAPTCHA_ENABLED:
        publicKey = cfg.RECAPTCHA_PUB_KEY
        secretKey = cfg.RECAPTCHA_SEC_KEY
        captcha = partial(ReCaptchaProtectedResource,
                          remoteIP=cfg.RECAPTCHA_REMOTEIP)
    elif cfg.GIMP_CAPTCHA_ENABLED:
        # Get the master HMAC secret key for CAPTCHA challenges, and then
        # create a new HMAC key from it for use on the server.
        captchaKey = crypto.getKey(cfg.GIMP_CAPTCHA_HMAC_KEYFILE)
        hmacKey = crypto.getHMAC(captchaKey, "Captcha-Key")
        # Load or create our encryption keys:
        secretKey, publicKey = crypto.getRSAKey(cfg.GIMP_CAPTCHA_RSA_KEYFILE)
        captcha = partial(GimpCaptchaProtectedResource,
                          hmacKey=hmacKey,
                          captchaDir=cfg.GIMP_CAPTCHA_DIR)

    bridges = WebResourceBridges(dist, sched, numBridges,
                                 fwdHeaders, includeFingerprints=fprInclude)
    if captcha:
        # Protect the 'bridges' page with a CAPTCHA, if configured to do so:
        protected = captcha(publicKey=publicKey,
                            secretKey=secretKey,
                            useForwardedHeader=fwdHeaders,
                            protectedResource=bridges)
        httpdist.putChild('bridges', protected)
        logging.info("Protecting resources with %s." % captcha.func.__name__)
    else:
        httpdist.putChild('bridges', bridges)

    site = server.Site(httpdist)
    site.displayTracebacks = False

    if cfg.HTTP_UNENCRYPTED_PORT:
        ip = cfg.HTTP_UNENCRYPTED_BIND_IP or ""
        port = cfg.HTTP_UNENCRYPTED_PORT or 80
        try:
            reactor.listenTCP(port, site, interface=ip)
        except CannotListenError as error:
            raise SystemExit(error)
        logging.info("Started HTTP server on %s:%d" % (str(ip), int(port)))

    if cfg.HTTPS_PORT:
        ip = cfg.HTTPS_BIND_IP or ""
        port = cfg.HTTPS_PORT or 443
        try:
            from twisted.internet.ssl import DefaultOpenSSLContextFactory
            factory = DefaultOpenSSLContextFactory(cfg.HTTPS_KEY_FILE,
                                                   cfg.HTTPS_CERT_FILE)
            reactor.listenSSL(port, site, factory, interface=ip)
        except CannotListenError as error:
            raise SystemExit(error)
        logging.info("Started HTTPS server on %s:%d" % (str(ip), int(port)))

    return site

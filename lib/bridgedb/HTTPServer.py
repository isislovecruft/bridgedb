# BridgeDB by Nick Mathewson.
# Copyright (c) 2007-2013, The Tor Project, Inc.
# See LICENSE for licensing information

"""
This module implements the web (http, https) interfaces to the bridge database.
"""

import base64
import gettext
import logging
import re
import textwrap
import time
import os

from twisted.internet import reactor
from twisted.internet.error import CannotListenError
from twisted.python import filepath
from twisted.web import resource
from twisted.web import server
from twisted.web import static
from twisted.web.util import redirectTo

import bridgedb.Dist
import bridgedb.I18n as I18n
import bridgedb.Util as Util

from bridgedb import captcha
from bridgedb import crypto
from bridgedb import txrecaptcha
from bridgedb.Filters import filterBridgesByIP4
from bridgedb.Filters import filterBridgesByIP6
from bridgedb.Filters import filterBridgesByTransport
from bridgedb.Filters import filterBridgesByNotBlockedIn
from bridgedb.parse import headers

from ipaddr import IPv4Address, IPv6Address
from random import randint
import mako.exceptions
from mako.template import Template
from mako.lookup import TemplateLookup


template_root = os.path.join(os.path.dirname(__file__),'templates')
logging.debug("Set template root to %s" % template_root)

rtl_langs = ('ar', 'he', 'fa', 'gu_IN', 'ku')

# Setting `filesystem_checks` to False is recommended for production servers,
# due to potential speed increases. This means that the atimes of the Mako
# template files aren't rechecked every time the template is requested
# (otherwise, if they are checked, and the atime is newer, the template is
# recompiled). `collection_size` sets the number of compiled templates which
# are cached before the least recently used ones are removed. See:
# http://docs.makotemplates.org/en/latest/usage.html#using-templatelookup
lookup = TemplateLookup(directories=[template_root],
                        output_encoding='utf-8',
                        filesystem_checks=False,
                        collection_size=500)


_geoipdb = '/usr/share/GeoIP/GeoIP.dat'

try:
    # Make sure we have the database before trying to import the module:
    if not os.path.isfile(_geoipdb):
        raise EnvironmentError("Could not find %r. On Debian-based systems, "\
                               "please install the geoip-database package."
                               % _geoipdb)
    # This is a "pure" python version which interacts with the Maxmind GeoIP
    # API (version 1). It requires, in Debian, the libgeoip-dev and
    # geoip-database packages.
    import pygeoip
    geoip = pygeoip.GeoIP(_geoipdb, flags=pygeoip.MEMORY_CACHE)
    logging.info("GeoIP database loaded")
except Exception as err:
    logging.warn("Error while loading geoip module: %r" % err)
    geoip = None


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

    def __init__(self, useForwardedHeader=False, protectedResource=None):
        resource.Resource.__init__(self)
        self.useForwardedHeader = useForwardedHeader
        self.resource = protectedResource

    def getClientIP(self, request):
        ip = None
        if self.useForwardedHeader:
            h = request.getHeader("X-Forwarded-For")
            if h:
                ip = h.split(",")[-1].strip()
                if not bridgedb.Bridges.is_valid_ip(ip):
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
        except:
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
        image, challenge = self.getCaptchaImage(request)

        try:
            # TODO: this does not work for versions of IE < 8.0
            imgstr = 'data:image/jpeg;base64,%s' % base64.b64encode(image)
            template = lookup.get_template('captcha.html')
            rendered = template.render(imgstr=imgstr,
                                       challenge_field=challenge)
        except Exception as err:
            rendered = replaceErrorPage(err, 'captcha.html')

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

    def __init__(self, secretKey=None, publicKey=None, hmacKey=None,
                 captchaDir='', useForwardedHeader=False,
                 protectedResource=None):
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
        CaptchaProtectedResource.__init__(self, useForwardedHeader,
                                          protectedResource)
        self.secretKey = secretKey
        self.publicKey = publicKey
        self.hmacKey = hmacKey
        self.captchaDir = captchaDir

    def checkSolution(self, request):
        """Process a solved CAPTCHA by sending rehashing the solution together with
        the client's IP address, and checking that the result matches the challenge.

        The client's IP address is not sent to the ReCaptcha server; instead,
        a completely random IP is generated and sent instead.

        :type request: :api:`twisted.web.http.Request`
        :param request: A ``Request`` object, including POST arguments which
            should include two key/value pairs: one key being
            ``'captcha_challenge_field'``, and the other,
            ``'captcha_response_field'``. These POST arguments should be
            obtained from :meth:`render_GET`.
        :rtupe: bool
        :returns: True, if the CAPTCHA solution was valid; False otherwise.
        """
        challenge, solution = self.extractClientSolution(request)
        clientIP = self.getClientIP(request)
        clientHMACKey = crypto.getHMAC(self.hmacKey, clientIP)
        valid = captcha.GimpCaptcha.check(challenge, solution,
                                          self.secretKey, clientHMACKey)
        logging.debug("%sorrect captcha from %r: %r." % (
            "C" if valid else "Inc", Util.logSafely(clientIP), solution))

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
        capt = captcha.GimpCaptcha(self.secretKey, self.publicKey,
                                   clientHMACKey, self.captchaDir)
        try:
            capt.get()
        except captcha.GimpCaptchaError as error:
            logging.error(error)
        except Exception as error:
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

    def __init__(self, recaptchaPrivKey='', recaptchaPubKey='', remoteip='',
                 useForwardedHeader=False, protectedResource=None):
        CaptchaProtectedResource.__init__(self, useForwardedHeader,
                                          protectedResource)
        self.recaptchaPrivKey = recaptchaPrivKey
        self.recaptchaPubKey = recaptchaPubKey
        self.recaptchaRemoteIP = remoteip

    def getCaptchaImage(self, request):
        """Get a CAPTCHA image from the remote reCaptcha server.

        :type request: :api:`twisted.web.http.Request`
        :param request: A client's initial request for some other resource
            which is protected by this one (i.e. protected by a CAPTCHA).
        :returns: A 2-tuple of ``(image, challenge)``, where::
            - ``image`` is a string holding a binary, JPEG-encoded image.
            - ``challenge`` is a unique string associated with the request.
        """
        capt = captcha.ReCaptcha(self.recaptchaPubKey, self.recaptchaPrivKey)

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
        either the public IP address of bridges.torproject.org (if
        ``RECAPTCHA_REMOTE_IP`` is configured), or a random IP.

        :rtype: str
        :returns: A fake IP address to report to the reCaptcha API server.
        """
        if self.recaptchaRemoteIP:
            remoteIP = self.recaptchaRemoteIP
        else:
            # generate a random IP for the captcha submission
            remoteIP = '%d.%d.%d.%d' % (randint(1,255),randint(1,255),
                                        randint(1,255),randint(1,255))
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
        :rtupe: bool
        :returns: True, if the CAPTCHA solution was valid; False otherwise.
        """
        challenge, response = self.extractClientSolution(request)
        clientIP = self.getClientIP(request)
        remoteIP = self.getRemoteIP()

        logging.debug("Captcha from %r. Parameters: %r"
                      % (Util.logSafely(clientIP), request.args))

        def checkResponse(solution, clientIP):
            if solution.is_valid:
                logging.info("Valid CAPTCHA solution from %r."
                             % Util.logSafely(clientIP))
                return True
            else:
                logging.info("Invalid CAPTCHA solution from %r: %r"
                             % (Util.logSafely(clientIP), solution.error_code))
                return False

        d = txrecaptcha.submit(challenge, response, self.recaptchaPrivKey,
                               remoteIP).addCallback(checkResponse, clientIP)
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
        :rtype: str
        :returns: A rendered HTML page containing a ReCaptcha challenge image
                  for the client to solve.
        """
        return CaptchaProtectedResource.render_POST(self, request)


class WebResourceOptions(resource.Resource):
    """This resource is used by Twisted Web to give a web page with
       additional options that the user may use to specify the criteria
       the returned bridges should meet.
    """
    isLeaf = True

    def __init__(self):
        """Create a new WebResource for the Options page"""
        gettext.install("bridgedb", unicode=True)
        resource.Resource.__init__(self)

    def render_GET(self, request):
        rtl = False

        try:
            rtl = usingRTLLang(request)
        except Exception as err:
            logging.exception(err)
            logging.error("The gettext files were not properly installed.")
            logging.info("To install translations, try doing `python " \
                         "setup.py compile_catalog`.")

        request.setHeader("Content-Type", "text/html; charset=utf-8")
        return lookup.get_template('options.html').render(rtl=rtl)

    render_POST = render_GET


class WebResourceBridges(resource.Resource):
    """This resource is used by Twisted Web to give a web page with some
       bridges in response to a request."""

    isLeaf = True

    def __init__(self, distributor, schedule, N=1, useForwardedHeader=False,
                 includeFingerprints=True):
        """Create a new resource for displaying bridges to a client.

        :type distributor: :class:`IPBasedDistributor`
        :param distributor: The mechanism to retrieve bridges for this
            distributor.
        :type schedule: :class:`IntervalSchedule`
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
        # using bridgedb.Time.NoSchedule?
        interval = self.schedule.getInterval(time.time())
        bridges = ( )
        ip = None
        countryCode = None

        # XXX this code is duplicated in CaptchaProtectedResource
        if self.useForwardedHeader:
            h = request.getHeader("X-Forwarded-For")
            if h:
                ip = h.split(",")[-1].strip()
                if not bridgedb.Bridges.is_valid_ip(ip):
                    logging.warn("Got weird forwarded-for value %r",h)
                    ip = None
        else:
            ip = request.getClientIP()

        # XXX This can also be a separate function
        # XXX if the ip is None, this throws an exception
        if geoip:
            countryCode = geoip.country_code_by_addr(ip)
            if countryCode:
                logging.debug("Client request from GeoIP CC: %s" % countryCode)

        rtl = usingRTLLang(request)
        if rtl:
            logging.debug("Rendering RTL response.")

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
                     % (Util.logSafely(ip), request.args))

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
            bridgeLines = "".join("  %s\n" % b.getConfigLine(
                includeFingerprint=self.includeFingerprints,
                addressClass=addressClass,
                transport=transport,
                request=bridgedb.Dist.uniformMap(ip)
                ) for b in bridges)

        answer = self.renderAnswer(request, bridgeLines, rtl, format)
        return answer

    def renderAnswer(self, request, bridgeLines=None, rtl=False, format=None):
        """Generate a response for a client which includes **bridges**.

        The generated response can be plaintext or HTML.

        :type request: :api:`twisted.web.http.Request`
        :param request: A ``Request`` object containing the HTTP method, full
            URI, and any URL/POST arguments and headers present.
        :type bridgeLines: list or None
        :param bridgeLines: A list of strings used to configure a Tor client
            to use a bridge.
        :param bool rtl: If ``True``, the language used for the response to
            the client should be rendered right-to-left.
        :type format: str or None
        :param format: If ``'plain'``, return a plaintext response. Otherwise,
            use the :file:`bridgedb/templates/bridges.html` template to render
            an HTML response page which includes the **bridges**.
        :rtype: str
        :returns: A plaintext or HTML response to serve.
        """
        if format == 'plain':
            request.setHeader("Content-Type", "text/plain")
            rendered = bridgeLines
        else:
            request.setHeader("Content-Type", "text/html; charset=utf-8")
            try:
                # XXX FIXME the returned page from
                # ``WebResourceBridgesTests.test_render_GET_RTLlang``
                # is in Arabic and has `<html lang="en">`! Doh.
                template = lookup.get_template('bridges.html')
                rendered = template.render(answer=bridgeLines, rtl=rtl)
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
            rtl = usingRTLLang(request)
        except Exception as err:
            logging.exception(err)
            logging.error("The gettext files were not properly installed.")
            logging.info("To install translations, try doing `python " \
                         "setup.py compile_catalog`.")

        return lookup.get_template('index.html').render(rtl=rtl)


def addWebServer(cfg, dist, sched):
    """Set up a web server.

    :param cfg: A configuration object from :mod:`bridgedb.Main`. Currently,
         we use these options::
             HTTPS_N_BRIDGES_PER_ANSWER
             HTTP_UNENCRYPTED_PORT
             HTTP_UNENCRYPTED_BIND_IP
             HTTP_USE_IP_FROM_FORWARDED_HEADER
             HTTPS_PORT
             HTTPS_BIND_IP
             HTTPS_USE_IP_FROM_FORWARDED_HEADER
             RECAPTCHA_ENABLED
             RECAPTCHA_PUB_KEY
             RECAPTCHA_PRIV_KEY
             RECAPTCHA_REMOTEIP
             GIMP_CAPTCHA_ENABLED
             GIMP_CAPTCHA_DIR
    :type dist: :class:`bridgedb.Dist.IPBasedDistributor`
    :param dist: A bridge distributor.
    :type sched: :class:`bridgedb.Time.IntervalSchedule`
    :param sched: DOCDOC
    """
    httpdist = resource.Resource()
    httpdist.putChild('', WebRoot())
    httpdist.putChild('robots.txt',
                      static.File(os.path.join(template_root, 'robots.txt')))
    httpdist.putChild('assets',
                      static.File(os.path.join(template_root, 'assets/')))
    httpdist.putChild('options', WebResourceOptions())

    bridgesResource = WebResourceBridges(
        dist, sched, cfg.HTTPS_N_BRIDGES_PER_ANSWER,
        cfg.HTTP_USE_IP_FROM_FORWARDED_HEADER,
        includeFingerprints=cfg.HTTPS_INCLUDE_FINGERPRINTS)

    if cfg.RECAPTCHA_ENABLED:
        protected = ReCaptchaProtectedResource(
                recaptchaPrivKey=cfg.RECAPTCHA_PRIV_KEY,
                recaptchaPubKey=cfg.RECAPTCHA_PUB_KEY,
                remoteip=cfg.RECAPTCHA_REMOTEIP,
                useForwardedHeader=cfg.HTTP_USE_IP_FROM_FORWARDED_HEADER,
                protectedResource=bridgesResource)
        httpdist.putChild('bridges', protected)

    elif cfg.GIMP_CAPTCHA_ENABLED:
        # Get the HMAC secret key for CAPTCHA challenges and create a new key
        # from it for use on the server:
        captchaKey = crypto.getKey(cfg.GIMP_CAPTCHA_HMAC_KEYFILE)
        hmacKey = crypto.getHMAC(captchaKey, "Captcha-Key")

        # Load or create our encryption keys:
        secretKey, publicKey = crypto.getRSAKey(cfg.GIMP_CAPTCHA_RSA_KEYFILE)

        protected = GimpCaptchaProtectedResource(
            secretKey=secretKey,
            publicKey=publicKey,
            hmacKey=hmacKey,
            captchaDir=cfg.GIMP_CAPTCHA_DIR,
            useForwardedHeader=cfg.HTTP_USE_IP_FROM_FORWARDED_HEADER,
            protectedResource=bridgesResource)
        httpdist.putChild('bridges', protected)
    else:
        httpdist.putChild('bridges', bridgesResource)

    site = server.Site(httpdist)

    if cfg.HTTP_UNENCRYPTED_PORT:
        ip = cfg.HTTP_UNENCRYPTED_BIND_IP or ""
        try:
            reactor.listenTCP(cfg.HTTP_UNENCRYPTED_PORT, site, interface=ip)
        except CannotListenError as error:
            raise SystemExit(error)

    if cfg.HTTPS_PORT:
        from twisted.internet.ssl import DefaultOpenSSLContextFactory
        #from OpenSSL.SSL import SSLv3_METHOD
        ip = cfg.HTTPS_BIND_IP or ""
        factory = DefaultOpenSSLContextFactory(cfg.HTTPS_KEY_FILE,
                                               cfg.HTTPS_CERT_FILE)
        try:
            reactor.listenSSL(cfg.HTTPS_PORT, site, factory, interface=ip)
        except CannotListenError as error:
            raise SystemExit(error)

    return site

def usingRTLLang(request):
    """Check if we should translate the text into a RTL language

    Retrieve the headers from the request. Obtain the Accept-Language header
    and decide if we need to translate the text. Install the requisite
    languages via gettext, if so. Then, manually check which languages we
    support. Choose the first language from the header that we support and
    return True if it is a RTL language, else return False.

    :type request: :api:`twisted.web.server.Request`
    :param request: An incoming request.
    :rtype: bool
    :returns: ``True`` if the preferred language is right-to-left; ``False``
              otherwise.
    """
    langs = setLocaleFromRequestHeader(request)

    # Grab only the language (first two characters) so we know if the language
    # is read right-to-left
    #langs = [ lang[:2] for lang in langs ]
    lang = getAssumedChosenLang(langs)
    if lang in rtl_langs:
        return True
    return False

def getAssumedChosenLang(langs):
    """Return the first language in **langs** that we support.

    :param list langs: All requested languages
    :rtype: str
    :returns: A country code for the client's preferred language.
    """
    i18npath = os.path.join(os.path.dirname(__file__), 'i18n')
    path = filepath.FilePath(i18npath)
    assert path.isdir()

    lang = 'en-US'
    supp_langs = path.listdir() + ['en']
    for l in langs:
        if l in supp_langs:
            lang = l
            break
    return lang

def setLocaleFromRequestHeader(request):
    """Retrieve the languages from the accept-language header and install them.

    Parse the languages in the header, and attempt to install the first one in
    the list. If that fails, we receive a :class:`gettext.NullTranslation`
    object, if it worked then we have a :class:`gettext.GNUTranslation`
    object. Whichever one we end up with, get the other languages and add them
    as fallbacks to the first. Lastly, install this chain of translations.

    :type request: :api:`twisted.web.server.Request`
    :param request: An incoming request from a client.
    :rtype: list
    :returns: All requested languages.
    """
    logging.debug("Getting client 'Accept-Language' header...")
    header = request.getHeader('accept-language')

    if header is None:
        logging.debug("Client sent no 'Accept-Language' header. Using fallback.")
        header = 'en,en-US'

    localedir = os.path.join(os.path.dirname(__file__), 'i18n/')
    langs = headers.parseAcceptLanguage(header)
    ## XXX the 'Accept-Language' header is potentially identifying
    logging.debug("Client Accept-Language (top 5): %s" % langs[:5])

    try:
        language = gettext.translation("bridgedb", localedir=localedir,
                                       languages=langs, fallback=True)
        for lang in langs:
            language.add_fallback(gettext.translation("bridgedb",
                                                      localedir=localedir,
                                                      languages=langs,
                                                      fallback=True))
    except IOError as error:
        logging.error(error.message)

    language.install(unicode=True)
    return langs

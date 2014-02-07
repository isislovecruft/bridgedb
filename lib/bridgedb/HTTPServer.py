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
import twisted.web.resource
from twisted.web.server import Site
from twisted.web import static
from twisted.web.util import redirectTo
from twisted.python import filepath

import bridgedb.Dist
import bridgedb.I18n as I18n
import bridgedb.Util as Util

from recaptcha.client import captcha
from bridgedb.Raptcha import Raptcha
from bridgedb.Filters import filterBridgesByIP6, filterBridgesByIP4
from bridgedb.Filters import filterBridgesByTransport
from bridgedb.Filters import filterBridgesByNotBlockedIn
from bridgedb.parse import headers
from ipaddr import IPv4Address, IPv6Address
from random import randint
import mako.exceptions
from mako.template import Template
from mako.lookup import TemplateLookup
from zope.interface import Interface, Attribute, implements

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


try:
    # Make sure we have the database before trying to import the module:
    geoipdb = '/usr/share/GeoIP/GeoIP.dat'
    if not os.path.isfile(geoipdb):
        raise EnvironmentError("Could not find %r. On Debian-based systems, "\
                               "please install the geoip-database package."
                               % geoipdb)
    # This is a "pure" python version which interacts with the Maxmind GeoIP
    # API (version 1). It require, in Debian, the libgeoip-dev and
    # geoip-database packages.
    import pygeoip
    geoip = pygeoip.GeoIP(geoipdb, flags=pygeoip.MEMORY_CACHE)

except Exception as err:
    logging.debug("Error while loading geoip module: %r" % err)
    logging.warn("GeoIP database not found")
    geoip = None
else:
    logging.info("GeoIP database loaded")


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


class CaptchaProtectedResource(twisted.web.resource.Resource):
    def __init__(self, useRecaptcha=False, recaptchaPrivKey='',
            recaptchaPubKey='', useForwardedHeader=False, resource=None):
        self.isLeaf = resource.isLeaf
        self.useForwardedHeader = useForwardedHeader
        self.recaptchaPrivKey = recaptchaPrivKey
        self.recaptchaPubKey = recaptchaPubKey
        self.resource = resource

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

    def render_GET(self, request):
        """Retrieve a ReCaptcha from the API server and serve it to the client.

        :type request: :api:`twisted.web.http.Request`
        :param request: A ``Request`` object for 'bridges.html'.
        :rtype: str
        :returns: A rendered HTML page containing a ReCaptcha challenge image
                  for the client to solve.
        """
        c = Raptcha(self.recaptchaPubKey, self.recaptchaPrivKey)

        try:
            c.get()
        except Exception as error:
            logging.fatal("Connection to Recaptcha server failed: %s" % error)

        if c.image is None:
            logging.warn("No CAPTCHA image received from ReCaptcha server!")

        try:
            # TODO: this does not work for versions of IE < 8.0
            imgstr = 'data:image/jpeg;base64,%s' % base64.b64encode(c.image)
            template = lookup.get_template('captcha.html')
            rendered = template.render(imgstr=imgstr,
                                       challenge_field=c.challenge)
        except Exception as err:
            rendered = replaceErrorPage(err, 'captcha.html')

        return rendered

    def render_POST(self, request):
        """Process a client CAPTCHA by sending it to the ReCaptcha server.

        The client's IP address is not sent to the ReCaptcha server; instead,
        a completely random IP is generated and sent instead.

        :type request: :api:`twisted.web.http.Request`
        :param request: A ``Request`` object containing the POST arguments
                        should include two key/value pairs: one key being
                        ``'recaptcha_challange_field'``, and the other,
                        ``'recaptcha_response_field'``. These POST arguments
                        should be obtained from :meth:`render_GET`.
        """
        try:
            challenge = request.args['recaptcha_challenge_field'][0]
            response = request.args['recaptcha_response_field'][0]
        except:
            return redirectTo(request.URLPath(), request)

        # generate a random IP for the captcha submission
        remote_ip = '%d.%d.%d.%d' % (randint(1,255),randint(1,255),
                                     randint(1,255),randint(1,255))

        recaptcha_response = captcha.submit(challenge, response,
                                            self.recaptchaPrivKey, remote_ip)
        logging.debug("Captcha from client with masked IP %r. Parameters:\n%r"
                      % (remote_ip, request.args))

        if recaptcha_response.is_valid:
            logging.info("Valid recaptcha from client with masked IP %r."
                         % remote_ip)
            try:
                rendered = self.resource.render(request)
            except Exception as err:
                rendered = replaceErrorPage(err)
            return rendered
        else:
            logging.info("Invalid recaptcha from client with masked IP %r: %r"
                         % (remote_ip, recaptcha_response.error_code))

        logging.debug("Client failed a recaptcha; returning redirect to %s"
                      % request.uri)
        return redirectTo(request.uri, request)


class WebResourceOptions(twisted.web.resource.Resource):
    """This resource is used by Twisted Web to give a web page with
       additional options that the user may use to specify the criteria
       the returned bridges should meet.
    """
    isLeaf = True

    def __init__(self):
        """Create a new WebResource for the Options page"""
        gettext.install("bridgedb", unicode=True)
        twisted.web.resource.Resource.__init__(self)

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

class WebResourceBridges(twisted.web.resource.Resource):
    """This resource is used by Twisted Web to give a web page with some
       bridges in response to a request."""
    isLeaf = True

    def __init__(self, distributor, schedule, N=1, useForwardedHeader=False,
                 includeFingerprints=True, domains=None):
        """Create a new WebResource.
             distributor -- an IPBasedDistributor object
             schedule -- an IntervalSchedule object
             N -- the number of bridges to hand out per query.
        """
        gettext.install("bridgedb", unicode=True)
        twisted.web.resource.Resource.__init__(self)
        self.distributor = distributor
        self.schedule = schedule
        self.nBridgesToGive = N
        self.useForwardedHeader = useForwardedHeader
        self.includeFingerprints = includeFingerprints

        # do not use mutable types as __init__ defaults!
        if not domains: domains = []
        self.domains = domains

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
        interval = self.schedule.getInterval(time.time())
        bridges = ( )
        ip = None
        countryCode = None
        if self.useForwardedHeader:
            h = request.getHeader("X-Forwarded-For")
            if h:
                ip = h.split(",")[-1].strip()
                if not bridgedb.Bridges.is_valid_ip(ip):
                    logging.warn("Got weird forwarded-for value %r",h)
                    ip = None
        else:
            ip = request.getClientIP()

        if geoip:
            countryCode = geoip.country_code_by_addr(ip)
            if countryCode:
                logging.debug("Client request from GeoIP CC: %s" % countryCode)

        rtl = usingRTLLang(request)
        if rtl:
            logging.debug("Rendering RTL response.")

        format = request.args.get("format", None)
        if format and len(format): format = format[0] # choose the first arg

        # do want any options?
        transport = ipv6 = unblocked = False

        ipv6 = request.args.get("ipv6", False)
        if ipv6: ipv6 = True # if anything after ?ipv6=

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
                       use the :file:`bridgedb/templates/bridges.html`
                       template to render an HTML response page which includes
                       the **bridges**.
        :rtype: str
        :returns: A plaintext or HTML response to serve.
        """
        if format == 'plain':
            request.setHeader("Content-Type", "text/plain")
            rendered = bridgeLines
        else:
            request.setHeader("Content-Type", "text/html; charset=utf-8")
            try:
                template = lookup.get_template('bridges.html')
                rendered = template.render(answer=bridgeLines, rtl=rtl)
            except Exception as err:
                rendered = replaceErrorPage(err)

        return rendered


class WebRoot(twisted.web.resource.Resource):
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
         cfg -- a configuration object from Main.  We use these options:
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
         dist -- an IPBasedDistributor object.
         sched -- an IntervalSchedule object.
    """
    site = None
    httpdist = twisted.web.resource.Resource()
    httpdist.putChild('', WebRoot())
    httpdist.putChild('robots.txt',
                      static.File(os.path.join(template_root, 'robots.txt')))
    httpdist.putChild('assets',
                      static.File(os.path.join(template_root, 'assets/')))

    resource = WebResourceBridges(dist, sched, cfg.HTTPS_N_BRIDGES_PER_ANSWER,
                   cfg.HTTP_USE_IP_FROM_FORWARDED_HEADER,
                   includeFingerprints=cfg.HTTPS_INCLUDE_FINGERPRINTS,
                   domains=cfg.EMAIL_DOMAINS)

    resource_options = WebResourceOptions()

    httpdist.putChild('options', resource_options)
    if cfg.RECAPTCHA_ENABLED:
        protected = CaptchaProtectedResource(
                recaptchaPrivKey=cfg.RECAPTCHA_PRIV_KEY,
                recaptchaPubKey=cfg.RECAPTCHA_PUB_KEY,
                useForwardedHeader=cfg.HTTP_USE_IP_FROM_FORWARDED_HEADER,
                resource=resource)
        httpdist.putChild('bridges', protected)
    else:
        httpdist.putChild('bridges', resource)

    site = Site(httpdist)

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

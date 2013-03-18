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

from twisted.internet import reactor
import twisted.web.resource
import twisted.web.server

import bridgedb.Dist
import bridgedb.I18n as I18n

from recaptcha.client import captcha 
from bridgedb.Raptcha import Raptcha
from bridgedb.Filters import filterBridgesByIP6, filterBridgesByIP4
from bridgedb.Filters import filterBridgesByTransport
from bridgedb.Filters import filterBridgesByNotBlockedIn
from ipaddr import IPv4Address, IPv6Address
from random import randint

try:
    import GeoIP
    # GeoIP data object: choose database here
    # This is the same geoip implementation that pytorctl uses
    geoip = GeoIP.new(GeoIP.GEOIP_STANDARD)
    logging.info("GeoIP database loaded")
except:
    geoip = None
    logging.warn("GeoIP database not found") 

class WebResource(twisted.web.resource.Resource):
    """This resource is used by Twisted Web to give a web page with some
       bridges in response to a request."""
    isLeaf = True

    def __init__(self, distributor, schedule, N=1, useForwardedHeader=False,
                 includeFingerprints=True,
                 useRecaptcha=False,recaptchaPrivKey='', recaptchaPubKey='',
                 domains=None): 
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

        # recaptcha options
        self.useRecaptcha = useRecaptcha
        self.recaptchaPrivKey = recaptchaPrivKey
        self.recaptchaPubKey = recaptchaPubKey

    def render_GET(self, request):
        if self.useRecaptcha:
            # get a captcha
            c = Raptcha(self.recaptchaPubKey, self.recaptchaPrivKey)
            c.get()

            # TODO: this does not work for versions of IE < 8.0
            imgstr = 'data:image/jpeg;base64,%s' % base64.b64encode(c.image)
            HTML_CAPTCHA_TEMPLATE = self.buildHTMLMessageTemplateWithCaptcha(
                    getLocaleFromRequest(request), c.challenge, imgstr)
            return HTML_CAPTCHA_TEMPLATE
        else:
            return self.getBridgeRequestAnswer(request)


    def render_POST(self, request):

        # check captcha if recaptcha support is enabled
        if self.useRecaptcha:
            try:
                challenge = request.args['recaptcha_challenge_field'][0]
                response = request.args['recaptcha_response_field'][0]

            except:
                return self.render_GET(request)

            # generate a random IP for the captcha submission
            remote_ip = '%d.%d.%d.%d' % (randint(1,255),randint(1,255),
                                         randint(1,255),randint(1,255))

            recaptcha_response = captcha.submit(challenge, response,
                                            self.recaptchaPrivKey, remote_ip)
            if recaptcha_response.is_valid:
                logging.info("Valid recaptcha from %s. Parameters were %r",
                        remote_ip, request.args)
            else:
                logging.info("Invalid recaptcha from %s. Parameters were %r",
                             remote_ip, request.args)
                logging.info("Recaptcha error code: %s", recaptcha_response.error_code)
                return self.render_GET(request) # redirect back to captcha

        return self.getBridgeRequestAnswer(request)

    def getBridgeRequestAnswer(self, request):
        """ returns a response to a bridge request """
 
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

        # get locale
        t = getLocaleFromRequest(request) 

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

        rules = []

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

        if bridges:
            answer = "".join("  %s\n" % b.getConfigLine(
                includeFingerprint=self.includeFingerprints,
                addressClass=addressClass,
                transport=transport,
                request=bridgedb.Dist.uniformMap(ip)
                ) for b in bridges) 
        else:
            answer = t.gettext(I18n.BRIDGEDB_TEXT[7])

        logging.info("Replying to web request from %s.  Parameters were %r", ip,
                     request.args)
        if format == 'plain':
            request.setHeader("Content-Type", "text/plain")
            return answer
        else:
            HTML_MESSAGE_TEMPLATE = self.buildHTMLMessageTemplate(t)
            return HTML_MESSAGE_TEMPLATE % answer

    def buildHTMLMessageTemplate(self, t):
        """DOCDOC"""
        if self.domains:
            email_domain_list = "<ul>" \
                + "".join(("<li>%s</li>"%d for d in self.domains)) + "</ul>"
        else:
            email_domain_list = "<p>" + t.gettext(I18n.BRIDGEDB_TEXT[8]) + "</p>"
        html_msg = "<html><head>"\
                   + "<meta http-equiv=\"Content-Type\" content=\"text/html;"\
                   + " charset=UTF-8\"/>" \
                   + "</head><body>" \
                   + "<p>" + t.gettext(I18n.BRIDGEDB_TEXT[0]) \
                   + "<pre id=\"bridges\">" \
                   + "%s" \
                   + "</pre></p>" \
                   + "<p>" + t.gettext(I18n.BRIDGEDB_TEXT[1]) + "</p>" \
                   + "<p>" + t.gettext(I18n.BRIDGEDB_TEXT[2]) + "</p>" \
                   + "<p>" + t.gettext(I18n.BRIDGEDB_TEXT[3]) + "</p>" \
                   + "<p>" + t.gettext(I18n.BRIDGEDB_TEXT[4]) + "</p>" \
                   + email_domain_list \
                   + "<hr /><p><a href='?ipv6=true'>" \
                   + t.gettext(I18n.BRIDGEDB_TEXT[20]) + "</a></p>" \
                   + "<p><a href='?transport=obfs2'>" \
                   + t.gettext(I18n.BRIDGEDB_TEXT[21]) + "</a></p>" \
                   + "<form method='GET'>" \
                   + "<p>" + t.gettext(I18n.BRIDGEDB_TEXT[22]) + "</p>" \
                   + "<input name='transport'>" \
                   + "<input type='submit' value='" \
                   + t.gettext(I18n.BRIDGEDB_TEXT[23]) +"'>" \
                   + "</form>" \
                   + "</body></html>"
        return html_msg

    def buildHTMLMessageTemplateWithCaptcha(self, t, challenge, img):
        """Builds a translated html response with recaptcha"""
        if self.domains:
            email_domain_list = "<ul>" \
                + "".join(("<li>%s</li>"%d for d in self.domains)) + "</ul>"
        else:
            email_domain_list = "<p>" + t.gettext(I18n.BRIDGEDB_TEXT[8]) + "</p>" 

        recaptchaTemplate = textwrap.dedent("""\
            <form action="" method="POST">
              <input type="hidden" name="recaptcha_challenge_field"
                id="recaptcha_challenge_field"\
                        value="{recaptchaChallengeField}">
              <img width="300" height="57" alt="{bridgeDBText14}"\
                      src="{recaptchaImgSrc}">
              <div class="recaptcha_input_area">
                <label for="recaptcha_response_field">{bridgeDBText12}</label>
              </div>
              <div>
                <input name="recaptcha_response_field"\
                        id="recaptcha_response_field"
                type="text" autocomplete="off">
              </div>
              <div>
                <input type="submit" name="submit" value="{bridgeDBText13}">
              </div>
            </form>
            """).strip()

        recaptchaTemplate = recaptchaTemplate.format(
                recaptchaChallengeField=challenge,
                recaptchaImgSrc=img,
                bridgeDBText12=t.gettext(I18n.BRIDGEDB_TEXT[13]),
                bridgeDBText13=t.gettext(I18n.BRIDGEDB_TEXT[14]),
                bridgeDBText14=t.gettext(I18n.BRIDGEDB_TEXT[15]))

        html_msg = "<html><body>" \
                   + "<p>" + t.gettext(I18n.BRIDGEDB_TEXT[1]) + "</p>" \
                   + "<p>" + t.gettext(I18n.BRIDGEDB_TEXT[9]) + "</p>" \
                   + "<p>" + recaptchaTemplate + "</p>" \
                   + "<p>" + t.gettext(I18n.BRIDGEDB_TEXT[4]) + "</p>" \
                   + email_domain_list \
                   + "<hr /><p><a href='?ipv6=true'>" \
                   + t.gettext(I18n.BRIDGEDB_TEXT[20]) + "</a></p>" \
                   + "<p><a href='?transport=obfs2'>" \
                   + t.gettext(I18n.BRIDGEDB_TEXT[21]) + "</a></p>" \
                   + "<form method='GET'>" \
                   + "<p>" + t.gettext(I18n.BRIDGEDB_TEXT[22]) + "</p>" \
                   + "<input name='transport'>" \
                   + "<input name='submit' type='submit'>" \
                   + "</form>" \
                   + "</body></html>"
        return html_msg 

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
    Site = twisted.web.server.Site
    site = None
    if cfg.HTTP_UNENCRYPTED_PORT:
        ip = cfg.HTTP_UNENCRYPTED_BIND_IP or ""
        resource = WebResource(dist, sched, cfg.HTTPS_N_BRIDGES_PER_ANSWER,
                       cfg.HTTP_USE_IP_FROM_FORWARDED_HEADER,
                       includeFingerprints=cfg.HTTPS_INCLUDE_FINGERPRINTS,
                       useRecaptcha=cfg.RECAPTCHA_ENABLED,
                       domains=cfg.EMAIL_DOMAINS,
                       recaptchaPrivKey=cfg.RECAPTCHA_PRIV_KEY,
                       recaptchaPubKey=cfg.RECAPTCHA_PUB_KEY) 
        site = Site(resource)
        reactor.listenTCP(cfg.HTTP_UNENCRYPTED_PORT, site, interface=ip)
    if cfg.HTTPS_PORT:
        from twisted.internet.ssl import DefaultOpenSSLContextFactory
        #from OpenSSL.SSL import SSLv3_METHOD
        ip = cfg.HTTPS_BIND_IP or ""
        factory = DefaultOpenSSLContextFactory(cfg.HTTPS_KEY_FILE,
                                               cfg.HTTPS_CERT_FILE)
        resource = WebResource(dist, sched, cfg.HTTPS_N_BRIDGES_PER_ANSWER,
                       cfg.HTTPS_USE_IP_FROM_FORWARDED_HEADER,
                       includeFingerprints=cfg.HTTPS_INCLUDE_FINGERPRINTS,
                       domains=cfg.EMAIL_DOMAINS,
                       useRecaptcha=cfg.RECAPTCHA_ENABLED,
                       recaptchaPrivKey=cfg.RECAPTCHA_PRIV_KEY,
                       recaptchaPubKey=cfg.RECAPTCHA_PUB_KEY) 
        site = Site(resource)
        reactor.listenSSL(cfg.HTTPS_PORT, site, factory, interface=ip)
    return site

def getLocaleFromRequest(request):
    # See if we did get a request for a certain locale, otherwise fall back
    # to 'en':
    # Try evaluating the path /foo first, then check if we got a ?lang=foo
    default_lang = lang = "en"
    if len(request.path) > 1:
        lang = request.path[1:]
    if lang == default_lang:
        lang = request.args.get("lang", [default_lang])
        lang = lang[0]
    return I18n.getLang(lang)

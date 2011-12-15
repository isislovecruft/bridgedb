# BridgeDB by Nick Mathewson.
# Copyright (c) 2007-2009, The Tor Project, Inc.
# See LICENSE for licensing information

"""
This module implements the web and email interfaces to the bridge database.
"""

from cStringIO import StringIO
import MimeWriter
import rfc822
import time
import logging
import gettext
import re

from zope.interface import implements

from twisted.internet import reactor
from twisted.internet.defer import Deferred
from twisted.internet.task import LoopingCall
import twisted.web.resource
import twisted.web.server
import twisted.mail.smtp

import bridgedb.Dist
import bridgedb.I18n as I18n

import recaptcha.client.captcha as captcha
from random import randint
from bridgedb.Raptcha import Raptcha
import base64
import textwrap
from ipaddr import IPv4Address, IPv6Address
 
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

        # allow client to specify a country
        forcecc = getCCFromRequest(request)
        if forcecc != None:
            countryCode = forcecc

        # get locale
        t = getLocaleFromRequest(request) 

        format = request.args.get("format", None)
        if format and len(format): format = format[0] # choose the first arg

        # do want ipv6 support?
        ipv6 = False
        if "ipv6" in request.postpath: ipv6 = True

        if ip:
            if ipv6:
                rules=[filterBridgesByIP6]
            else:
                rules=[filterBridgesByIP4]

            bridges = self.distributor.getBridgesForIP(ip, interval,
                                                       self.nBridgesToGive,
                                                       countryCode,
                                                       bridgeFilterRules=rules)

        if bridges:
            answer = "".join("%s %s\n" % (
                b.getConfigLine(self.includeFingerprints,needIPv6=ipv6,
                                selectFromORAddresses=ipv6),
                (I18n.BRIDGEDB_TEXT[16] if b.isBlocked(countryCode) else "")
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
                   + "<hr /><p>Note for experts: if you can use IPv6, try upgrading to Tor 0.2.3.12-alpha and use this IPv6 address in your bridge line:<br /><tt>[2001:948:7:2::164]:6001</tt><br />Let us know how it goes!</p>" \
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

class MailFile:
    """A file-like object used to hand rfc822.Message a list of lines
       as though it were reading them from a file."""
    def __init__(self, lines):
        self.lines = lines
        self.idx = 0
    def readline(self):
        try :
            line = self.lines[self.idx]
            self.idx += 1
            return line
        except IndexError:
            return ""

def getBridgeDBEmailAddrFromList(ctx, address_list):
    """Loop through a list of (full name, email address) pairs and look up our
       mail address. If our address isn't found (which can't happen), return
       the default ctx from address so we can keep on working.
    """
    email = ctx.fromAddr
    for _, address in address_list:
        # Strip the @torproject.org part from the address
        idx = address.find('@')
        if idx != -1:
            username = address[:idx]
            # See if the user looks familiar. We do a 'find' instead
            # of compare because we might have a '+' address here
            if username.find(ctx.username) != -1:
                email = address
    return email

def getMailResponse(lines, ctx):
    """Given a list of lines from an incoming email message, and a
       MailContext object, parse the email and decide what to do in response.
       If we want to answer, return a 2-tuple containing the address that
       will receive the response, and a readable filelike object containing
       the response.  Return None,None if we shouldn't answer.
    """
    # Extract data from the headers.
    msg = rfc822.Message(MailFile(lines))
    subject = msg.getheader("Subject", None)
    if not subject: subject = "[no subject]"
    clientFromAddr = msg.getaddr("From")
    clientSenderAddr = msg.getaddr("Sender")
    # RFC822 requires at least one 'To' address
    clientToList = msg.getaddrlist("To")
    clientToaddr = getBridgeDBEmailAddrFromList(ctx, clientToList)
    msgID = msg.getheader("Message-ID", None)
    if clientSenderAddr and clientSenderAddr[1]:
        clientAddr = clientSenderAddr[1]
    elif clientFromAddr and clientFromAddr[1]:
        clientAddr = clientFromAddr[1]
    else:
        logging.info("No From or Sender header on incoming mail.")
        return None,None

    # Look up the locale part in the 'To:' address, if there is one and get
    # the appropriate Translation object
    lang = getLocaleFromPlusAddr(clientToaddr)
    t = I18n.getLang(lang)

    try:
        _, addrdomain = bridgedb.Dist.extractAddrSpec(clientAddr.lower())
    except bridgedb.Dist.BadEmail:
        logging.info("Ignoring bad address on incoming email.")
        return None,None
    if not addrdomain:
        logging.info("Couldn't parse domain from %r", clientAddr)
    if addrdomain and ctx.cfg.EMAIL_DOMAIN_MAP:
        addrdomain = ctx.cfg.EMAIL_DOMAIN_MAP.get(addrdomain, addrdomain)
    if addrdomain not in ctx.cfg.EMAIL_DOMAINS:
        logging.info("Unrecognized email domain %r", addrdomain)
        return None,None
    rules = ctx.cfg.EMAIL_DOMAIN_RULES.get(addrdomain, [])
    if 'dkim' in rules:
        # getheader() returns the last of a given kind of header; we want
        # to get the first, so we use getheaders() instead.
        dkimHeaders = msg.getheaders("X-DKIM-Authentication-Results")
        dkimHeader = "<no header>"
        if dkimHeaders: dkimHeader = dkimHeaders[0]
        if not dkimHeader.startswith("pass"):
            logging.info("Got a bad dkim header (%r) on an incoming mail; "
                         "rejecting it.", dkimHeader)
            return None, None

    # Was the magic string included
    #for ln in lines:
    #    if ln.strip().lower() in ("get bridges", "subject: get bridges"):
    #        break
    #else:
    #    logging.info("Got a mail from %r with no bridge request; dropping",
    #                 clientAddr)
    #    return None,None

    # Figure out which bridges to send

    # read subject, see if they want ipv6
    ipv6 = False
    for ln in lines:
        if "ipv6" in ln.strip().lower():
            ipv6 = True
            rules=[filterBridgesByIP6]
    else:
        rules=[filterBridgesByIP4]

    try:
        interval = ctx.schedule.getInterval(time.time())
        bridges = ctx.distributor.getBridgesForEmail(clientAddr,
                                                     interval, ctx.N,
                                                     countryCode=None,
                                                     bridgeFilterRules=rules)
    except bridgedb.Dist.BadEmail, e:
        logging.info("Got a mail from a bad email address %r: %s.",
                     clientAddr, e)
        return None, None

    # Handle rate limited email
    except bridgedb.Dist.TooSoonEmail, e:
        logging.info("Got a mail too frequently; warning %r: %s.",
                     clientAddr, e)

        # Compose a warning email
        f = StringIO()
        w = MimeWriter.MimeWriter(f)
        w.addheader("From", ctx.fromAddr)
        w.addheader("To", clientAddr)
        w.addheader("Message-ID", twisted.mail.smtp.messageid())
        if not subject.startswith("Re:"): subject = "Re: %s"%subject
        w.addheader("Subject", subject)
        if msgID:
            w.addheader("In-Reply-To", msgID)
        w.addheader("Date", twisted.mail.smtp.rfc822date())
        body = w.startbody("text/plain")

        # MAX_EMAIL_RATE is in seconds, convert to hours
        EMAIL_MESSAGE_RATELIMIT = buildSpamWarningTemplate(t)
        body.write(EMAIL_MESSAGE_RATELIMIT % (bridgedb.Dist.MAX_EMAIL_RATE / 3600))
        f.seek(0)
        return clientAddr, f

    except bridgedb.Dist.IgnoreEmail, e:
        logging.info("Got a mail too frequently; ignoring %r: %s.",
                      clientAddr, e)
        return None, None 

    # Generate the message.
    f = StringIO()
    w = MimeWriter.MimeWriter(f)
    w.addheader("From", ctx.fromAddr)
    w.addheader("To", clientAddr)
    w.addheader("Message-ID", twisted.mail.smtp.messageid())
    if not subject.startswith("Re:"): subject = "Re: %s"%subject
    w.addheader("Subject", subject)
    if msgID:
        w.addheader("In-Reply-To", msgID)
    w.addheader("Date", twisted.mail.smtp.rfc822date())
    body = w.startbody("text/plain")

    if bridges:
        with_fp = ctx.cfg.EMAIL_INCLUDE_FINGERPRINTS
        answer = "".join("  %s\n" % b.getConfigLine(with_fp, needIPv6=ipv6,\
                                   selectFromORAddresses=ipv6) for b in bridges)
    else:
        answer = "(no bridges currently available)"

    EMAIL_MESSAGE_TEMPLATE = buildMessageTemplate(t)
    body.write(EMAIL_MESSAGE_TEMPLATE % answer)

    f.seek(0)
    logging.info("Email looks good; we should send an answer.")
    return clientAddr, f

def buildMessageTemplate(t):
    msg_template =  t.gettext(I18n.BRIDGEDB_TEXT[5]) + "\n\n" \
                    + t.gettext(I18n.BRIDGEDB_TEXT[0]) + "\n\n" \
                    + "%s\n" \
                    + t.gettext(I18n.BRIDGEDB_TEXT[1]) + "\n\n" \
                    + t.gettext(I18n.BRIDGEDB_TEXT[2]) + "\n\n" \
                    + t.gettext(I18n.BRIDGEDB_TEXT[3]) + "\n\n" \
                    + t.gettext(I18n.BRIDGEDB_TEXT[6]) + "\n\n"

    return msg_template

def buildSpamWarningTemplate(t):
    msg_template =  t.gettext(I18n.BRIDGEDB_TEXT[5]) + "\n\n" \
                    + t.gettext(I18n.BRIDGEDB_TEXT[10]) + "\n\n" \
                    + "%s " \
                    + t.gettext(I18n.BRIDGEDB_TEXT[11]) + "\n\n" \
                    + t.gettext(I18n.BRIDGEDB_TEXT[12]) + "\n\n"
    return msg_template 

def replyToMail(lines, ctx):
    """Given a list of lines from an incoming email message, and a
       MailContext object, possibly send a reply.
    """
    logging.info("Got a completed email; deciding whether to reply.")
    sendToUser, response = getMailResponse(lines, ctx)
    if response is None:
        logging.debug("getMailResponse said not to reply, so I won't.")
        return
    response.seek(0)
    d = Deferred()
    factory = twisted.mail.smtp.SMTPSenderFactory(
        ctx.smtpFromAddr,
        sendToUser,
        response,
        d)
    reactor.connectTCP(ctx.smtpServer, ctx.smtpPort, factory)
    logging.info("Sending reply to %r", sendToUser)
    return d

def getLocaleFromPlusAddr(address):
    """See whether the user sent his email to a 'plus' address, for 
       instance to bridgedb+fa@tpo. Plus addresses are the current 
       mechanism to set the reply language
    """
    replyLocale = "en"
    r = '.*(<)?(\w+\+(\w+)@\w+(?:\.\w+)+)(?(1)>)'
    match = re.match(r, address)
    if match:
        replyLocale = match.group(3)

    return replyLocale

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

class MailContext:
    """Helper object that holds information used by email subsystem."""
    def __init__(self, cfg, dist, sched):
        # Reject any RCPT TO lines that aren't to this user.
        self.username = (cfg.EMAIL_USERNAME or
                         "bridges")
        # Reject any mail longer than this.
        self.maximumSize = 32*1024
        # Use this server for outgoing mail.
        self.smtpServer = (cfg.EMAIL_SMTP_HOST or "127.0.0.1")
        self.smtpPort = (cfg.EMAIL_SMTP_PORT or 25)
        # Use this address in the MAIL FROM line for outgoing mail.
        self.smtpFromAddr = (cfg.EMAIL_SMTP_FROM_ADDR or
                             "bridges@torproject.org")
        # Use this address in the "From:" header for outgoing mail.
        self.fromAddr = (cfg.EMAIL_FROM_ADDR or
                         "bridges@torproject.org")
        # An EmailBasedDistributor object
        self.distributor = dist
        # An IntervalSchedule object
        self.schedule = sched
        # The number of bridges to send for each email.
        self.N = cfg.EMAIL_N_BRIDGES_PER_ANSWER

        self.cfg = cfg

class MailMessage:
    """Plugs into the Twisted Mail and receives an incoming message.
       Once the message is in, we reply or we don't. """
    implements(twisted.mail.smtp.IMessage)

    def __init__(self, ctx):
        """Create a new MailMessage from a MailContext."""
        self.ctx = ctx
        self.lines = []
        self.nBytes = 0
        self.ignoring = False

    def lineReceived(self, line):
        """Called when we get another line of an incoming message."""
        self.nBytes += len(line)
        logging.debug("> %s", line.rstrip("\r\n"))
        if self.nBytes > self.ctx.maximumSize:
            self.ignoring = True
        else:
            self.lines.append(line)

    def eomReceived(self):
        """Called when we receive the end of a message."""
        if not self.ignoring:
            replyToMail(self.lines, self.ctx)
        return twisted.internet.defer.succeed(None)

    def connectionLost(self):
        """Called if we die partway through reading a message."""
        pass

class MailDelivery:
    """Plugs into Twisted Mail and handles SMTP commands."""
    implements(twisted.mail.smtp.IMessageDelivery)
    def setBridgeDBContext(self, ctx):
        self.ctx = ctx
    def receivedHeader(self, helo, origin, recipients):
        #XXXX what is this for? what should it be?
        return "Received: BridgeDB"
    def validateFrom(self, helo, origin):
        return origin
    def validateTo(self, user):
        """If the local user that was addressed isn't our configured local 
           user or doesn't contain a '+' with a prefix matching the local
           configured user: Yell
        """
        u = user.dest.local
        # Hasplus? If yes, strip '+foo'
        idx = u.find('+')
        if idx != -1:
            u = u[:idx]
        if u != self.ctx.username:
            raise twisted.mail.smtp.SMTPBadRcpt(user)
        return lambda: MailMessage(self.ctx)

class MailFactory(twisted.mail.smtp.SMTPFactory):
    """Plugs into Twisted Mail; creates a new MailDelivery whenever we get
       a connection on the SMTP port."""
    def __init__(self, *a, **kw):
        twisted.mail.smtp.SMTPFactory.__init__(self, *a, **kw)
        self.delivery = MailDelivery()

    def setBridgeDBContext(self, ctx):
        self.ctx = ctx
        self.delivery.setBridgeDBContext(ctx)

    def buildProtocol(self, addr):
        p = twisted.mail.smtp.SMTPFactory.buildProtocol(self, addr)
        p.delivery = self.delivery
        return p

def addSMTPServer(cfg, dist, sched):
    """Set up a smtp server.
         cfg -- a configuration object from Main.  We use these options:
                EMAIL_BIND_IP
                EMAIL_PORT
                EMAIL_N_BRIDGES_PER_ANSWER
                EMAIL_DOMAIN_RULES
         dist -- an EmailBasedDistributor object.
         sched -- an IntervalSchedule object.
    """
    ctx = MailContext(cfg, dist, sched)
    factory = MailFactory()
    factory.setBridgeDBContext(ctx)
    ip = cfg.EMAIL_BIND_IP or ""
    reactor.listenTCP(cfg.EMAIL_PORT, factory, interface=ip)
    # Set up a LoopingCall to run every 30 minutes and forget old email times.
    lc = LoopingCall(dist.cleanDatabase)
    lc.start(1800, now=False)
    return factory

def runServers():
    """Start all the servers that we've configured. Exits when they do."""
    reactor.run()

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

def getCCFromRequest(request):
    path = re.sub(r'[^a-zA-Z]', '', request.path)
    if len(path) ==  2:
        return path.lower()
    return None 

def filterBridgesByIP4(bridge):
    try:
        if IPv4Address(bridge.ip): return True
    except ValueError:
        pass

    for k in bridge.or_addresses.keys():
        if type(k) is IPv4Address:
            return True
    return False

def filterBridgesByIP6(bridge):
    try:
        if IPv6Address(bridge.ip): return True
    except ValueError:
        pass

    for k in bridge.or_addresses.keys():
        if type(k) is IPv6Address:
            return True
    return False

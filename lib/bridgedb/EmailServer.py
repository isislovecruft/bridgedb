# BridgeDB by Nick Mathewson.
# Copyright (c) 2007-2013, The Tor Project, Inc.
# See LICENSE for licensing information

"""
This module implements the email interface to the bridge database.
"""

from StringIO import StringIO
import MimeWriter
import gettext
import gpgme
import logging
import re
import rfc822
import time

from ipaddr import IPv4Address, IPv6Address

from twisted.internet import reactor
from twisted.internet.defer import Deferred
from twisted.internet.task import LoopingCall
import twisted.mail.smtp

from zope.interface import implements

import bridgedb.Dist
import bridgedb.Util as Util
from bridgedb.Dist import BadEmail, TooSoonEmail, IgnoreEmail
from bridgedb.Filters import filterBridgesByIP6, filterBridgesByIP4
from bridgedb.Filters import filterBridgesByTransport
from bridgedb.Filters import filterBridgesByNotBlockedIn

import bridgedb.I18n as I18n

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
    except BadEmail:
        logging.info("Ignoring bad address on incoming email.")
        return None,None
    if not addrdomain:
        logging.info("Couldn't parse domain from %r", Util.logSafely(clientAddr))
    if addrdomain and ctx.cfg.EMAIL_DOMAIN_MAP:
        addrdomain = ctx.cfg.EMAIL_DOMAIN_MAP.get(addrdomain, addrdomain)
    if addrdomain not in ctx.cfg.EMAIL_DOMAINS:
        logging.info("Unrecognized email domain %r", Util.logSafely(addrdomain))
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
    unblocked = transport = ipv6 = skippedheaders = False
    bridgeFilterRules = []
    addressClass = None
    for ln in lines:
        # ignore all lines before the subject header
        if "subject" in ln.strip().lower():
            skippedheaders = True
        if not skippedheaders: continue

        if "ipv6" in ln.strip().lower():
            ipv6 = True
        if "transport" in ln.strip().lower():
            try:
                transport = re.search("transport ([_a-zA-Z][_a-zA-Z0-9]*)",
                        ln).group(1).strip()
            except (TypeError, AttributeError):
                transport = None
            logging.debug("Got request for transport: %s" % transport)
        if "unblocked" in ln.strip().lower():
            try:
                unblocked = re.search("unblocked ([a-zA-Z]{2,4})",
                        ln).group(1).strip()
            except (TypeError, AttributeError):
                transport = None

    if ipv6:
        bridgeFilterRules.append(filterBridgesByIP6)
        addressClass = IPv6Address
    else:
        bridgeFilterRules.append(filterBridgesByIP4)
        addressClass = IPv4Address

    if transport:
        bridgeFilterRules = [filterBridgesByTransport(transport, addressClass)]

    if unblocked:
        rules.append(filterBridgesByNotBlockedIn(unblocked,
            addressClass, transport))

    try:
        interval = ctx.schedule.getInterval(time.time())
        bridges = ctx.distributor.getBridgesForEmail(clientAddr,
            interval, ctx.N,
            countryCode=None,
            bridgeFilterRules=bridgeFilterRules)

    # Handle rate limited email
    except TooSoonEmail, e:
        logging.info("Got a mail too frequently; warning %r: %s.",
                     Util.logSafely(clientAddr), e)

        # Compose a warning email
        # MAX_EMAIL_RATE is in seconds, convert to hours
        body  = buildSpamWarningTemplate(t) % (bridgedb.Dist.MAX_EMAIL_RATE / 3600)
        return composeEmail(ctx.fromAddr, clientAddr, subject, body, msgID,
                gpgContext=ctx.gpgContext)

    except IgnoreEmail, e:
        logging.info("Got a mail too frequently; ignoring %r: %s.",
                      Util.logSafely(clientAddr), e)
        return None, None 

    except BadEmail, e:
        logging.info("Got a mail from a bad email address %r: %s.",
                     Util.logSafely(clientAddr), e)
        return None, None 

    if bridges:
        with_fp = ctx.cfg.EMAIL_INCLUDE_FINGERPRINTS
        answer = "".join("  %s\n" %b.getConfigLine(
            includeFingerprint=with_fp,
            addressClass=addressClass,
            transport=transport,
            request=clientAddr
            ) for b in bridges)
    else:
        answer = "(no bridges currently available)"

    body = buildMessageTemplate(t) % answer
    # Generate the message.
    return composeEmail(ctx.fromAddr, clientAddr, subject, body, msgID,
            gpgContext=ctx.gpgContext)


def buildMessageTemplate(t):
    msg_template =  t.gettext(I18n.BRIDGEDB_TEXT[5]) + "\n\n" \
                    + t.gettext(I18n.BRIDGEDB_TEXT[0]) + "\n\n" \
                    + "%s\n" \
                    + t.gettext(I18n.BRIDGEDB_TEXT[1]) + "\n\n" \
                    + t.gettext(I18n.BRIDGEDB_TEXT[2]) + "\n\n" \
                    + t.gettext(I18n.BRIDGEDB_TEXT[3]) + "\n\n" \
                    + t.gettext(I18n.BRIDGEDB_TEXT[17])+ "\n\n"
                    # list supported commands, e.g. ipv6, transport
    msg_template = msg_template \
                    + "  " + t.gettext(I18n.BRIDGEDB_TEXT[18])+ "\n" \
                    + "  " + t.gettext(I18n.BRIDGEDB_TEXT[19])+ "\n\n" \
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
    logging.info("Sending reply to %r", Util.logSafely(sendToUser))
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

        # Initialize a gpg context or set to None for backward compatibliity.
        self.gpgContext = getGPGContext(cfg)

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

def composeEmail(fromAddr, clientAddr, subject, body, msgID=False,
        gpgContext=None):

    f = StringIO()
    w = MimeWriter.MimeWriter(f)
    w.addheader("From", fromAddr)
    w.addheader("To", clientAddr)
    w.addheader("Message-ID", twisted.mail.smtp.messageid())
    if not subject.startswith("Re:"): subject = "Re: %s"%subject
    w.addheader("Subject", subject)
    if msgID:
        w.addheader("In-Reply-To", msgID)
    w.addheader("Date", twisted.mail.smtp.rfc822date())
    mailbody = w.startbody("text/plain")

    # gpg-clearsign messages
    if gpgContext:
        signature = StringIO()
        plaintext = StringIO(body)
        sigs = gpgContext.sign(plaintext, signature, gpgme.SIG_MODE_CLEAR)
        if (len(sigs) != 1):
            logging.warn('Failed to sign message!')
        signature.seek(0)
        [mailbody.write(l) for l in signature]
    else:
        mailbody.write(body)

    f.seek(0)
    logging.debug("Email body:\n%s" % f.read())
    f.seek(0)
    return clientAddr, f

def getGPGContext(cfg):
    """Import a key from a file and initialise a context for GnuPG operations.

    The key should not be protected by a passphrase, and should have the
    signing flag enabled.

    :type cfg: :class:`bridgedb.persistent.Conf`
    :param cfg: The loaded config file.
    :rtype: :class:`gpgme.Context` or None
    :returns: A GPGME context with the signers initialized by the keyfile
        specified by the option EMAIL_GPG_SIGNING_KEY in bridgedb.conf, or
        None if the option was not enabled, or was unable to initialize.
    """
    try:
        # must have enabled signing and specified a key file
        if not cfg.EMAIL_GPG_SIGNING_ENABLED or not cfg.EMAIL_GPG_SIGNING_KEY:
            return None
    except AttributeError:
        return None

    keyfile = None
    ctx = gpgme.Context()

    try:
        logging.debug("Opening GPG keyfile %s..." % cfg.EMAIL_GPG_SIGNING_KEY)
        keyfile = open(cfg.EMAIL_GPG_SIGNING_KEY)
        key = ctx.import_(keyfile)

        if not (len(key.imports) > 0):
            logging.debug(
                "Unexpected result from gpgme.Context.import_(): %r" % key)
            raise gpgme.GpgmeError("Could not import GnuPG key from file %r"
                                   % cfg.EMAIL_GPG_SIGNING_KEY)

        fingerprint = key.imports[0][0]
        logging.info("GPG Key with fingerprint %s imported" % fingerprint)

        ctx.armor = True
        ctx.signers = [ctx.get_key(fingerprint)]

        logging.info("Testing signature created with GnuPG key...")
        message = StringIO('Test')
        new_sigs = ctx.sign(message, StringIO(), gpgme.SIG_MODE_CLEAR)
        if not len(new_sigs) == 1:
            raise gpgme.GpgmeError(
                "Testing was unable to produce a signature with GnuPG key.")

    except (IOError, OSError) as error:
        logging.debug(error)
        logging.error("Could not open or read from GnuPG key file %r!"
                      % cfg.EMAIL_GPG_SIGNING_KEY)
        ctx = None
    except gpgme.GpgmeError as error:
        logging.exception(error)
        ctx = None
    finally:
        if keyfile and not keyfile.closed:
            keyfile.close()

    return ctx

# BridgeDB by Nick Mathewson.
# Copyright (c) 2007, The Tor Project, Inc.
# See LICENSE for licensing informatino

from cStringIO import StringIO
import MimeWriter
import rfc822
import time

from zope.interface import implements

from twisted.internet import reactor
from twisted.internet.defer import Deferred
import twisted.web.resource
import twisted.web.server
import twisted.mail.smtp

class WebResource(twisted.web.resource.Resource):
    isLeaf = True

    def __init__(self, distributor, schedule, N=1):
        self.distributor = distributor
        self.schedule = schedule
        self.nBridgesToGive = N

    def render_GET(self, request):
        interval = self.schedule.getInterval(time.time())
        ip = request.getClientIP()
        bridges = self.distributor.getBridgesForIP(ip, interval,
                                                   self.nBridgesToGive)
        if bridges:
            answer = "".join("%s\n" % b.getConfigLine() for b in bridges)
        else:
            answer = "No bridges available."

        return "<html><body><pre>%s</pre></body></html>" % answer

def addWebServer(cfg, dist, sched):
    from twised.web.server import Site
    resource = WebResource(dist, sched, cfg.HTTPS_N_BRIDGES_PER_ANSWER)
    site = Site(resource)
    if cfg.HTTP_UNENCRYPTED_PORT:
        reactor.listenTCP(cfg.HTTP_UNENCRYPTED_PORT, site)
    if cfg.HTTPS_PORT:
        from twisted.internet.ssl import DefaultOpenSSLContextFactory
        from OpenSSL.SSL import SSLv3_METHOD
        factory = DefaultOpenSSLContextFactory(cfg.HTTPS_KEY_FILE,
                                               cfg.HTTPS_CERT_FILE)
        reactor.listenSSL(cfg.HTTPS_PORT, site, factory)
    return site

class MailFile:
    def __init__(self, lines):
        self.idx = 0
    def readline(self):
        try :
            line = self.lines[self.idx]
            self.idx += 1
            return line #Append a \n? XXXX
        except IndexError:
            return ""

def getMailResponse(lines, ctx):
    # Extract data from the headers.
    msg = rfc822(MailFile(lines))
    subject = msg.getheader("Subject", None)
    if not subject: subject = "[no subject]"
    clientFromAddr = msg.getaddr("From")
    clientSenderAddr = msg.getaddr("Sender")
    msgID = msg.getheader("Message-ID")
    if clientSenderAddr:
        clientAddr = clientSenderAddr[1]
    elif clientFromAddr:
        clientAddr = clientFromAddr[1]
    else:
        return None
    for ln in lines:
        if ln.strip() in ("get bridges", "Subject: get bridges"):
            break
    else:
        return None

    try:
        interval = ctx.schedule.getInterval(time.time())
        bridges = ctx.distributor.getBridgesForEmail(clientAddr,
                                                     interval, ctx.N)
    except bridgedb.Dist.BadEmail:
        return None
    if not bridges:
        return None

    # Generate the message.
    f = StringIO()
    w = MimeWriter.MimeWriter(f)
    w.addHeader("From", ctx.fromAddr)
    w.addHeader("To", clientAddr)
    w.addHeader("Message-ID", twisted.mail.smtp.messageid())
    if not subject.startswith("Re:"): subject = "Re: %s"%subject
    w.addHeader("Subject", subject)
    w.addHeader("In-Reply-To", msgID)
    w.addHeader("Date", twisted.mail.smtp.rfc822date())
    body = w.startbody("text/plain")
    for b in bridges:
        body.write("%s\n" % b.getConfigLine())

    f.seek(0)
    return f

def replyToMail(lines, ctx):
    sendToUser, response = getMailResponse(lines)
    if response is None:
        return
    d = Deferred()
    factory = twisted.mail.smtp.SMTPSenderFactory(
        ctx.fromAddr,
        sendToUser,
        StringIO(response),
        d)
    reactor.connectTCP(ctx.smtpServer, ctx.smtpPort, factory)
    return d

class MailContext:
    def __init__(self, cfg):
        self.username = "bridges"
        self.maximumSize = 32*1024
        self.smtpServer
        self.smtpPort
        self.fromAddr
        self.distributor
        self.schedule

class MailMessage:
    implements(twisted.mail.smtp.IMessage)

    def __init__(self, ctx)
        self.ctx = ctx
        self.lines = []
        self.nBytes = 0
        self.ignoring = False

    def lineReceived(self, line):
        self.nBytes += len(line)
        if self.nBytes > ctx.maximumSize:
            self.ignoring = True
        else:
            self.lines.append(line)

    def eomReceived(self):
        if not self.ignoring:
            replyToMail(self.lines, self.ctx)
        return defer.succeed(None)

    def connectionLost(self):
        pass

class MailDelivery:
    implements(twisted.mail.smtp.IMessageDelivery)
    def setBridgeDBContext(self, ctx):
        self.ctx = ctx
    def receivedHeader(self, helo, origin, recipients):
        #XXXX what is this for? what should it be?
        return "Received: BridgeDB"
    def validateFrom(self, helo, origin):
        return origin
    def validateTo(self, user):
        if user.dest.local != self.ctx.username:
            raise twisted.mail.smtp.SMTPBadRcpt(user)
        return lambda: MailMessage(self.ctx)

class MailFactory(twisted.mail.smtp.SMTPFactory):
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
    ctx = MailContext() #XXXX
    factory = MailFactory()
    factory.setBridgeDBContext(ctx)
    reactor.listenTCP(cfg.EMAIL_PORT, factory)
    return factory

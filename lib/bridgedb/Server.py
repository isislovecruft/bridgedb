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

import bridgedb.Dist

HTML_MESSAGE_TEMPLATE = """
<html><body>
<p>Here are your bridge relays:
<pre>%s</pre>
</p>
<p>Bridge relays (or "bridges" for short) are Tor relays that aren't listed
in the main directory. Since there is no complete public list of them,
even if your ISP is filtering connections to all the known Tor relays,
they probably won't be able to block all the bridges.</p>
<p>To use the above lines, go to Vidalia's Network settings page, and click
"My ISP blocks connections to the Tor network". Then add each bridge
address one at a time.</p>
<p>Configuring more than one bridge address will make your Tor connection
more stable, in case some of the bridges become unreachable.</p>
<p>Another way to find public bridge addresses is to send mail to
bridges@torproject.org with the line "get bridges" by itself in the body
of the mail. However, so we can make it harder for an attacker to learn
lots of bridge addresses, you must send this request from a gmail or
yahoo account.</p>
</body></html>
""".strip()

EMAIL_MESSAGE_TEMPLATE = """\
[This is an automated message; please do not reply.]

Here are your bridge relays:

%s

Bridge relays (or "bridges" for short) are Tor relays that aren't listed
in the main directory. Since there is no complete public list of them,
even if your ISP is filtering connections to all the known Tor relays,
they probably won't be able to block all the bridges.

To use the above lines, go to Vidalia's Network settings page, and click
"My ISP blocks connections to the Tor network". Then add each bridge
address one at a time.

Configuring more than one bridge address will make your Tor connection
more stable, in case some of the bridges become unreachable.

Another way to find public bridge addresses is to visit
https://bridges.torproject.org/. The answers you get from that page
will change every few days, so check back periodically if you need more
bridge addresses.
"""

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

        return HTML_MESSAGE_TEMPLAY % answer

def addWebServer(cfg, dist, sched):
    from twisted.web.server import Site
    resource = WebResource(dist, sched, cfg.HTTPS_N_BRIDGES_PER_ANSWER)
    site = Site(resource)
    if cfg.HTTP_UNENCRYPTED_PORT:
        ip = cfg.HTTPS_BIND_IP or ""
        reactor.listenTCP(cfg.HTTP_UNENCRYPTED_PORT, site, interface=ip)
    if cfg.HTTPS_PORT:
        from twisted.internet.ssl import DefaultOpenSSLContextFactory
        from OpenSSL.SSL import SSLv3_METHOD
        ip = cfg.HTTP_UNENCRYPTED_BIND_IP or ""
        factory = DefaultOpenSSLContextFactory(cfg.HTTPS_KEY_FILE,
                                               cfg.HTTPS_CERT_FILE)
        reactor.listenSSL(cfg.HTTPS_PORT, site, factory, interface=ip)
    return site

class MailFile:
    def __init__(self, lines):
        self.lines = lines
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
    msg = rfc822.Message(MailFile(lines))
    subject = msg.getheader("Subject", None)
    if not subject: subject = "[no subject]"
    clientFromAddr = msg.getaddr("From")
    clientSenderAddr = msg.getaddr("Sender")
    msgID = msg.getheader("Message-ID")
    if clientSenderAddr and clientSenderAddr[1]:
        clientAddr = clientSenderAddr[1]
    elif clientFromAddr and clientFromAddr[1]:
        clientAddr = clientFromAddr[1]
    else:
        print "No from header. WTF."
        return None,None
    for ln in lines:
        if ln.strip().lower() in ("get bridges", "subject: get bridges"):
            break
    else:
        print "No request for bridges."
        return None,None

    try:
        interval = ctx.schedule.getInterval(time.time())
        bridges = ctx.distributor.getBridgesForEmail(clientAddr,
                                                     interval, ctx.N)
    except bridgedb.Dist.BadEmail, e:
        print "Bad email addr in request: %s"%e
        return None, None
    if not bridges:
        print "No bridges available."
        return None, None

    # Generate the message.
    f = StringIO()
    w = MimeWriter.MimeWriter(f)
    w.addheader("From", ctx.fromAddr)
    w.addheader("To", clientAddr)
    w.addheader("Message-ID", twisted.mail.smtp.messageid())
    if not subject.startswith("Re:"): subject = "Re: %s"%subject
    w.addheader("Subject", subject)
    w.addheader("In-Reply-To", msgID)
    w.addheader("Date", twisted.mail.smtp.rfc822date())
    body = w.startbody("text/plain")

    answer = "".join("%s\n" % b.getConfigLine() for b in bridges)
    body.write(EMAIL_MESSAGE_TEMPLATE % answer)

    f.seek(0)
    return clientAddr, f

def replyToMail(lines, ctx):
    print "Got complete email; attempting to reply."
    sendToUser, response = getMailResponse(lines, ctx)
    if response is None:
        return
    response.seek(0)
    d = Deferred()
    factory = twisted.mail.smtp.SMTPSenderFactory(
        ctx.fromAddr,
        sendToUser,
        response,
        d)
    reactor.connectTCP(ctx.smtpServer, ctx.smtpPort, factory)
    print "Sending reply."
    return d

class MailContext:
    def __init__(self, cfg, dist, sched):
        self.username = "bridges"
        self.maximumSize = 32*1024
        self.smtpServer = "127.0.0.1"
        self.smtpPort = 25
        self.fromAddr = "bridges@torproject.org"
        self.distributor = dist
        self.schedule = sched
        self.N = cfg.EMAIL_N_BRIDGES_PER_ANSWER

class MailMessage:
    implements(twisted.mail.smtp.IMessage)

    def __init__(self, ctx):
        self.ctx = ctx
        self.lines = []
        self.nBytes = 0
        self.ignoring = False

    def lineReceived(self, line):
        self.nBytes += len(line)
        if self.nBytes > self.ctx.maximumSize:
            self.ignoring = True
        else:
            self.lines.append(line)

    def eomReceived(self):
        if not self.ignoring:
            replyToMail(self.lines, self.ctx)
        return twisted.internet.defer.succeed(None)

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
    ctx = MailContext(cfg, dist, sched)
    factory = MailFactory()
    factory.setBridgeDBContext(ctx)
    ip = cfg.EMAIL_BIND_IP or ""
    reactor.listenTCP(cfg.EMAIL_PORT, factory, interface=ip)
    return factory

def runServers():
    reactor.run()

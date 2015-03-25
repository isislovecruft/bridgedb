# -*- encoding: utf-8 -*-
#_____________________________________________________________________________
#
# This file is part of BridgeDB, a Tor bridge distribution system.
#
# :authors: Isis Lovecruft 0xA3ADB67A2CDB8B35 <isis@torproject.org>
# :copyright: (c) 2014-2015, Isis Lovecruft
#             (c) 2014-2015, The Tor Project, Inc.
# :license: see LICENSE for licensing information
#_____________________________________________________________________________

"""Unittests for :mod:`bridgedb.HTTPServer`."""

from __future__ import print_function

import logging
import os
import random
import shutil

import ipaddr

from BeautifulSoup import BeautifulSoup

from twisted.internet import reactor
from twisted.internet import task
from twisted.trial import unittest
from twisted.web.resource import Resource
from twisted.web.test import requesthelper

from bridgedb import HTTPServer
from bridgedb.schedule import ScheduledInterval


# For additional logger output for debugging, comment out the following:
logging.disable(50)
# and then uncomment the following line:
#HTTPServer.logging.getLogger().setLevel(10)


class ReplaceErrorPageTests(unittest.TestCase):
    """Tests for :func:`bridgedb.HTTPServer.replaceErrorPage`."""

    def test_replaceErrorPage(self):
        """``replaceErrorPage`` should return the expected html."""
        exc = Exception("vegan gümmibären")
        errorPage = HTTPServer.replaceErrorPage(exc)
        self.assertSubstring("Something went wrong", errorPage)
        self.assertNotSubstring("vegan gümmibären", errorPage)


class CaptchaProtectedResourceTests(unittest.TestCase):
    """Tests for :mod:`bridgedb.HTTPServer.CaptchaProtectedResource`."""

    def setUp(self):
        self.dist = None
        self.sched = None
        self.pagename = b'bridges.html'
        self.root = Resource()
        self.protectedResource = HTTPServer.WebResourceBridges(self.dist,
                                                               self.sched)
        self.captchaResource = HTTPServer.CaptchaProtectedResource(
            useForwardedHeader=True, protectedResource=self.protectedResource)
        self.root.putChild(self.pagename, self.captchaResource)

    def test_render_GET_noCaptcha(self):
        """render_GET() should return a page without a CAPTCHA, which has the
        image alt text.
        """
        request = DummyRequest([self.pagename])
        request.method = b'GET'
        page = self.captchaResource.render_GET(request)
        self.assertSubstring(
            "Your browser is not displaying images properly", page)

    def test_render_GET_missingTemplate(self):
        """render_GET() with a missing template should raise an error and
        return the result of replaceErrorPage().
        """
        oldLookup = HTTPServer.lookup
        try:
            HTTPServer.lookup = None
            request = DummyRequest([self.pagename])
            request.method = b'GET'
            page = self.captchaResource.render_GET(request)
            errorPage = HTTPServer.replaceErrorPage(Exception('kablam'))
            self.assertEqual(page, errorPage)
        finally:
            HTTPServer.lookup = oldLookup

    def createRequestWithIPs(self):
        """Set the IP address returned from ``request.getClientIP()`` to
        '3.3.3.3', and the IP address reported in the 'X-Forwarded-For' header
        to '2.2.2.2'.
        """
        request = DummyRequest([self.pagename])
        # Since we do not set ``request.getClientIP`` here like we do in some
        # of the other unittests, an exception would be raised here if
        # ``getBridgesForRequest()`` is unable to get the IP address from this
        # 'X-Forwarded-For' header (because ``ip`` would get set to ``None``).
        request.headers.update({'x-forwarded-for': '2.2.2.2'})
        # See :api:`twisted.test.requesthelper.DummyRequest.getClientIP`
        request.client = requesthelper.IPv4Address('TCP', '3.3.3.3', 443)
        request.method = b'GET'
        return request

    def test_getClientIP_XForwardedFor(self):
        """CaptchaProtectedResource.getClientIP() should return the IP address
        from the 'X-Forwarded-For' header when ``useForwardedHeader=True``.
        """
        self.captchaResource.useForwardedHeader = True
        request = self.createRequestWithIPs()
        clientIP = self.captchaResource.getClientIP(request)
        self.assertEqual(clientIP, '2.2.2.2')

    def test_getClientIP_fromRequest(self):
        """CaptchaProtectedResource.getClientIP() should return the IP address
        from the request instance when ``useForwardedHeader=False``.
        """
        self.captchaResource.useForwardedHeader = False
        request = self.createRequestWithIPs()
        clientIP = self.captchaResource.getClientIP(request)
        self.assertEqual(clientIP, '3.3.3.3')

    def test_render_POST(self):
        """render_POST() with a wrong 'captcha_response_field' should return
        a redirect to the CaptchaProtectedResource page.
        """
        request = DummyRequest([self.pagename])
        request.method = b'POST'
        page = self.captchaResource.render_POST(request)
        self.assertEqual(BeautifulSoup(page).find('meta')['http-equiv'],
                         'refresh')


class GimpCaptchaProtectedResourceTests(unittest.TestCase):
    """Tests for :mod:`bridgedb.HTTPServer.GimpCaptchaProtectedResource`."""

    def setUp(self):
        """Create a :class:`HTTPServer.WebResourceBridges` and protect it with
        a :class:`GimpCaptchaProtectedResource`.
        """
        # Create our cached CAPTCHA directory:
        self.captchaDir = 'captchas'
        if not os.path.isdir(self.captchaDir):
            os.makedirs(self.captchaDir)

        # Set up our resources to fake a minimal HTTP(S) server:
        self.pagename = b'captcha.html'
        self.root = Resource()
        # (None, None) is the (distributor, scheduleInterval):
        self.protectedResource = HTTPServer.WebResourceBridges(None, None)
        self.captchaResource = HTTPServer.GimpCaptchaProtectedResource(
            secretKey='42',
            publicKey='23',
            hmacKey='abcdefghijklmnopqrstuvwxyz012345',
            captchaDir='captchas',
            useForwardedHeader=True,
            protectedResource=self.protectedResource)

        self.root.putChild(self.pagename, self.captchaResource)

        # Set up the basic parts of our faked request:
        self.request = DummyRequest([self.pagename])

    def tearDown(self):
        """Delete the cached CAPTCHA directory if it still exists."""
        if os.path.isdir(self.captchaDir):
            shutil.rmtree(self.captchaDir)

    def test_extractClientSolution(self):
        """A (challenge, sollution) pair extracted from a request resulting
        from a POST should have the same unmodified (challenge, sollution) as
        the client originally POSTed.
        """
        expectedChallenge = '23232323232323232323'
        expectedResponse = 'awefawefaefawefaewf'

        self.request.method = b'POST'
        self.request.addArg('captcha_challenge_field', expectedChallenge)
        self.request.addArg('captcha_response_field', expectedResponse)

        response = self.captchaResource.extractClientSolution(self.request)
        (challenge, response) = response
        self.assertEqual(challenge, expectedChallenge)
        self.assertEqual(response, expectedResponse)

    def test_checkSolution(self):
        """checkSolution() should return False is the solution is invalid."""
        expectedChallenge = '23232323232323232323'
        expectedResponse = 'awefawefaefawefaewf'

        self.request.method = b'POST'
        self.request.addArg('captcha_challenge_field', expectedChallenge)
        self.request.addArg('captcha_response_field', expectedResponse)

        valid = self.captchaResource.checkSolution(self.request)
        self.assertFalse(valid)

    def test_getCaptchaImage(self):
        """Retrieving a (captcha, challenge) pair with an empty captchaDir
        should return None for both of the (captcha, challenge) strings.
        """
        self.request.method = b'GET'
        response = self.captchaResource.getCaptchaImage(self.request)
        (image, challenge) = response
        # Because we created the directory, there weren't any CAPTCHAs to
        # retrieve from it:
        self.assertIs(image, None)
        self.assertIs(challenge, None)

    def test_getCaptchaImage_noCaptchaDir(self):
        """Retrieving a (captcha, challenge) with an missing captchaDir should
        raise a bridgedb.captcha.GimpCaptchaError.
        """
        shutil.rmtree(self.captchaDir)
        self.request.method = b'GET'
        self.assertRaises(HTTPServer.captcha.GimpCaptchaError,
                          self.captchaResource.getCaptchaImage, self.request)

    def test_render_GET_missingTemplate(self):
        """render_GET() with a missing template should raise an error and
        return the result of replaceErrorPage().
        """
        oldLookup = HTTPServer.lookup
        try:
            HTTPServer.lookup = None
            self.request.method = b'GET'
            page = self.captchaResource.render_GET(self.request)
            errorPage = HTTPServer.replaceErrorPage(Exception('kablam'))
            self.assertEqual(page, errorPage)
        finally:
            HTTPServer.lookup = oldLookup

    def test_render_POST_blankFields(self):
        """render_POST() with a blank 'captcha_response_field' should return
        a redirect to the CaptchaProtectedResource page.
        """
        self.request.method = b'POST'
        self.request.addArg('captcha_challenge_field', '')
        self.request.addArg('captcha_response_field', '')

        page = self.captchaResource.render_POST(self.request)
        self.assertEqual(BeautifulSoup(page).find('meta')['http-equiv'],
                         'refresh')

    def test_render_POST_wrongSolution(self):
        """render_POST() with a wrong 'captcha_response_field' should return
        a redirect to the CaptchaProtectedResource page.
        """
        expectedChallenge = '23232323232323232323'
        expectedResponse = 'awefawefaefawefaewf'

        self.request.method = b'POST'
        self.request.addArg('captcha_challenge_field', expectedChallenge)
        self.request.addArg('captcha_response_field', expectedResponse)

        page = self.captchaResource.render_POST(self.request)
        self.assertEqual(BeautifulSoup(page).find('meta')['http-equiv'],
                         'refresh')


class ReCaptchaProtectedResourceTests(unittest.TestCase):
    """Tests for :mod:`bridgedb.HTTPServer.ReCaptchaProtectedResource`."""

    def setUp(self):
        """Create a :class:`HTTPServer.WebResourceBridges` and protect it with
        a :class:`ReCaptchaProtectedResource`.
        """
        self.timeout = 10.0  # Can't take longer than that, right?
        # Set up our resources to fake a minimal HTTP(S) server:
        self.pagename = b'captcha.html'
        self.root = Resource()
        # (None, None) is the (distributor, scheduleInterval):
        self.protectedResource = HTTPServer.WebResourceBridges(None, None)
        self.captchaResource = HTTPServer.ReCaptchaProtectedResource(
            publicKey='23',
            secretKey='42',
            remoteIP='111.111.111.111',
            useForwardedHeader=True,
            protectedResource=self.protectedResource)

        self.root.putChild(self.pagename, self.captchaResource)

        # Set up the basic parts of our faked request:
        self.request = DummyRequest([self.pagename])

    def tearDown(self):
        """Cleanup method for removing timed out connections on the reactor.

        This seems to be the solution for the dirty reactor due to
        ``DelayedCall``s which is mentioned at the beginning of this
        file. There doesn't seem to be any documentation anywhere which
        proposes this solution, although this seems to solve the problem.
        """
        for delay in reactor.getDelayedCalls():
            try:
                delay.cancel()
            except (AlreadyCalled, AlreadyCancelled):
                pass

    def test_renderDeferred_invalid(self):
        """:meth:`_renderDeferred` should redirect a ``Request`` (after the
        CAPTCHA was NOT xsuccessfully solved) which results from a
        ``Deferred``'s callback.
        """
        self.request.method = b'POST'

        def testCB(request):
            """Check the ``Request`` returned from ``_renderDeferred``."""
            self.assertIsInstance(request, DummyRequest)
            soup = BeautifulSoup(b''.join(request.written)).find('meta')['http-equiv']
            self.assertEqual(soup, 'refresh')

        d = task.deferLater(reactor, 0, lambda x: x, (False, self.request))
        d.addCallback(self.captchaResource._renderDeferred)
        d.addCallback(testCB)
        return d

    def test_renderDeferred_valid(self):
        """:meth:`_renderDeferred` should correctly render a ``Request`` (after
        the CAPTCHA has been successfully solved) which results from a
        ``Deferred``'s callback.
        """
        self.request.method = b'POST'

        def testCB(request):
            """Check the ``Request`` returned from ``_renderDeferred``."""
            self.assertIsInstance(request, DummyRequest)
            html = b''.join(request.written)
            self.assertSubstring('Uh oh, spaghettios!', html)

        d = task.deferLater(reactor, 0, lambda x: x, (True, self.request))
        d.addCallback(self.captchaResource._renderDeferred)
        d.addCallback(testCB)
        return d

    def test_renderDeferred_nontuple(self):
        """:meth:`_renderDeferred` should correctly render a ``Request`` (after
        the CAPTCHA has been successfully solved) which results from a
        ``Deferred``'s callback.
        """
        self.request.method = b'POST'

        def testCB(request):
            """Check the ``Request`` returned from ``_renderDeferred``."""
            self.assertIs(request, None)

        d = task.deferLater(reactor, 0, lambda x: x, (self.request))
        d.addCallback(self.captchaResource._renderDeferred)
        d.addCallback(testCB)
        return d

    def test_checkSolution_blankFields(self):
        """:meth:`HTTPServer.ReCaptchaProtectedResource.checkSolution` should
        return a redirect if is the solution field is blank.
        """
        self.request.method = b'POST'
        self.request.addArg('captcha_challenge_field', '')
        self.request.addArg('captcha_response_field', '')

        self.assertEqual((False, self.request),
                         self.successResultOf(
                             self.captchaResource.checkSolution(self.request)))

    def test_getRemoteIP_useRandomIP(self):
        """Check that removing our remoteip setting produces a random IP."""
        self.captchaResource.remoteIP = None
        ip = self.captchaResource.getRemoteIP()
        realishIP = ipaddr.IPv4Address(ip).compressed
        self.assertTrue(realishIP)
        self.assertNotEquals(realishIP, '111.111.111.111')

    def test_getRemoteIP_useConfiguredIP(self):
        """Check that our remoteip setting is used if configured."""
        ip = self.captchaResource.getRemoteIP()
        realishIP = ipaddr.IPv4Address(ip).compressed
        self.assertTrue(realishIP)
        self.assertEquals(realishIP, '111.111.111.111')

    def test_render_GET_missingTemplate(self):
        """render_GET() with a missing template should raise an error and
        return the result of replaceErrorPage().
        """
        oldLookup = HTTPServer.lookup
        try:
            HTTPServer.lookup = None
            self.request.method = b'GET'
            page = self.captchaResource.render_GET(self.request)
            errorPage = HTTPServer.replaceErrorPage(Exception('kablam'))
            self.assertEqual(page, errorPage)
        finally:
            HTTPServer.lookup = oldLookup

    def test_render_POST_blankFields(self):
        """render_POST() with a blank 'captcha_response_field' should return
        a redirect to the CaptchaProtectedResource page.
        """
        self.request.method = b'POST'
        self.request.addArg('captcha_challenge_field', '')
        self.request.addArg('captcha_response_field', '')

        page = self.captchaResource.render_POST(self.request)
        self.assertEqual(page, HTTPServer.server.NOT_DONE_YET)

    def test_render_POST_wrongSolution(self):
        """render_POST() with a wrong 'captcha_response_field' should return
        a redirect to the CaptchaProtectedResource page.
        """
        expectedChallenge = '23232323232323232323'
        expectedResponse = 'awefawefaefawefaewf'

        self.request.method = b'POST'
        self.request.addArg('captcha_challenge_field', expectedChallenge)
        self.request.addArg('captcha_response_field', expectedResponse)

        page = self.captchaResource.render_POST(self.request)
        self.assertEqual(page, HTTPServer.server.NOT_DONE_YET)


class DummyBridge(object):
    """A mock :class:`bridgedb.Bridges.Bridge` which only supports a mocked
    ``getConfigLine`` method."""

    def _randORPort(self): return random.randint(9001, 9999)
    def _randPTPort(self): return random.randint(6001, 6666)
    def _returnFour(self): return random.randint(2**24, 2**32-1)
    def _returnSix(self): return random.randint(2**24, 2**128-1)

    def __init__(self, transports=[]):
        """Create a mocked bridge suitable for testing distributors and web
        resource rendering.
        """
        self.nickname = "bridge-{0}".format(self._returnFour())
        self.ip = ipaddr.IPv4Address(self._returnFour())
        self.orport = self._randORPort()
        self.transports = transports
        self.running = True
        self.stable = True
        self.blockingCountries = {}
        self.desc_digest = None
        self.ei_digest = None
        self.verified = False
        self.fingerprint = "".join(random.choice('abcdef0123456789')
                                   for _ in xrange(40))
        self.or_addresses = {ipaddr.IPv6Address(self._returnSix()):
                             self._randORPort()}

    def getConfigLine(self, includeFingerprint=True,
                      addressClass=ipaddr.IPv4Address,
                      transport=None,
                      request=None):
        """Get a "torrc" bridge config line to give to a client."""
        line = []
        if transport is not None:
            #print("getConfigLine got transport=%r" % transport)
            line.append(str(transport))
        line.append("%s:%s" % (self.ip, self.orport))
        if includeFingerprint is True: line.append(self.fingerprint)
        bridgeLine = " ".join([item for item in line])
        #print "Created config line: %r" % bridgeLine
        return bridgeLine


class DummyIPBasedDistributor(object):
    """A mocked :class:`bridgedb.Dist.IPBasedDistributor` which is used to test
    :class:`bridgedb.HTTPServer.WebResourceBridges.
    """

    def _dumbAreaMapper(ip): return ip

    def __init__(self, areaMapper=None, nClusters=None, key=None,
                 ipCategories=None, answerParameters=None):
        """None of the parameters are really used, they are just there to retain
        an identical method signature.
        """
        self.areaMapper = self._dumbAreaMapper
        self.nClusters = 3
        self.nBridgesToGive = 3
        self.key = self.__class__.__name__
        self.ipCategories = ipCategories
        self.answerParameters = answerParameters

    def getBridgesForIP(self, ip=None, epoch=None, N=1,
                        countyCode=None, bridgeFilterRules=None):
        """Needed because it's called in
        :meth:`WebResourceBridges.getBridgesForIP`.
        """
        return [DummyBridge() for _ in xrange(N)]


class DummyRequest(requesthelper.DummyRequest):
    """Wrapper for :api:`twisted.test.requesthelper.DummyRequest` to add
    redirect support.
    """

    def __init__(self, *args, **kwargs):
        requesthelper.DummyRequest.__init__(self, *args, **kwargs)
        self.redirect = self._redirect(self)

    def URLPath(self):
        """Fake the missing Request.URLPath too."""
        return self.uri

    def _redirect(self, request):
        """Stub method to add a redirect() method to DummyResponse."""
        newRequest = type(request)
        newRequest.uri = request.uri
        return newRequest


class WebResourceBridgesTests(unittest.TestCase):
    """Tests for :class:`HTTPServer.WebResourceBridges`."""

    def setUp(self):
        """Set up our resources to fake a minimal HTTP(S) server."""
        self.pagename = b'bridges.html'
        self.root = Resource()

        self.dist = DummyIPBasedDistributor()
        self.sched = ScheduledInterval('hour', 1)
        self.nBridgesPerRequest = 2
        self.bridgesResource = HTTPServer.WebResourceBridges(
            self.dist, self.sched, N=2,
            #useForwardedHeader=True,
            includeFingerprints=True)

        self.root.putChild(self.pagename, self.bridgesResource)

    def parseBridgesFromHTMLPage(self, page):
        """Utility to pull the bridge lines out of an HTML response page.

        :param str page: A rendered HTML page, as a string.
        :raises: Any error which might occur.
        :rtype: list
        :returns: A list of the bridge lines contained on the **page**.
        """
        # The bridge lines are contained in a <div class='bridges'> tag:
        soup = BeautifulSoup(page)
        well = soup.find('div', {'class': 'bridge-lines'})
        content = well.renderContents().strip()
        lines = content.splitlines()

        bridges = []
        for line in lines:
            bridgelines = line.split('<br />')
            for bridge in bridgelines:
                if bridge:  # It still could be an empty string at this point
                    bridges.append(bridge)

        return bridges

    def test_render_GET_vanilla(self):
        """Test rendering a request for normal, vanilla bridges."""
        request = DummyRequest([self.pagename])
        request.method = b'GET'
        request.getClientIP = lambda: '1.1.1.1'

        page = self.bridgesResource.render(request)

        # The response should explain how to use the bridge lines:
        self.assertTrue("To enter bridges into Tor Browser" in str(page))

        for b in self.parseBridgesFromHTMLPage(page):
            # Check that each bridge line had the expected number of fields:
            fields = b.split(' ')
            self.assertEqual(len(fields), 2)

            # Check that the IP and port seem okay:
            ip, port = fields[0].rsplit(':')
            self.assertIsInstance(ipaddr.IPv4Address(ip), ipaddr.IPv4Address)
            self.assertIsInstance(int(port), int)
            self.assertGreater(int(port), 0)
            self.assertLessEqual(int(port), 65535)

    def test_render_GET_XForwardedFor(self):
        """The client's IP address should be obtainable from the
        'X-Forwarded-For' header in the request.
        """
        self.bridgesResource.useForwardedHeader = True
        request = DummyRequest([self.pagename])
        request.method = b'GET'
        # Since we do not set ``request.getClientIP`` here like we do in some
        # of the other unittests, an exception would be raised here if
        # ``getBridgesForRequest()`` is unable to get the IP address from this
        # 'X-Forwarded-For' header (because ``ip`` would get set to ``None``).
        request.headers.update({'x-forwarded-for': '2.2.2.2'})

        page = self.bridgesResource.render(request)
        self.bridgesResource.useForwardedHeader = False  # Reset it

        # The response should explain how to use the bridge lines:
        self.assertTrue("To enter bridges into Tor Browser" in str(page))

    def test_render_GET_RTLlang(self):
        """Test rendering a request for plain bridges in Arabic."""
        request = DummyRequest([b"bridges?transport=obfs3"])
        request.method = b'GET'
        request.getClientIP = lambda: '3.3.3.3'
        # For some strange reason, the 'Accept-Language' value *should not* be
        # a list, unlike all the other headers and args…
        request.headers.update({'accept-language': 'ar,en,en_US,'})

        page = self.bridgesResource.render(request)
        self.assertSubstring("direction: rtl", page)
        self.assertSubstring(
            # "I need an alternative way to get bridges!"
            "أحتاج إلى وسيلة بديلة للحصول على bridges", page)

        for bridgeLine in self.parseBridgesFromHTMLPage(page):
            # Check that each bridge line had the expected number of fields:
            bridgeLine = bridgeLine.split(' ')
            self.assertEqual(len(bridgeLine), 2)

    def test_render_GET_RTLlang_obfs3(self):
        """Test rendering a request for obfs3 bridges in Farsi."""
        request = DummyRequest([b"bridges?transport=obfs3"])
        request.method = b'GET'
        request.getClientIP = lambda: '3.3.3.3'
        request.headers.update({'accept-language': 'fa,en,en_US,'})
        # We actually have to set the request args manually when using a
        # DummyRequest:
        request.args.update({'transport': ['obfs3']})

        page = self.bridgesResource.render(request)
        self.assertSubstring("direction: rtl", page)
        self.assertSubstring(
            # "How to use the above bridge lines" (since there should be
            # bridges in this response, we don't tell them about alternative
            # mechanisms for getting bridges)
            "چگونگی از پل‌های خود استفاده کنید", page)

        for bridgeLine in self.parseBridgesFromHTMLPage(page):
            # Check that each bridge line had the expected number of fields:
            bridgeLine = bridgeLine.split(' ')
            self.assertEqual(len(bridgeLine), 3)
            self.assertEqual(bridgeLine[0], 'obfs3')

            # Check that the IP and port seem okay:
            ip, port = bridgeLine[1].rsplit(':')
            self.assertIsInstance(ipaddr.IPv4Address(ip), ipaddr.IPv4Address)
            self.assertIsInstance(int(port), int)
            self.assertGreater(int(port), 0)
            self.assertLessEqual(int(port), 65535)


    def test_renderAnswer_textplain(self):
        """If the request format specifies 'plain', we should return content
        with mimetype 'text/plain'.
        """
        request = DummyRequest([self.pagename])
        request.args.update({'format': ['plain']})
        request.getClientIP = lambda: '4.4.4.4'
        request.method = b'GET'

        page = self.bridgesResource.render(request)
        self.assertTrue("html" not in str(page))

        # We just need to strip and split it because it looks like:
        #
        #   94.235.85.233:9492 0d9d0547c3471cddc473f7288a6abfb54562dc06
        #   255.225.204.145:9511 1fb89d618b3a12afe3529fd072127ea08fb50466
        #
        # (Yes, there are two leading spaces at the beginning of each line)
        #
        bridgeLines = [line.strip() for line in page.strip().split('\n')]

        for bridgeLine in bridgeLines:
            bridgeLine = bridgeLine.split(' ')
            self.assertEqual(len(bridgeLine), 2)

            # Check that the IP and port seem okay:
            ip, port = bridgeLine[0].rsplit(':')
            self.assertIsInstance(ipaddr.IPv4Address(ip), ipaddr.IPv4Address)
            self.assertIsInstance(int(port), int)
            self.assertGreater(int(port), 0)
            self.assertLessEqual(int(port), 65535)


class WebResourceOptionsTests(unittest.TestCase):
    """Tests for :class:`bridgedb.HTTPServer.WebResourceOptions`."""

    def setUp(self):
        """Create a :class:`HTTPServer.WebResourceOptions`."""
        # Set up our resources to fake a minimal HTTP(S) server:
        self.pagename = b'options.html'
        self.root = Resource()
        self.optionsResource = HTTPServer.WebResourceOptions()
        self.root.putChild(self.pagename, self.optionsResource)

    def test_render_GET_RTLlang(self):
        """Test rendering a request for obfs3 bridges in Arabic."""
        request = DummyRequest(["bridges?transport=obfs3"])
        request.method = b'GET'
        request.getClientIP = lambda: '3.3.3.3'
        request.headers.update({'accept-language': 'he'})
        # We actually have to set the request args manually when using a
        # DummyRequest:
        request.args.update({'transport': ['obfs2']})

        page = self.optionsResource.render(request)
        self.assertSubstring("direction: rtl", page)
        self.assertSubstring("מהם גשרים?", page)

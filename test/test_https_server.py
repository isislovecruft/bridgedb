# -*- coding: utf-8 -*-
#_____________________________________________________________________________
#
# This file is part of BridgeDB, a Tor bridge distribution system.
#
# :authors: Isis Lovecruft 0xA3ADB67A2CDB8B35 <isis@torproject.org>
# :copyright: (c) 2014-2015, Isis Lovecruft
#             (c) 2014-2015, The Tor Project, Inc.
# :license: see LICENSE for licensing information
#_____________________________________________________________________________

"""Unittests for :mod:`bridgedb.https.server`."""

from __future__ import print_function

import logging
import os
import shutil

import ipaddr

from BeautifulSoup import BeautifulSoup

from twisted.internet import reactor
from twisted.internet import task
from twisted.trial import unittest
from twisted.web.resource import Resource
from twisted.web.test import requesthelper

from bridgedb.https import server
from bridgedb.schedule import ScheduledInterval

from .https_helpers import _createConfig
from .https_helpers import DummyRequest
from .https_helpers import DummyHTTPSDistributor
from .util import DummyBridge
from .util import DummyMaliciousBridge


# For additional logger output for debugging, comment out the following:
logging.disable(50)
# and then uncomment the following line:
#server.logging.getLogger().setLevel(10)


class SetFQDNTests(unittest.TestCase):
    """Tests for :func:`bridgedb.https.server.setFQDN` and
    :func:`bridgedb.https.server.setFQDN`.
    """

    def setUp(self):
        self.originalFQDN = server.SERVER_PUBLIC_FQDN

    def tearDown(self):
        server.SERVER_PUBLIC_FQDN = self.originalFQDN

    def test_setFQDN_https(self):
        """Calling ``server.setFQDN([…], https=True)`` should prepend
        ``"https://"`` to the module :data:`server.SERVER_PUBLIC_FQDN`
        variable.
        """
        server.setFQDN('example.com', https=True)
        self.assertEqual(server.SERVER_PUBLIC_FQDN, "https://example.com")

    def test_setFQDN_http(self):
        """Calling ``server.setFQDN([…], https=False)`` should not prepend
        anything at all to the module :data:`server.SERVER_PUBLIC_FQDN`
        variable.
        """
        server.setFQDN('example.com', https=False)
        self.assertEqual(server.SERVER_PUBLIC_FQDN, "example.com")


class GetClientIPTests(unittest.TestCase):
    """Tests for :func:`bridgedb.https.server.getClientIP`."""

    def createRequestWithIPs(self):
        """Set the IP address returned from ``request.getClientIP()`` to
        '3.3.3.3', and the IP address reported in the 'X-Forwarded-For' header
        to '2.2.2.2'.
        """
        request = DummyRequest([''])
        request.headers.update({'x-forwarded-for': '2.2.2.2'})
        # See :api:`twisted.test.requesthelper.DummyRequest.getClientIP`
        request.client = requesthelper.IPv4Address('TCP', '3.3.3.3', 443)
        request.method = b'GET'
        return request

    def test_getClientIP_XForwardedFor(self):
        """getClientIP() should return the IP address from the
        'X-Forwarded-For' header when ``useForwardedHeader=True``.
        """
        request = self.createRequestWithIPs()
        clientIP = server.getClientIP(request, useForwardedHeader=True)
        self.assertEqual(clientIP, '2.2.2.2')

    def test_getClientIP_XForwardedFor_bad_ip(self):
        """getClientIP() should return None if the IP address from the
        'X-Forwarded-For' header is bad/invalid and
        ``useForwardedHeader=True``.
        """
        request = self.createRequestWithIPs()
        request.headers.update({'x-forwarded-for': 'pineapple'})
        clientIP = server.getClientIP(request, useForwardedHeader=True)
        self.assertEqual(clientIP, None)

    def test_getClientIP_fromRequest(self):
        """getClientIP() should return the IP address from the request instance
        when ``useForwardedHeader=False``.
        """
        request = self.createRequestWithIPs()
        clientIP = server.getClientIP(request)
        self.assertEqual(clientIP, '3.3.3.3')


class ReplaceErrorPageTests(unittest.TestCase):
    """Tests for :func:`bridgedb.https.server.replaceErrorPage`."""

    def setUp(self):
        self.resource500 = server.resource500

    def tearDown(self):
        server.resource500 = self.resource500

    def test_replaceErrorPage(self):
        """``replaceErrorPage`` should return the error-500.html page."""
        request = DummyRequest([''])
        exc = Exception("vegan gümmibären")
        errorPage = server.replaceErrorPage(request, exc)
        self.assertSubstring("Bad News Bears", errorPage)
        self.assertNotSubstring("vegan gümmibären", errorPage)

    def test_replaceErrorPage_matches_resource500(self):
        """``replaceErrorPage`` should return the error-500.html page."""
        request = DummyRequest([''])
        exc = Exception("vegan gümmibären")
        errorPage = server.replaceErrorPage(request, exc)
        error500Page = server.resource500.render(request)
        self.assertEqual(errorPage, error500Page)

    def test_replaceErrorPage_no_resource500(self):
        """If ``server.resource500`` is missing/broken, then
        ``replaceErrorPage`` should return custom hardcoded HTML error text.
        """
        request = DummyRequest([''])
        exc = Exception("vegan gümmibären")
        server.resource500 = None
        errorPage = server.replaceErrorPage(request, exc)
        self.assertNotSubstring("Bad News Bears", errorPage)
        self.assertNotSubstring("vegan gümmibären", errorPage)
        self.assertSubstring("Sorry! Something went wrong with your request.",
                             errorPage)

class ErrorResourceTests(unittest.TestCase):
    """Tests for :class:`bridgedb.https.server.ErrorResource`."""

    def setUp(self):
        self.request = DummyRequest([''])

    def test_resource404(self):
        """``server.resource404`` should display the error-404.html page."""
        page = server.resource404.render(self.request)
        self.assertSubstring('We dug around for the page you requested', page)

    def test_resource500(self):
        """``server.resource500`` should display the error-500.html page."""
        page = server.resource500.render(self.request)
        self.assertSubstring('Bad News Bears', page)

    def test_maintenance(self):
        """``server.maintenance`` should display the error-503.html page."""
        page = server.maintenance.render(self.request)
        self.assertSubstring('Under Maintenance', page)


class CustomErrorHandlingResourceTests(unittest.TestCase):
    """Tests for :class:`bridgedb.https.server.CustomErrorHandlingResource`."""

    def test_getChild(self):
        """``CustomErrorHandlingResource.getChild`` should return a rendered
        copy of ``server.resource404``.
        """
        request = DummyRequest([''])
        resource = server.CustomErrorHandlingResource()
        self.assertEqual(server.resource404, resource.getChild('foobar', request))


class CSPResourceTests(unittest.TestCase):
    """Tests for :class:`bridgedb.HTTPServer.CSPResource`."""

    def setUp(self):
        self.pagename = b'foo.html'
        self.request = DummyRequest([self.pagename])
        self.request.method = b'GET'

        server.setFQDN('bridges.torproject.org')

    def test_CSPResource_setCSPHeader(self):
        """Setting the CSP header on a request should work out just peachy,
        like no errors or other bad stuff happening.
        """
        resource = server.CSPResource()
        resource.setCSPHeader(self.request)

    def test_render_POST_ascii(self):
        """Calling ``CSPResource.render_POST()`` should log whatever stuff was
        sent in the body of the POST request.
        """
        self.request.method = b'POST'
        self.request.writeContent('lah dee dah')
        self.request.client = requesthelper.IPv4Address('TCP', '3.3.3.3', 443)

        resource = server.CSPResource()
        page = resource.render_POST(self.request)

        self.assertIn('<html>', str(page))

    def test_render_POST_no_client_IP(self):
        """Calling ``CSPResource.render_POST()`` should log whatever stuff was
        sent in the body of the POST request, regardless of whether we were
        able to determine the client's IP address.
        """
        self.request.method = b'POST'
        self.request.writeContent('lah dee dah')

        resource = server.CSPResource()
        page = resource.render_POST(self.request)

        self.assertIn('<html>', str(page))

    def test_render_POST_unicode(self):
        """Calling ``CSPResource.render_POST()`` should log whatever stuff was
        sent in the body of the POST request, even if it's unicode.
        """
        self.request.method = b'POST'
        self.request.writeContent(
            ('南京大屠杀是中国抗日战争初期侵华日军在中华民国首都南京犯下的'
             '大規模屠殺、強姦以及纵火、抢劫等战争罪行与反人类罪行。'))
        self.request.client = requesthelper.IPv4Address('TCP', '3.3.3.3', 443)

        resource = server.CSPResource()
        page = resource.render_POST(self.request)

        self.assertIn('<html>', str(page))

    def test_render_POST_weird_request(self):
        """Calling ``CSPResource.render_POST()`` without a strange content
        object which doesn't have a ``content`` attribute should trigger the
        ``except Exception`` clause.
        """
        self.request.method = b'GET'
        del self.request.content

        resource = server.CSPResource()
        page = resource.render_POST(self.request)

        self.assertIn('<html>', str(page))


class IndexResourceTests(unittest.TestCase):
    """Test for :class:`bridgedb.https.server.IndexResource`."""

    def setUp(self):
        self.pagename = ''
        self.indexResource = server.IndexResource()
        self.root = Resource()
        self.root.putChild(self.pagename, self.indexResource)

    def test_IndexResource_render_GET(self):
        """renderGet() should return the index page."""
        request = DummyRequest([self.pagename])
        request.method = b'GET'
        page = self.indexResource.render_GET(request)
        self.assertSubstring("add the bridges to Tor Browser", page)

    def test_IndexResource_render_GET_lang_ta(self):
        """renderGet() with ?lang=ta should return the index page in Tamil."""
        request = DummyRequest([self.pagename])
        request.method = b'GET'
        request.addArg('lang', 'ta')
        page = self.indexResource.render_GET(request)
        self.assertSubstring("bridge-களை Tor Browser-உள்", page)


class HowtoResourceTests(unittest.TestCase):
    """Test for :class:`bridgedb.https.server.HowtoResource`."""

    def setUp(self):
        self.pagename = 'howto.html'
        self.howtoResource = server.HowtoResource()
        self.root = Resource()
        self.root.putChild(self.pagename, self.howtoResource)

    def test_HowtoResource_render_GET(self):
        """renderGet() should return the howto page."""
        request = DummyRequest([self.pagename])
        request.method = b'GET'
        page = self.howtoResource.render_GET(request)
        self.assertSubstring("the wizard", page)

    def test_HowtoResource_render_GET_lang_ru(self):
        """renderGet() with ?lang=ru should return the howto page in Russian."""
        request = DummyRequest([self.pagename])
        request.method = b'GET'
        request.addArg('lang', 'ru')
        page = self.howtoResource.render_GET(request)
        self.assertSubstring("следуйте инструкциям установщика", page)


class CaptchaProtectedResourceTests(unittest.TestCase):
    """Tests for :class:`bridgedb.https.server.CaptchaProtectedResource`."""

    def setUp(self):
        self.dist = None
        self.sched = None
        self.pagename = b'bridges.html'
        self.root = Resource()
        self.protectedResource = server.BridgesResource(self.dist, self.sched)
        self.captchaResource = server.CaptchaProtectedResource(
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
        oldLookup = server.lookup
        try:
            server.lookup = None
            request = DummyRequest([self.pagename])
            request.method = b'GET'
            page = self.captchaResource.render_GET(request)
            errorPage = server.replaceErrorPage(request, Exception('kablam'))
            self.assertEqual(page, errorPage)
        finally:
            server.lookup = oldLookup

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
    """Tests for :mod:`bridgedb.https.server.GimpCaptchaProtectedResource`."""

    def setUp(self):
        """Create a :class:`server.BridgesResource` and protect it with
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
        self.protectedResource = server.BridgesResource(None, None)
        self.captchaResource = server.GimpCaptchaProtectedResource(
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
        self.assertRaises(server.captcha.GimpCaptchaError,
                          self.captchaResource.getCaptchaImage, self.request)

    def test_render_GET_missingTemplate(self):
        """render_GET() with a missing template should raise an error and
        return the result of replaceErrorPage().
        """
        oldLookup = server.lookup
        try:
            server.lookup = None
            self.request.method = b'GET'
            page = self.captchaResource.render_GET(self.request)
            errorPage = server.replaceErrorPage(self.request, Exception('kablam'))
            self.assertEqual(page, errorPage)
        finally:
            server.lookup = oldLookup

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
    """Tests for :mod:`bridgedb.https.server.ReCaptchaProtectedResource`."""

    def setUp(self):
        """Create a :class:`server.BridgesResource` and protect it with
        a :class:`ReCaptchaProtectedResource`.
        """
        self.timeout = 10.0  # Can't take longer than that, right?
        # Set up our resources to fake a minimal HTTP(S) server:
        self.pagename = b'captcha.html'
        self.root = Resource()
        # (None, None) is the (distributor, scheduleInterval):
        self.protectedResource = server.BridgesResource(None, None)
        self.captchaResource = server.ReCaptchaProtectedResource(
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
        """:meth:`server.ReCaptchaProtectedResource.checkSolution` should
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
        oldLookup = server.lookup
        try:
            server.lookup = None
            self.request.method = b'GET'
            page = self.captchaResource.render_GET(self.request)
            errorPage = server.replaceErrorPage(self.request, Exception('kablam'))
            self.assertEqual(page, errorPage)
        finally:
            server.lookup = oldLookup

    def test_render_POST_blankFields(self):
        """render_POST() with a blank 'captcha_response_field' should return
        a redirect to the CaptchaProtectedResource page.
        """
        self.request.method = b'POST'
        self.request.addArg('captcha_challenge_field', '')
        self.request.addArg('captcha_response_field', '')

        page = self.captchaResource.render_POST(self.request)
        self.assertEqual(page, server.NOT_DONE_YET)

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
        self.assertEqual(page, server.NOT_DONE_YET)


class BridgesResourceTests(unittest.TestCase):
    """Tests for :class:`https.server.BridgesResource`."""

    def setUp(self):
        """Set up our resources to fake a minimal HTTP(S) server."""
        self.pagename = b'bridges.html'
        self.root = Resource()

        self.dist = DummyHTTPSDistributor()
        self.sched = ScheduledInterval(1, 'hour')
        self.nBridgesPerRequest = 2

    def useBenignBridges(self):
        self.dist._bridge_class = DummyBridge
        self.bridgesResource = server.BridgesResource(
            self.dist, self.sched, N=self.nBridgesPerRequest,
            includeFingerprints=True)
        self.root.putChild(self.pagename, self.bridgesResource)

    def useMaliciousBridges(self):
        self.dist._bridge_class = DummyMaliciousBridge
        self.bridgesResource = server.BridgesResource(
            self.dist, self.sched, N=self.nBridgesPerRequest,
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

    def test_render_GET_malicious_newlines(self):
        """Test rendering a request when the some of the bridges returned have
        malicious (HTML, Javascript, etc., in their) PT arguments.
        """
        self.useMaliciousBridges()

        request = DummyRequest([self.pagename])
        request.method = b'GET'
        request.getClientIP = lambda: '1.1.1.1'

        page = self.bridgesResource.render(request)
        self.assertTrue(
            'bad=Bridge 6.6.6.6:6666 0123456789abcdef0123456789abcdef01234567' in str(page),
            "Newlines in bridge lines should be removed.")

    def test_render_GET_malicious_returnchar(self):
        """Test rendering a request when the some of the bridges returned have
        malicious (HTML, Javascript, etc., in their) PT arguments.
        """
        self.useMaliciousBridges()

        request = DummyRequest([self.pagename])
        request.method = b'GET'
        request.getClientIP = lambda: '1.1.1.1'

        page = self.bridgesResource.render(request)
        self.assertTrue(
            'eww=Bridge 1.2.3.4:1234' in str(page),
            "Return characters in bridge lines should be removed.")

    def test_render_GET_malicious_javascript(self):
        """Test rendering a request when the some of the bridges returned have
        malicious (HTML, Javascript, etc., in their) PT arguments.
        """
        self.useMaliciousBridges()

        request = DummyRequest([self.pagename])
        request.method = b'GET'
        request.getClientIP = lambda: '1.1.1.1'

        page = self.bridgesResource.render(request)
        self.assertTrue(
            "evil=&lt;script&gt;alert(&#39;fuuuu&#39;);&lt;/script&gt;" in str(page),
            ("The characters &, <, >, ', and \" in bridge lines should be "
             "replaced with their corresponding HTML special characters."))

    def test_renderAnswer_GET_textplain_malicious(self):
        """If the request format specifies 'plain', we should return content
        with mimetype 'text/plain' and ASCII control characters replaced.
        """
        self.useMaliciousBridges()

        request = DummyRequest([self.pagename])
        request.args.update({'format': ['plain']})
        request.getClientIP = lambda: '4.4.4.4'
        request.method = b'GET'

        page = self.bridgesResource.render(request)
        self.assertTrue("html" not in str(page))
        self.assertTrue(
            'eww=Bridge 1.2.3.4:1234' in str(page),
            "Return characters in bridge lines should be removed.")
        self.assertTrue(
            'bad=Bridge 6.6.6.6:6666' in str(page),
            "Newlines in bridge lines should be removed.")

    def test_render_GET_vanilla(self):
        """Test rendering a request for normal, vanilla bridges."""
        self.useBenignBridges()

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
        self.useBenignBridges()

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
        self.useBenignBridges()

        request = DummyRequest([b"bridges?transport=obfs3"])
        request.method = b'GET'
        request.getClientIP = lambda: '3.3.3.3'
        # For some strange reason, the 'Accept-Language' value *should not* be
        # a list, unlike all the other headers and args…
        request.headers.update({'accept-language': 'ar,en,en_US,'})

        page = self.bridgesResource.render(request)
        self.assertSubstring("rtl.css", page)
        self.assertSubstring(
            # "I need an alternative way to get bridges!"
            "أحتاج إلى وسيلة بديلة للحصول على bridges", page)

        for bridgeLine in self.parseBridgesFromHTMLPage(page):
            # Check that each bridge line had the expected number of fields:
            bridgeLine = bridgeLine.split(' ')
            self.assertEqual(len(bridgeLine), 2)

    def test_render_GET_RTLlang_obfs3(self):
        """Test rendering a request for obfs3 bridges in Farsi."""
        self.useBenignBridges()

        request = DummyRequest([b"bridges?transport=obfs3"])
        request.method = b'GET'
        request.getClientIP = lambda: '3.3.3.3'
        request.headers.update({'accept-language': 'fa,en,en_US,'})
        # We actually have to set the request args manually when using a
        # DummyRequest:
        request.args.update({'transport': ['obfs3']})

        page = self.bridgesResource.render(request)
        self.assertSubstring("rtl.css", page)
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
        self.useBenignBridges()

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

    def test_renderAnswer_textplain_error(self):
        """If we hit some error while returning bridge lines in text/plain
        format, then our custom plaintext error message (the hardcoded HTML in
        ``server.replaceErrorPage``) should be returned.
        """
        self.useBenignBridges()

        request = DummyRequest([self.pagename])
        request.args.update({'format': ['plain']})
        request.getClientIP = lambda: '4.4.4.4'
        request.method = b'GET'

        # We'll cause a TypeError here due to calling '\n'.join(None)
        page = self.bridgesResource.renderAnswer(request, bridgeLines=None)

        # We don't want the fancy version:
        self.assertNotSubstring("Bad News Bears", page)
        self.assertSubstring("Sorry! Something went wrong with your request.",
                             page)


class OptionsResourceTests(unittest.TestCase):
    """Tests for :class:`bridgedb.https.server.OptionsResource`."""

    def setUp(self):
        """Create a :class:`server.OptionsResource`."""
        # Set up our resources to fake a minimal HTTP(S) server:
        self.pagename = b'options.html'
        self.root = Resource()
        self.optionsResource = server.OptionsResource()
        self.root.putChild(self.pagename, self.optionsResource)

    def test_render_GET_RTLlang(self):
        """Test rendering a request for obfs3 bridges in Hebrew."""
        request = DummyRequest(["bridges?transport=obfs3"])
        request.method = b'GET'
        request.getClientIP = lambda: '3.3.3.3'
        request.headers.update({'accept-language': 'he'})
        # We actually have to set the request args manually when using a
        # DummyRequest:
        request.args.update({'transport': ['obfs2']})

        page = self.optionsResource.render(request)
        self.assertSubstring("rtl.css", page)
        self.assertSubstring("מהם גשרים?", page)


class HTTPSServerServiceTests(unittest.TestCase):
    """Unittests for :func:`bridgedb.email.server.addWebServer`."""

    def setUp(self):
        """Create a config and an HTTPSDistributor."""
        self.config = _createConfig()
        self.distributor = DummyHTTPSDistributor()

    def tearDown(self):
        """Cleanup method after each ``test_*`` method runs; removes timed out
        connections on the reactor and clears the :ivar:`transport`.

        Basically, kill all connections with fire.
        """
        for delay in reactor.getDelayedCalls():
            try:
                delay.cancel()
            except (AlreadyCalled, AlreadyCancelled):
                pass

        # FIXME: this is definitely not how we're supposed to do this, but it
        # kills the DirtyReactorAggregateErrors.
        reactor.disconnectAll()
        reactor.runUntilCurrent()

    def test_addWebServer_GIMP_CAPTCHA_ENABLED(self):
        """Call :func:`bridgedb.https.server.addWebServer` to test startup."""
        server.addWebServer(self.config, self.distributor)

    def test_addWebServer_RECAPTCHA_ENABLED(self):
        """Call :func:`bridgedb.https.server.addWebServer` to test startup."""
        config = self.config
        config.RECAPTCHA_ENABLED = True
        server.addWebServer(config, self.distributor)

    def test_addWebServer_no_captchas(self):
        """Call :func:`bridgedb.https.server.addWebServer` to test startup."""
        config = self.config
        config.GIMP_CAPTCHA_ENABLED = False
        server.addWebServer(config, self.distributor)

    def test_addWebServer_no_HTTPS_ROTATION_PERIOD(self):
        """Call :func:`bridgedb.https.server.addWebServer` to test startup."""
        config = self.config
        config.HTTPS_ROTATION_PERIOD = None
        server.addWebServer(config, self.distributor)

    def test_addWebServer_CSP_ENABLED_False(self):
        """Call :func:`bridgedb.https.server.addWebServer` with
        ``CSP_ENABLED=False`` to test startup.
        """
        config = self.config
        config.CSP_ENABLED = False
        server.addWebServer(config, self.distributor)

    def test_addWebServer_CSP_REPORT_ONLY_False(self):
        """Call :func:`bridgedb.https.server.addWebServer` with
        ``CSP_REPORT_ONLY=False`` to test startup.
        """
        config = self.config
        config.CSP_REPORT_ONLY = False
        server.addWebServer(config, self.distributor)

    def test_addWebServer_CSP_INCLUDE_SELF_False(self):
        """Call :func:`bridgedb.https.server.addWebServer` with
        ``CSP_INCLUDE_SELF=False`` to test startup.
        """
        config = self.config
        config.CSP_INCLUDE_SELF = False
        server.addWebServer(config, self.distributor)

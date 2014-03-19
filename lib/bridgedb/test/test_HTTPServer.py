# -*- encoding: utf-8 -*-
#_____________________________________________________________________________
#
# This file is part of BridgeDB, a Tor bridge distribution system.
#
# :authors: Isis Lovecruft 0xA3ADB67A2CDB8B35 <isis@torproject.org>
# :copyright: (c) 2014, Isis Lovecruft
#             (c) 2014, The Tor Project, Inc.
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
from twisted.trial import unittest
from twisted.web.resource import Resource
from twisted.web.test import requesthelper

from bridgedb import HTTPServer


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
            useForwardedHeader=True, resource=self.protectedResource)
        self.root.putChild(self.pagename, self.captchaResource)

    def test_render_GET_noCaptcha(self):
        """render_GET() should return a page without a CAPTCHA, which has the
        image alt text.
        """
        request = requesthelper.DummyRequest([self.pagename])
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
            request = requesthelper.DummyRequest([self.pagename])
            request.method = b'GET'
            page = self.captchaResource.render_GET(request)
            errorPage = HTTPServer.replaceErrorPage(Exception('kablam'))
            self.assertEqual(page, errorPage)
        finally:
            HTTPServer.lookup = oldLookup

    def test_getClientIP_XForwardedFor(self):
        """CaptchaProtectedResource.getClientIP() should return the IP address
        from the 'X-Forwarded-For' header when ``useForwardedHeader=True``.
        """
        requestIP = b'6.6.6.6'
        request = requesthelper.DummyRequest([self.pagename])
        request.setHeader(b'X-Forwarded-For', requestIP)
        request.method = b'GET'

        #child = root.getChild(pagename, request)
        page = self.captchaResource.render_GET(request)
        clientIP = self.captchaResource.getClientIP(request)
        #self.assertEquals(requestIP, clientIP)

    def test_render_POST(self):
        """render_POST() with a wrong 'captcha_response_field' should return
        a redirect to the CaptchaProtectedResource page.
        """
        pagename = 'captcha.html'
        self.root.putChild(pagename, self.captchaResource)

        def redirect(request):
            newRequest = type(request)
            newRequest.uri = pagename
            return newRequest

        request = requesthelper.DummyRequest(['captcha.html'])
        request.method = b'POST'
        request.redirect = redirect(request)

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
            resource=self.protectedResource)

        self.root.putChild(self.pagename, self.captchaResource)

        # Set up the basic parts of our faked request:
        self.request = requesthelper.DummyRequest([self.pagename])
        self.request.URLPath = lambda: request.uri # Fake the URLPath too
        self.request.redirect = self.doRedirect(self.request)

    def doRedirect(self, request):
        """Stub method to add a redirect() to DummyResponse."""
        newRequest = type(request)
        newRequest.uri = self.pagename
        return newRequest

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
        # Create our cached CAPTCHA directory:
        self.captchaDir = 'captchas'
        if not os.path.isdir(self.captchaDir):
            os.makedirs(self.captchaDir)

        # Set up our resources to fake a minimal HTTP(S) server:
        self.pagename = b'captcha.html'
        self.root = Resource()
        # (None, None) is the (distributor, scheduleInterval):
        self.protectedResource = HTTPServer.WebResourceBridges(None, None)
        self.captchaResource = HTTPServer.ReCaptchaProtectedResource(
            recaptchaPrivKey='42',
            recaptchaPubKey='23',
            remoteip='111.111.111.111',
            useForwardedHeader=True,
            resource=self.protectedResource)

        self.root.putChild(self.pagename, self.captchaResource)

        # Set up the basic parts of our faked request:
        self.request = requesthelper.DummyRequest([self.pagename])
        self.request.URLPath = lambda: request.uri # Fake the URLPath too
        self.request.redirect = self.doRedirect(self.request)

    def doRedirect(self, request):
        """Stub method to add a redirect() to DummyResponse."""
        newRequest = type(request)
        newRequest.uri = self.pagename
        return newRequest

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

    def test_checkSolution_blankFields(self):
        """:meth:`HTTPServer.ReCaptchaProtectedResource.checkSolution` should
        return a redirect if is the solution field is blank.
        """
        self.request.method = b'POST'
        self.request.addArg('captcha_challenge_field', '')
        self.request.addArg('captcha_response_field', '') 
        
        self.assertIsInstance(
            self.captchaResource.checkSolution(self.request),
            HTTPServer.txrecaptcha.RecaptchaResponse)

    def test_getRemoteIP_useRandomIP(self):
        """Check that removing our remoteip setting produces a random IP."""
        self.captchaResource.recaptchaRemoteIP = None
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

# -*- coding: utf-8 -*-
#_____________________________________________________________________________
#
# This file is part of BridgeDB, a Tor bridge distribution system.
#
# :authors: trygve <tor-dev@lists.torproject.org>
# :copyright: (c) 2014, trygve
#             (c) 2014-2015, The Tor Project, Inc.
#             (c) 2014-2015, Isis Lovecruft
# :license: see LICENSE for licensing information
#_____________________________________________________________________________

"""Integration tests for BridgeDB's HTTPS Distributor.

These tests use `mechanize`_ and `BeautifulSoup`_, and require a BridgeDB
instance to have been started in a separate process. To see how a BridgeDB is
started for our CI infrastructure from a fresh clone of this repository, see
the "before_script" section of the `.travis.yml` file in the top level of this
repository.

.. _mechanize: https://pypi.python.org/pypi/mechanize/
    http://wwwsearch.sourceforge.net/mechanize/
.. _BeautifulSoup:
    http://www.crummy.com/software/BeautifulSoup/bs3/documentation.html
"""

from __future__ import print_function

import gettext
import ipaddr
import mechanize
import os

from BeautifulSoup import BeautifulSoup

from twisted.trial import unittest
from twisted.trial.reporter import TestResult
from twisted.trial.unittest import FailTest
from twisted.trial.unittest import SkipTest

from .test_Tests import DynamicTestCaseMeta
from .util import processExists
from .util import getBridgeDBPID


HTTP_ROOT = 'http://127.0.0.1:6788'
CAPTCHA_RESPONSE = 'Tvx74Pmy'

TOPDIR = os.getcwd()
while not TOPDIR.endswith('bridgedb'):
    TOPDIR = os.path.dirname(TOPDIR)

PIDFILE = os.path.join(TOPDIR, 'run', 'bridgedb.pid')
PID = getBridgeDBPID(PIDFILE)


class HTTPTests(unittest.TestCase):

    def setUp(self):
        if not os.environ.get("CI"):
            raise SkipTest(("The mechanize tests cannot handle self-signed  "
                            "TLS certificates, and thus require opening "
                            "another port for running a plaintext HTTP-only "
                            "BridgeDB webserver. Because of this, these tests "
                            "are only run on CI servers."))
        if not PID or not processExists(PID):
            raise FailTest("Could not start BridgeDB process on CI server!")

        self.br = None

    def tearDown(self):
        self.br = None

    def openBrowser(self):
        # use mechanize to open the BridgeDB website in its browser
        self.br = mechanize.Browser()
        # prevents 'HTTP Error 403: request disallowed by robots.txt'
        self.br.set_handle_robots(False)
        self.br.open(HTTP_ROOT)

        # -------------- Home/Root  page
        self.assertTrue(self.br.viewing_html())
        self.assertEquals(self.br.response().geturl(), HTTP_ROOT)
        self.assertEquals(self.br.title(), "BridgeDB")
        return self.br

    def goToOptionsPage(self):
        # check that we are on the root page
        self.assertTrue(self.br.viewing_html())
        self.assertEquals(self.br.response().geturl(), HTTP_ROOT)

        # follow the link with the word 'bridges' in it.
        # Could also use: text='bridges'
        # Could also use: url='/options'
        self.br.follow_link(text_regex='bridges')

        # ------------- Options
        self.assertEquals(self.br.response().geturl(), HTTP_ROOT + "/options")
        return self.br

    def submitOptions(self, transport, ipv6, captchaResponse):
        # check that we are on the options page
        self.assertEquals(self.br.response().geturl(), HTTP_ROOT + "/options")

        # At this point, we'd like to be able to set some values in
        # the 'advancedOptions' form. Unfortunately the HTML form
        # does not define a 'name' attribute, so the we have to rely on
        # the fact that this is the only form on the page and will therefore
        # always exist at index 0.
        #br.select_form(name="advancedOptions")
        self.br.select_form(nr=0)

        # change the pluggable transport to something else
        self.br.form['transport'] = [transport]
        if ipv6:
            self.br.form['ipv6'] = ['yes']
        self.br.submit()

        # ------------- Captcha
        EXPECTED_URL = HTTP_ROOT + "/bridges?transport=%s" % transport
        if ipv6:
            EXPECTED_URL += "&ipv6=yes"
        self.assertEquals(self.br.response().geturl(), EXPECTED_URL)

        # As on the previous page, the form does not define a 'name'
        # attribute, forcing us to use the index of the form, i.e. 0
        #self.br.select_form(name="captchaSubmission")
        self.br.select_form(nr=0)

        # input the required captcha response. There is only one captcha
        # defined by default, so this should always be accepted. Note this
        # will not be possible to automate if used with a third-party CAPTCHA
        # systems (e.g. reCAPTCHA)
        self.br.form['captcha_response_field'] = captchaResponse
        captcha_response = self.br.submit()

        # ------------- Results
        # URL should be the same as last time
        self.assertEquals(self.br.response().geturl(), EXPECTED_URL)
        soup = BeautifulSoup(captcha_response.read())
        return soup

    def getBridgeLinesFromSoup(self, soup, fieldsPerBridge):
        """We're looking for something like this in the response::
            <div class="bridge-lines">
             obfs2 175.213.252.207:11125 5c6da7d927460317c6ff5420b75c2d0f431f18dd
            </div>
        """
        bridges = []
        soup = soup.findAll(attrs={'class' : 'bridge-lines'})
        self.assertTrue(soup, "Could not find <div class='bridge-lines'>!")

        for portion in soup:
            br_tags = portion.findChildren('br')
            bridge_lines = set(portion.contents).difference(set(br_tags))
            for bridge_line in bridge_lines:
                bridge_line = bridge_line.strip()
                if bridge_line:
                    fields = bridge_line.split()
                    bridges.append(fields)

        self.assertTrue(len(bridges) > 0, "Found no bridge lines in %s" % soup)

        for bridge in bridges:
            self.assertEquals(len(bridge), fieldsPerBridge,
                                  "Expected %d fields in bridge line %s"
                                  % (fieldsPerBridge, bridge))
        return bridges

    def test_content_security_policy(self):
        """Check that the HTTP Content-Security-Policy header is set."""
        self.br = mechanize.Browser()
        self.br.set_handle_robots(False)
        self.br.set_debug_http(True)
        self.br.open(HTTP_ROOT)

        headers = ''.join(self.br.response().info().headers)

        self.assertIn("Content-Security-Policy", headers)
        self.assertIn("default-src 'none';", headers)

    def test_404(self):
        """Asking for a non-existent resource should yield our custom 404 page,
        but we can't actually check because Mechanize flips out if we get
        anything response code other than 200. :/
        """
        page = '/'.join([HTTP_ROOT, '404'])
        self.openBrowser()
        self.assertRaises(mechanize.HTTPError, self.br.open, page)

    def test_get_obfs3_ipv4(self):
        self.openBrowser()
        self.goToOptionsPage()

        PT = 'obfs3'
        soup = self.submitOptions(transport=PT, ipv6=False,
                                  captchaResponse=CAPTCHA_RESPONSE)
        bridges = self.getBridgeLinesFromSoup(soup, fieldsPerBridge=3)
        for bridge in bridges:
            pt = bridge[0]
            self.assertEquals(PT, pt)

    def test_get_vanilla_ipv4(self):
        self.openBrowser()
        self.goToOptionsPage()

        PT = '0'
        soup = self.submitOptions(transport=PT, ipv6=False,
                                  captchaResponse=CAPTCHA_RESPONSE)
        bridges = self.getBridgeLinesFromSoup(soup, fieldsPerBridge=2)
        for bridge in bridges:
            self.assertTrue(bridge != None)
            addr = bridge[0].rsplit(':', 1)[0]
            self.assertIsInstance(ipaddr.IPAddress(addr), ipaddr.IPv4Address)

    def test_get_vanilla_ipv6(self):
        self.openBrowser()
        self.goToOptionsPage()

        PT = '0'
        soup = self.submitOptions(transport=PT, ipv6=True,
                                  captchaResponse=CAPTCHA_RESPONSE)
        bridges = self.getBridgeLinesFromSoup(soup, fieldsPerBridge=2)
        for bridge in bridges:
            self.assertTrue(bridge != None)
            addr = bridge[0].rsplit(':', 1)[0].strip('[]')
            self.assertIsInstance(ipaddr.IPAddress(addr), ipaddr.IPv6Address)

    def test_get_scramblesuit_ipv4(self):
        self.openBrowser()
        self.goToOptionsPage()

        PT = 'scramblesuit'
        soup = self.submitOptions(transport=PT, ipv6=False,
                                  captchaResponse=CAPTCHA_RESPONSE)
        bridges = self.getBridgeLinesFromSoup(soup, fieldsPerBridge=4)
        for bridge in bridges:
            pt = bridge[0]
            password = bridge[-1]
            self.assertEquals(PT, pt)
            self.assertTrue(password.find("password=") != -1,
                            "Password field missing expected text")

    def test_get_obfs4_ipv4(self):
        """Try asking for obfs4 bridges, and check that the PT arguments in the
        returned bridge lines were space-separated.

        This is a regression test for #12932, see
        https://bugs.torproject.org/12932.
        """
        self.openBrowser()
        self.goToOptionsPage()

        PT = 'obfs4'

        try:
            soup = self.submitOptions(transport=PT, ipv6=False,
                                      captchaResponse=CAPTCHA_RESPONSE)
        except ValueError as error:
            if 'non-disabled' in str(error):
                raise SkipTest("Pluggable Transport obfs4 is currently disabled.")

        bridges = self.getBridgeLinesFromSoup(soup, fieldsPerBridge=6)
        for bridge in bridges:
            pt = bridge[0]
            ptArgs = bridge[-3:]
            self.assertEquals(PT, pt)
            self.assertTrue(len(ptArgs) == 3,
                            ("Expected obfs4 bridge line to have 3 PT args, "
                             "found %d instead: %s") % (len(ptArgs), ptArgs))

    def test_get_obfs4_ipv4_iatmode(self):
        """Ask for obfs4 bridges and check that there is an 'iat-mode' PT
        argument in the bridge lines.
        """
        self.openBrowser()
        self.goToOptionsPage()

        PT = 'obfs4'

        try:
            soup = self.submitOptions(transport=PT, ipv6=False,
                                      captchaResponse=CAPTCHA_RESPONSE)
        except ValueError as error:
            if 'non-disabled' in str(error):
                raise SkipTest("Pluggable Transport obfs4 is currently disabled.")

        bridges = self.getBridgeLinesFromSoup(soup, fieldsPerBridge=6)
        for bridge in bridges:
            ptArgs = bridge[-3:]
            hasIATMode = False
            for arg in ptArgs:
                if 'iat-mode' in arg:
                    hasIATMode = True

            self.assertTrue(hasIATMode,
                            "obfs4 bridge line is missing 'iat-mode' PT arg.")

    def test_get_obfs4_ipv4_publickey(self):
        """Ask for obfs4 bridges and check that there is an 'public-key' PT
        argument in the bridge lines.
        """
        self.openBrowser()
        self.goToOptionsPage()

        PT = 'obfs4'

        try:
            soup = self.submitOptions(transport=PT, ipv6=False,
                                      captchaResponse=CAPTCHA_RESPONSE)
        except ValueError as error:
            if 'non-disabled' in str(error):
                raise SkipTest("Pluggable Transport obfs4 is currently disabled.")

        bridges = self.getBridgeLinesFromSoup(soup, fieldsPerBridge=6)
        for bridge in bridges:
            ptArgs = bridge[-3:]
            hasPublicKey = False
            for arg in ptArgs:
                if 'public-key' in arg:
                    hasPublicKey = True

            self.assertTrue(hasPublicKey,
                            "obfs4 bridge line is missing 'public-key' PT arg.")

    def test_get_obfs4_ipv4_nodeid(self):
        """Ask for obfs4 bridges and check that there is an 'node-id' PT
        argument in the bridge lines.
        """
        self.openBrowser()
        self.goToOptionsPage()

        PT = 'obfs4'

        try:
            soup = self.submitOptions(transport=PT, ipv6=False,
                                      captchaResponse=CAPTCHA_RESPONSE)
        except ValueError as error:
            if 'non-disabled' in str(error):
                raise SkipTest("Pluggable Transport obfs4 is currently disabled.")

        bridges = self.getBridgeLinesFromSoup(soup, fieldsPerBridge=6)
        for bridge in bridges:
            ptArgs = bridge[-3:]
            hasNodeID = False
            for arg in ptArgs:
                if 'node-id' in arg:
                    hasNodeID = True

            self.assertTrue(hasNodeID,
                            "obfs4 bridge line is missing 'node-id' PT arg.")


class _HTTPTranslationsTests(unittest.TestCase):
    """Build a TestCase with dynamic methods which tests all HTTP rendering of
    all translations in the bridgedb/i18n/ directory.
    """
    i18n = os.path.join(TOPDIR, 'bridgedb', 'i18n')

    def setUp(self):
        if not os.environ.get("CI"):
            raise SkipTest(("The mechanize tests cannot handle self-signed  "
                            "TLS certificates, and thus require opening "
                            "another port for running a plaintext HTTP-only "
                            "BridgeDB webserver. Because of this, these tests "
                            "are only run on CI servers."))

        if not PID or not processExists(PID):
            raise FailTest("Could not start BridgeDB process on CI server!")

        self.br = None

    @classmethod
    def makeTestMethod(cls, locale):
        """Dynamically generate a test_ method for **locale**."""

        def test(self):
            pageArgs = '/?lang=%s' % locale
            language = gettext.translation("bridgedb",
                                           localedir=self.i18n,
                                           languages=[locale,],
                                           fallback=True)
            expected = language.gettext("What are bridges?")

            if not locale.startswith('en'):
                self.assertNotEqual(expected, "What are bridges?")

            self.openBrowser()
            self.br.open(HTTP_ROOT + pageArgs)
            self.assertSubstring(expected, self.br.response().read())

        test.__name__ = 'test_%s' % locale
        setattr(cls, test.__name__, test)

        return test

    def tearDown(self):
        self.br = None

    def openBrowser(self):
        self.br = mechanize.Browser()
        self.br.set_handle_robots(False)

    def test_self(self):
        self.assertTrue(self)


def createHTTPTranslationsTestSuite():
    suite = unittest.TestSuite()
    translations = os.listdir(_HTTPTranslationsTests.i18n)
    translations.remove('templates')

    for locale in translations:
        klass = _HTTPTranslationsTests
        method = klass.makeTestMethod(locale)
        case = klass()
        suite.addTest(case)

    return [suite,]


class HTTPTranslationsTests(unittest.TestCase):
    __metaclass__ = DynamicTestCaseMeta
    testResult    = TestResult()
    testSuites    = createHTTPTranslationsTestSuite()

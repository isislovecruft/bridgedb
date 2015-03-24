# -*- coding: utf-8 -*-
#
# This file is part of BridgeDB, a Tor bridge distribution system.
#
# :authors: Isis Lovecruft 0xA3ADB67A2CDB8B35 <isis@torproject.org>
# :copyright: (c) 2014-2015, Isis Lovecruft
#             (c) 2014-2015, The Tor Project, Inc.
# :license: 3-Clause BSD, see LICENSE for licensing information


from twisted.trial import unittest

from bridgedb import translations
from bridgedb.test.test_HTTPServer import DummyRequest


REALISH_HEADERS = {
    b'Accept-Encoding': [b'gzip, deflate'],
    b'User-Agent': [
        b'Mozilla/5.0 (X11; Linux x86_64; rv:28.0) Gecko/20100101 Firefox/28.0'],
    b'Accept': [
        b'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'],
}

# Add this to the above REALISH_HEADERS to use it:
ACCEPT_LANGUAGE_HEADER = {
    b'Accept-Language': [b'de-de,en-gb;q=0.8,en;q=0.5,en-us;q=0.3'],
}


class TranslationsMiscTests(unittest.TestCase):
    """Tests for module-level code in ``bridgedb.translations`` module."""

    def test_getLocaleFromHTTPRequest_withLangParam(self):
        """This request uses a '?lang=ar' param, without an 'Accept-Language'
        header.

        The request result should be: ['ar', 'en', 'en-US'].
        """
        request = DummyRequest([b"bridges"])
        request.headers.update(REALISH_HEADERS)
        request.args.update({
            b'transport': [b'obfs3',],
            b'lang': [b'ar',],
        })

        parsed = translations.getLocaleFromHTTPRequest(request)
        self.assertEqual(parsed[0], 'ar')
        self.assertEqual(parsed[1], 'en')
        self.assertEqual(parsed[2], 'en_US')
        self.assertEqual(len(parsed), 3)

    def test_getLocaleFromHTTPRequest_withLangParam_AcceptLanguage(self):
        """This request uses a '?lang=ar' param, with an 'Accept-Language'
        header which includes: ['de-de', 'en-gb', 'en', 'en-us'].

        The request result should be: ['fa', 'de-de', 'en-gb', 'en', 'en-us'].
        """
        request = DummyRequest([b"options"])
        request.headers.update(ACCEPT_LANGUAGE_HEADER)
        request.args.update({b'lang': [b'fa']})

        parsed = translations.getLocaleFromHTTPRequest(request)
        self.assertEqual(parsed[0], 'fa')
        self.assertEqual(parsed[1], 'en')
        self.assertEqual(parsed[2], 'en_US')
        #self.assertEqual(parsed[3], 'en-gb')
        self.assertEqual(len(parsed), 3)

    def test_getLocaleFromPlusAddr(self):
        emailAddr = 'bridges@torproject.org'
        replyLocale = translations.getLocaleFromPlusAddr(emailAddr)
        self.assertEqual('en', replyLocale)

    def test_getLocaleFromPlusAddr_ar(self):
        emailAddr = 'bridges+ar@torproject.org'
        replyLocale = translations.getLocaleFromPlusAddr(emailAddr)
        self.assertEqual('ar', replyLocale)

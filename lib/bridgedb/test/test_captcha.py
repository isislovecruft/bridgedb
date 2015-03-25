# -*- coding: utf-8 -*-
#
# This file is part of BridgeDB, a Tor bridge distribution system.
#
# :authors: Isis Lovecruft 0xA3ADB67A2CDB8B35 <isis@torproject.org>
# :copyright: (c) 2013-2015, Isis Lovecruft
#             (c) 2007-2015, The Tor Project, Inc.
# :license: 3-Clause BSD, see LICENSE for licensing information

"""Unittests for the :mod:`bridgedb.captcha` module."""


import os
import shutil
import time

from base64 import urlsafe_b64decode

from twisted.trial import unittest

from zope.interface import implementedBy
from zope.interface import providedBy

from bridgedb import captcha
from bridgedb import crypto


class CaptchaTests(unittest.TestCase):
    """Tests for :class:`bridgedb.captcha.Captcha`."""

    def test_implementation(self):
        """Captcha class should implement ICaptcha interface."""
        self.assertTrue(captcha.ICaptcha.implementedBy(captcha.Captcha))

    def test_provider(self):
        """ICaptcha should be provided by instances of Captcha."""
        c = captcha.Captcha()
        self.assertTrue(captcha.ICaptcha.providedBy(c))

    def test_get(self):
        """Captcha.get() should return None."""
        c = captcha.Captcha()
        self.assertIsNone(c.get())


class ReCaptchaTests(unittest.TestCase):
    """Tests for :class:`bridgedb.captcha.ReCaptcha`."""

    def setUp(self):
        self.c = captcha.ReCaptcha('publik', 'sekrit')

    def test_init(self):
        """Check the ReCaptcha class stored the private and public keys."""
        self.assertEquals(self.c.secretKey, 'sekrit')
        self.assertEquals(self.c.publicKey, 'publik')

    def test_get(self):
        """Test get() method."""

        # Force urllib2 to do anything less idiotic than the defaults:
        envkey = 'HTTPS_PROXY'
        oldkey = None
        if os.environ.has_key(envkey):
            oldkey = os.environ[envkey]
        os.environ[envkey] = '127.0.0.1:9150'
        # This stupid thing searches the environment for ``<protocol>_PROXY``
        # variables, hence the above 'HTTPS_PROXY' env setting:
        proxy = captcha.urllib2.ProxyHandler()
        opener = captcha.urllib2.build_opener(proxy)
        captcha.urllib2.install_opener(opener)

        try:
            # There isn't really a reliable way to test this function! :(
            self.c.get()
        except Exception as error:
            reason  = "ReCaptcha.get() test requires an active network "
            reason += "connection.\nThis test failed with: %s" % error
            raise unittest.SkipTest(reason)
        else:
            self.assertIsInstance(self.c.image, basestring)
            self.assertIsInstance(self.c.challenge, basestring)
        finally:
            # Replace the original environment variable if there was one:
            if oldkey:
                os.environ[envkey] = oldkey
            else:
                os.environ.pop(envkey)

    def test_get_noKeys(self):
        """ReCaptcha.get() without API keys should fail."""
        c = captcha.ReCaptcha()
        self.assertRaises(captcha.CaptchaKeyError, c.get)


class GimpCaptchaTests(unittest.TestCase):
    """Tests for :class:`bridgedb.captcha.GimpCaptcha`."""

    def setUp(self):
        here             = os.getcwd()
        self.topDir      = here.rstrip('_trial_temp')
        self.cacheDir    = os.path.join(self.topDir, 'captchas')
        self.badCacheDir = os.path.join(here, 'capt')

        # Get keys for testing or create them:
        self.sekrit, self.publik = crypto.getRSAKey('test_gimpCaptcha_RSAkey')
        self.hmacKey = crypto.getKey('test_gimpCaptcha_HMACkey')

    def test_init_noSecretKey(self):
        """Calling GimpCaptcha.__init__() without a secret key parameter should raise
        a CaptchaKeyError.
        """
        self.assertRaises(captcha.CaptchaKeyError, captcha.GimpCaptcha,
                          self.publik, None, self.hmacKey, self.cacheDir)

    def test_init_noPublicKey(self):
        """__init__() without publicKey should raise a CaptchaKeyError."""
        self.assertRaises(captcha.CaptchaKeyError, captcha.GimpCaptcha,
                          None, self.sekrit, self.hmacKey, self.cacheDir)

    def test_init_noHMACKey(self):
        """__init__() without hmacKey should raise a CaptchaKeyError."""
        self.assertRaises(captcha.CaptchaKeyError, captcha.GimpCaptcha,
                          self.publik, self.sekrit, None, self.cacheDir)

    def test_init_noCacheDir(self):
        """__init__() without cacheDir should raise a CaptchaKeyError."""
        self.assertRaises(captcha.GimpCaptchaError, captcha.GimpCaptcha,
                          self.publik, self.sekrit, self.hmacKey, None)

    def test_init_badCacheDir(self):
        """GimpCaptcha with bad cacheDir should raise GimpCaptchaError."""
        self.assertRaises(captcha.GimpCaptchaError, captcha.GimpCaptcha,
                          self.publik, self.sekrit, self.hmacKey,
                          self.cacheDir.rstrip('chas'))

    def test_init(self):
        """Test that __init__ correctly initialised all the values."""
        c = captcha.GimpCaptcha(self.publik, self.sekrit, self.hmacKey,
                                self.cacheDir)
        self.assertIsNone(c.answer)
        self.assertIsNone(c.image)
        self.assertIsNone(c.challenge)

    def test_createChallenge(self):
        """createChallenge() should return the encrypted CAPTCHA answer."""
        c = captcha.GimpCaptcha(self.publik, self.sekrit, self.hmacKey,
                                self.cacheDir)
        challenge = c.createChallenge('w00t')
        self.assertIsInstance(challenge, basestring)

    def test_createChallenge_base64(self):
        """createChallenge() return value should be urlsafe base64-encoded."""
        c = captcha.GimpCaptcha(self.publik, self.sekrit, self.hmacKey,
                                self.cacheDir)
        challenge = c.createChallenge('w00t')
        decoded = urlsafe_b64decode(challenge)
        self.assertTrue(decoded)

    def test_createChallenge_hmacValid(self):
        """The HMAC in createChallenge() return value should be valid."""
        c = captcha.GimpCaptcha(self.publik, self.sekrit, self.hmacKey,
                                self.cacheDir)
        challenge = c.createChallenge('ShouldHaveAValidHMAC')
        decoded = urlsafe_b64decode(challenge)
        hmac = decoded[:20]
        orig = decoded[20:]
        correctHMAC = crypto.getHMAC(self.hmacKey, orig)
        self.assertEquals(hmac, correctHMAC)

    def test_createChallenge_decryptedAnswerMatches(self):
        """The HMAC in createChallenge() return value should be valid."""
        c = captcha.GimpCaptcha(self.publik, self.sekrit, self.hmacKey,
                                self.cacheDir)
        challenge = c.createChallenge('ThisAnswerShouldDecryptToThis')
        decoded = urlsafe_b64decode(challenge)
        hmac = decoded[:20]
        orig = decoded[20:]
        correctHMAC = crypto.getHMAC(self.hmacKey, orig)
        self.assertEqual(hmac, correctHMAC)

        decrypted = self.sekrit.decrypt(orig)
        timestamp = int(decrypted[:12].lstrip('0'))
        # The timestamp should be within 30 seconds of right now.
        self.assertApproximates(timestamp, int(time.time()), 30)
        self.assertEqual('ThisAnswerShouldDecryptToThis', decrypted[12:])

    def test_get(self):
        """GimpCaptcha.get() should return image and challenge strings."""
        c = captcha.GimpCaptcha(self.publik, self.sekrit, self.hmacKey,
                                self.cacheDir)
        image, challenge = c.get()
        self.assertIsInstance(image, basestring)
        self.assertIsInstance(challenge, basestring)

    def test_get_emptyCacheDir(self):
        """An empty cacheDir should raise GimpCaptchaError."""
        os.makedirs(self.badCacheDir)
        c = captcha.GimpCaptcha(self.publik, self.sekrit, self.hmacKey,
                                self.badCacheDir)
        self.assertRaises(captcha.GimpCaptchaError, c.get)
        shutil.rmtree(self.badCacheDir)

    def test_get_unreadableCaptchaFile(self):
        """An unreadable CAPTCHA file should raise GimpCaptchaError."""
        os.makedirs(self.badCacheDir)
        badFile = os.path.join(self.badCacheDir, 'uNr34dA81e.jpg')
        with open(badFile, 'w') as fh:
            fh.write(' ')
            fh.flush()
        os.chmod(badFile, 0266)

        c = captcha.GimpCaptcha(self.publik, self.sekrit, self.hmacKey,
                                self.badCacheDir)
        # This should hit the second `except:` clause in get():
        self.assertRaises(captcha.GimpCaptchaError, c.get)
        shutil.rmtree(self.badCacheDir)

    def test_check(self):
        """A correct answer and valid challenge should return True."""
        c = captcha.GimpCaptcha(self.publik, self.sekrit, self.hmacKey,
                                self.cacheDir)
        image, challenge = c.get()
        self.assertEquals(
            c.check(challenge, c.answer, c.secretKey, c.hmacKey),
            True)

    def test_check_blankAnswer(self):
        """A blank answer and valid challenge should return False."""
        c = captcha.GimpCaptcha(self.publik, self.sekrit, self.hmacKey,
                                self.cacheDir)
        image, challenge = c.get()
        self.assertEquals(
            c.check(challenge, None, c.secretKey, c.hmacKey),
            False)

    def test_check_nonBase64(self):
        """Valid answer and challenge with invalid base64 returns False."""
        c = captcha.GimpCaptcha(self.publik, self.sekrit, self.hmacKey,
                                self.cacheDir)
        image, challenge = c.get()
        challengeBadB64 = challenge.rstrip('==') + "\x42\x42\x42"
        self.assertEquals(
            c.check(challenge, c.answer, c.secretKey, c.hmacKey),
            True)
        self.assertEquals(
            c.check(challengeBadB64, c.answer, c.secretKey, c.hmacKey),
            False)

    def test_check_caseInsensitive_lowercase(self):
        """A correct answer in lowercase characters should return True."""
        c = captcha.GimpCaptcha(self.publik, self.sekrit, self.hmacKey,
                                self.cacheDir)
        image, challenge = c.get()
        solution = c.answer.lower()
        self.assertEquals(
            c.check(challenge, solution, c.secretKey, c.hmacKey),
            True)

    def test_check_caseInsensitive_uppercase(self):
        """A correct answer in uppercase characters should return True."""
        c = captcha.GimpCaptcha(self.publik, self.sekrit, self.hmacKey,
                                self.cacheDir)
        image, challenge = c.get()
        solution = c.answer.upper()
        self.assertEquals(
            c.check(challenge, solution, c.secretKey, c.hmacKey),
            True)

    def test_check_encoding_utf8(self):
        """A correct answer in utf-8 lowercase should return True."""
        c = captcha.GimpCaptcha(self.publik, self.sekrit, self.hmacKey,
                                self.cacheDir)
        image, challenge = c.get()
        solution = c.answer.encode('utf8')
        self.assertEquals(
            c.check(challenge, solution, c.secretKey, c.hmacKey),
            True)

    def test_check_encoding_ascii(self):
        """A correct answer in utf-8 lowercase should return True."""
        c = captcha.GimpCaptcha(self.publik, self.sekrit, self.hmacKey,
                                self.cacheDir)
        image, challenge = c.get()
        solution = c.answer.encode('ascii')
        self.assertEquals(
            c.check(challenge, solution, c.secretKey, c.hmacKey),
            True)

    def test_check_encoding_unicode(self):
        """A correct answer in utf-8 lowercase should return True."""
        c = captcha.GimpCaptcha(self.publik, self.sekrit, self.hmacKey,
                                self.cacheDir)
        image, challenge = c.get()
        solution = unicode(c.answer)
        self.assertEquals(
            c.check(challenge, solution, c.secretKey, c.hmacKey),
            True)

    def test_check_missingHMACbytes(self):
        """A challenge that is missing part of the HMAC should return False."""
        c = captcha.GimpCaptcha(self.publik, self.sekrit, self.hmacKey,
                                self.cacheDir)
        image, challenge = c.get()
        challengeBadHMAC = challenge[:10] + challenge[20:]
        self.assertEquals(
            c.check(challengeBadHMAC, c.answer, c.secretKey, c.hmacKey),
            False)

    def test_check_missingAnswerbytes(self):
        """Partial encrypted answers in challenges should return False."""
        c = captcha.GimpCaptcha(self.publik, self.sekrit, self.hmacKey,
                                self.cacheDir)
        image, challenge = c.get()
        challengeBadOrig = challenge[:20] + challenge[30:]
        self.assertEquals(
            c.check(challengeBadOrig, c.answer, c.secretKey, c.hmacKey),
            False)

    def test_check_badHMACkey(self):
        """A challenge with a bad HMAC key should return False."""
        hmacKeyBad = crypto.getKey('test_gimpCaptcha_badHMACkey')
        c = captcha.GimpCaptcha(self.publik, self.sekrit, self.hmacKey,
                                self.cacheDir)
        image, challenge = c.get()
        self.assertEquals(
            c.check(challenge, c.answer, c.secretKey, hmacKeyBad),
            False)

    def test_check_badRSAkey(self):
        """A challenge with a bad RSA secret key should return False."""
        secretKeyBad, publicKeyBad = crypto.getRSAKey('test_gimpCaptcha_badRSAkey')
        c = captcha.GimpCaptcha(self.publik, self.sekrit, self.hmacKey,
                                self.cacheDir)
        image, challenge = c.get()
        self.assertEquals(
            c.check(challenge, c.answer, secretKeyBad, c.hmacKey),
            False)

# -*- encoding: utf-8 -*-
#_____________________________________________________________________________
#
# This file is part of BridgeDB, a Tor bridge distribution system.
#
# :authors: Isis Lovecruft 0xA3ADB67A2CDB8B35 <isis@torproject.org>
#           Aaron Gibson   0x2C4B239DD876C9F6 <aagbsn@torproject.org>
#           Nick Mathewson 0x21194EBB165733EA <nickm@torproject.org>
#           please also see AUTHORS file
# :copyright: (c) 2007-2014, The Tor Project, Inc.
#             (c) 2007-2014, all entities within the AUTHORS file
#             (c) 2014, Isis Lovecruft
# :license: see LICENSE for licensing information
#_____________________________________________________________________________

"""This module implements various methods for obtaining or creating CAPTCHAs.

**Module Overview:**

..
  captcha
   |_ReCaptchaKeyError
   \_ReCaptcha - Class for obtaining reCaptcha images and challenge strings
..

There are two types of CAPTCHAs which BridgeDB knows how to serve: those
obtained by from a reCaptcha_ API server with
:class:`~bridgedb.captcha.Raptcha`, and those which have been generated with
gimp-captcha_ and then cached locally.

.. _reCaptcha : https://code.google.com/p/recaptcha/
.. _gimp-captcha: https://github.com/isislovecruft/gimp-captcha
"""

from base64 import urlsafe_b64encode
from base64 import urlsafe_b64decode

import logging
import random
import os
import time
import urllib2

from BeautifulSoup import BeautifulSoup

from zope.interface import Interface, Attribute, implements

from bridgedb import crypto, list_encoder
from bridgedb.txrecaptcha import API_SSL_SERVER


class ReCaptchaKeyError(Exception):
    """Exception raised when recaptcha API keys are not supplied."""

class GimpCaptchaError(Exception):
    """General exception raised when a Gimp CAPTCHA cannot be retrieved."""

class GimpCaptchaKeyError(ValueError):
    """Raised when there is a problem with one of the Gimp CAPTCHA keys."""


class ICaptcha(Interface):
    """Interface specification for CAPTCHAs."""

    image = Attribute(
        "A string containing the contents of a CAPTCHA image file.")
    challenge = Attribute(
        "A unique string associated with the dispursal of this CAPTCHA.")

    def get():
        """Retrieve a new CAPTCHA image."""


class Captcha(object):
    """A generic CAPTCHA base class.

    :ivar str image: The CAPTCHA image.
    :ivar str challenge: A challenge string which should permit checking of
        the client's CAPTCHA solution in some manner. This should be passed
        along to the client with the CAPTCHA image.
    """
    implements(ICaptcha)

    def __init__(self):
        self.image = None
        self.challenge = None

    def get(self):
        return self.image


class ReCaptcha(Captcha):
    """A reCaptcha CAPTCHA.

    :ivar str image: The CAPTCHA image.
    :ivar str challenge: The ``'recaptcha_challenge_response'`` HTTP form
        field to pass to the client along with the CAPTCHA image.
    """

    def __init__(self, pubkey=None, privkey=None):
        """Create a new ReCaptcha CAPTCHA.

        :param str pubkey: The public reCaptcha API key.
        :param str privkey: The private reCaptcha API key.
        """
        super(ReCaptcha, self).__init__()
        self.pubkey = pubkey
        self.privkey = privkey

    def get(self):
        """Retrieve a CAPTCHA from the reCaptcha API server.

        This simply requests a new CAPTCHA from
        ``recaptcha.client.captcha.API_SSL_SERVER`` and parses the returned
        HTML to extract the CAPTCHA image and challenge string. The image is
        stored at ``ReCaptcha.image`` and the challenge string at
        ``ReCaptcha.challenge``.

        :raises ReCaptchaKeyError: If either the :ivar:`pubkey` or
            :ivar:`privkey` are missing.
        :raises HTTPError: If the server returned any HTTP error status code.
        """
        if not self.pubkey or not self.privkey:
            raise ReCaptchaKeyError('You must supply recaptcha API keys')

        urlbase = API_SSL_SERVER
        form = "/noscript?k=%s" % self.pubkey

        # Extract and store image from recaptcha
        html = urllib2.urlopen(urlbase + form).read()
        # FIXME: The remaining lines currently cannot be reliably unit tested:
        soup = BeautifulSoup(html)                           # pragma: no cover
        imgurl = urlbase + "/" +  soup.find('img')['src']    # pragma: no cover
        cField = soup.find(                                  # pragma: no cover
            'input', {'name': 'recaptcha_challenge_field'})  # pragma: no cover
        self.challenge = str(cField['value'])                # pragma: no cover
        self.image = urllib2.urlopen(imgurl).read()          # pragma: no cover


def quantize_int(i, granularity):
    i = int(i)
    return (i // granularity) * granularity

class GimpCaptcha(Captcha):
    """A cached CAPTCHA image which was created with Gimp."""

    def __init__(self, secretKey=None, publicKey=None, hmacKey=None,
                 cacheDir=None, captchaLifetime=900, clientIP=None):
        """Create a ``GimpCaptcha`` which retrieves images from **cacheDir**.

        :param str secretkey: A PKCS#1 OAEP-padded, private RSA key, used for
            verifying the client's solution to the CAPTCHA.
        :param str publickey: A PKCS#1 OAEP-padded, public RSA key, used for
            creating the ``captcha_challenge_field`` string to give to a
            client.
        :param bytes hmacKey: An HMAC secret key.
        :param str cacheDir: The local directory which pre-generated CAPTCHA
            images have been stored in. This can be set via the
            ``GIMP_CAPTCHA_DIR`` setting in the config file.
        :param number captchaLifetime: Approximately how long (in seconds) we
            will accept a CAPTCHA response after issuing the challenge.
        :param str clientIP: The IP address from which we received the client's
            request for bridges.
        :raises GimpCaptchaError: if **cacheDir** is not a directory.
        :raises GimpCaptchaKeyError: if any of **secretKey**, **publicKey**,
            or **hmacKey** is invalid, or missing.
        """
        super(GimpCaptcha, self).__init__()

        if not cacheDir or not os.path.isdir(cacheDir):
            raise GimpCaptchaError("Gimp captcha cache isn't a directory: %r"
                                   % cacheDir)
        if not (publicKey and secretKey and hmacKey):
            raise GimpCaptchaKeyError(
                "Invalid key supplied to GimpCaptcha: SK=%r PK=%r HMAC=%r"
                % (secretKey, publicKey, hmacKey))

        self.secretKey = secretKey
        self.publicKey = publicKey
        self.cacheDir = cacheDir
        self.captchaLifetime = captchaLifetime
        self.hmacKey = hmacKey
        self.clientIP = clientIP
        self.answer = None

    @classmethod
    def verifyHMACList(cls, hmacKey, x, mac):
        return crypto.verifyHMAC(hmacKey, list_encoder.encode(x), mac)

    @classmethod
    def mutilateAnswerExperimental(cls, answer):
        """Fold all potentially confusable characters in **answer** to a
        canonical choice."""
        # XXX If this type of folding turns out to be a good idea,
        #     the map should be configurable.
        confusables = ['fF', 'pP', 'zZ2', 'jJ']
        def fold_confusables(ch):
            for confusable_set in confusables:
                if ch in confusable_set:
                    ch = confusable_set[0]
                    pass
                pass
            return ch
        return ''.join(map(fold_confusables, answer))

    @classmethod
    def check(cls, challenge, solution, hmacKey, clientIP,
              currentTime=time.time()):
        """Check a client's CAPTCHA **solution** against the **challenge**.

        :param str challenge: The contents of the
            ``'captcha_challenge_field'`` HTTP form field.
        :param str solution: The client's proposed solution to the CAPTCHA
            that they were presented with.
        :param bytes hmacKey: A private key for generating HMACs.
        :param str clientIP: The IP address from which the client's CAPTCHA
            response was sent.
        :param number currentTime: The current time, in the format returned by
            time.time.
        :rtype: bool
        :returns: True if the CAPTCHA solution was correct.
        """
        logging.debug("Checking CAPTCHA solution %r against challenge %r"
                      % (solution, challenge))
        try:
            challenge_list = list_encoder.decode(urlsafe_b64decode(challenge))
            if challenge_list[0] == 'captcha-challenge-v2':
                aad = challenge_list[1]
                assert isinstance(aad, list)
                mac_lower = challenge_list[2]
                mac_plain = challenge_list[3]
                mac_experimental = challenge_list[4]
                assert aad[0] == 'captcha-challenge-v2-aad'
                expire_time_str = aad[1]
                expire_time = int(expire_time_str)
                challenge_client_ip = aad[2]
                # done parsing the challenge; now validate it
                if clientIP != challenge_client_ip:
                    return False
                if currentTime > expire_time:
                    return False
                mac_lower_contents = ['captcha-challenge-v2-response-lower',
                                      aad,
                                      response.lower()]
                mac_plain_contents = ['captcha-challenge-v2-response-plain',
                                      aad,
                                      response]
                mac_exp_contents = [
                    'captcha-challenge-v2-response-experimental',
                    aad,
                    self.mutilateAnswerExperimental(response)]
                matched_lower = self.verifyHMACList(hmacKey,
                                                    mac_lower_contents,
                                                    mac_lower)
                matched_plain = self.verifyHMACList(hmacKey,
                                                    mac_plain_contents,
                                                    mac_plain)
                matched_exp = self.verifyHMACList(hmacKey,
                                                  mac_exp_contents,
                                                  mac_experimental)
                logging.info(('Received CAPTCHA solution matched lower? %r, ' +
                              'plain? %r, experimental folding? %r') %
                             (matched_lower, matched_plain, matched_exp))
                return matched_lower or matched_plain or matched_exp
            else:
                return False
            pass
        except Exception as error:
            logging.exception(error)
            return False

    def hmacList(self, x):
        return crypto.getHMAC(self.hmacKey, list_encoder.encode(x))

    def createChallenge(self, answer, now=time.time()):
        """Create a challenge blob for the answer **answer**,
        computing the expiration time based on **now**.

        :param str answer: The answer to a CAPTCHA.
        :param number now: Now.  Accepted as a parameter to permit
            unit testing.
        :rtype: str
        :returns: A URL-safe, base64-encoded challenge blob.
        """
        # XXX This is a horrible format.  If this were a real
        #     programming language like C, and I had access to a
        #     crypto library that implemented sane primitives, I would
        #     encrypt the challenge with something like NaCl's
        #     secretbox (but with AAD), and do all the comparisons in
        #     constant time.  But this isn't C, and the only
        #     cryptographic primitive available that I trust is HMAC.
        #
        # XXX Really, this should be using HMAC-SHA-256, not the
        #     long-obsolete HMAC-SHA-1 that BridgeDB has used since
        #     t=-∞ to map each client address to a pool location.
        expire_time = quantize_int(now + self.captchaLifetime, 30)
        expire_time_str = str(expire_time)
        challenge_aad_list = ['captcha-challenge-v2-aad',
                              expire_time_str,
                              self.clientIP]
        mac_lower_contents = ['captcha-challenge-v2-response-lower',
                              challenge_aad_list,
                              answer.lower()]
        mac_plain_contents = ['captcha-challenge-v2-response-plain',
                              challenge_aad_list,
                              answer]
        answer_experimental = self.mutilateAnswerExperimental(answer)
        mac_experimental_contents = [
            'captcha-challenge-v2-response-experimental',
            challenge_aad_list,
            self.mutilateAnswerExperimental(answer)]
        mac_lower = self.hmacList(mac_lower_contents)
        mac_plain = self.hmacList(mac_plain_contents)
        mac_experimental = self.hmacList(mac_experimental_contents)
        challenge_list = ['captcha-challenge-v2',
                          challenge_aad_list,
                          mac_lower,
                          mac_plain,
                          mac_experimental]
        challenge = urlsafe_b64encode(list_encoder.encode(challenge_list))
        return challenge

    def get(self):
        """Get a random CAPTCHA from the cache directory.

        This chooses a random CAPTCHA image file from the cache directory, and
        reads the contents of the image into a string. Next, it creates a
        challenge string for the CAPTCHA, via :meth:`createChallenge`.

        :raises GimpCaptchaError: if the chosen CAPTCHA image file could not
            be read, or if the **cacheDir** is empty.
        :rtype: tuple
        :returns: A 2-tuple containing the image file contents as a string,
            and a challenge string (used for checking the client's solution).
        """
        try:
            imageFilename = random.choice(os.listdir(self.cacheDir))
            imagePath = os.path.join(self.cacheDir, imageFilename)
            with open(imagePath) as imageFile:
                self.image = imageFile.read()
        except IndexError:
            raise GimpCaptchaError("CAPTCHA cache dir appears empty: %r"
                                   % self.cacheDir)
        except (OSError, IOError):
            raise GimpCaptchaError("Could not read Gimp captcha image file: %r"
                                   % imageFilename)

        self.answer = imageFilename.rsplit(os.path.extsep, 1)[0]
        self.challenge = self.createChallenge(self.answer)

        return (self.image, self.challenge)

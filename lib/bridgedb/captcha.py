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

import hashlib
import logging
import random
import os
import urllib2

from BeautifulSoup import BeautifulSoup
from recaptcha.client.captcha import API_SSL_SERVER
from zope.interface import Interface, Attribute, implements


class ReCaptchaKeyError(Exception):
    """Exception raised when recaptcha API keys are not supplied."""

class GimpCaptchaError(Exception):
    """General exception raised when a Gimp CAPTCHA cannot be retrieved."""


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
    """A reCaptcha CAPTCHA."""

    def __init__(self, pubkey=None, privkey=None):
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
        """
        if not self.pubkey or not self.privkey:
            raise ReCaptchaKeyError('You must supply recaptcha API keys')

        urlbase = API_SSL_SERVER
        form = "/noscript?k=%s" % self.pubkey

        # extract and store image from captcha
        html = urllib2.urlopen(urlbase + form).read()
        soup = BeautifulSoup(html)
        imgurl = urlbase + "/" +  soup.find('img')['src']
        self.challenge = str(soup.find('input', {'name': 'recaptcha_challenge_field'})['value'])
        self.image = urllib2.urlopen(imgurl).read()


class GimpCaptcha(Captcha):
    """A cached CAPTCHA image which was created with Gimp."""

    def __init__(self, cacheDir=None, clientIP=None):
        """Create a ``GimpCaptcha`` which retrieves images from **cacheDir**.

        :raises GimpCaptchaError: if **cacheDir** is not a directory.
        """
        super(GimpCaptcha, self).__init__()
        if not os.path.isdir(cacheDir):
            raise GimpCaptchaError("Gimp captcha cache isn't a directory: %r"
                                   % cacheDir)
        self.cacheDir = cacheDir
        self.clientIP = clientIP

    @classmethod
    def check(cls, challenge, answer, clientIP=None):
        """Check a client's CAPTCHA solution against the **challenge**.

        :rtype: bool
        :returns: True if the CAPTCHA solution was correct.
        """
        logging.debug("Checking CAPTCHA solution %r against challenge %r"
                      % (answer, challenge))
        solution = cls.createChallenge(answer, clientIP)
        if (not challenge) or (challenge != solution):
            return False
        return True

    @classmethod
    def createChallenge(cls, answer, clientIP=None):
        """Hash a CAPTCHA answer together with a **clientIP**, if given.

        :param str answer: The answer (either actual, or a client's proposed
            solution) to a CAPTCHA.
        :param str clientIP: The client's IP address.
        """
        challenge = '\n'.join([answer, str(clientIP)])
        return hashlib.sha256(challenge).hexdigest()

    def get(self):
        """Get a random CAPTCHA from the cache directory.

        :raises GimpCaptchaError: if the chosen CAPTCHA image file could not
                                  be read.
        :returns: A 2-tuple of ``(captcha, None)``, where ``captcha`` is the
                  image file contents.
        """
        imageFilename = random.choice(os.listdir(self.cacheDir))
        imagePath = os.path.join(self.cacheDir, imageFilename)

        try:
            with open(imagePath) as imageFile:
                self.image = imageFile.read()
        except (OSError, IOError) as err:
            raise GimpCaptchaError("Could not read Gimp captcha image file: %r"
                                   % imageFilename)

        captchaAnswer = imageFilename.rsplit(os.path.extsep, 1)[0]
        self.challenge = self.createChallenge(captchaAnswer, self.clientIP)

        return (self.image, self.challenge)

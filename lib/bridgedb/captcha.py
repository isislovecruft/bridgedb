# -*- coding: utf-8 -*-
#_____________________________________________________________________________
#
# This file is part of BridgeDB, a Tor bridge distribution system.
#
# :authors: Isis Lovecruft 0xA3ADB67A2CDB8B35 <isis@torproject.org>
#           Aaron Gibson   0x2C4B239DD876C9F6 <aagbsn@torproject.org>
#           Nick Mathewson 0x21194EBB165733EA <nickm@torproject.org>
#           please also see AUTHORS file
# :copyright: (c) 2007-2015, The Tor Project, Inc.
#             (c) 2007-2015, all entities within the AUTHORS file
#             (c) 2014-2015, Isis Lovecruft
# :license: see LICENSE for licensing information
#_____________________________________________________________________________

"""This module implements various methods for obtaining or creating CAPTCHAs.

**Module Overview:**

::

  captcha
   |- CaptchaExpired - Raised if a solution is given for a stale CAPTCHA.
   |- CaptchaKeyError - Raised if a CAPTCHA system's keys are invalid/missing.
   |- GimpCaptchaError - Raised when a Gimp CAPTCHA can't be retrieved.
   |
   \_ ICaptcha - Zope Interface specification for a generic CAPTCHA.
        |
      Captcha - Generic base class implementation for obtaining a CAPTCHA.
      |  |- image - The CAPTCHA image.
      |  |- challenge - A unique string associated with this CAPTCHA image.
      |  |- publicKey - The public key for this CAPTCHA system.
      |  |- secretKey - The secret key for this CAPTCHA system.
      |   \_ get() - Get a new pair of CAPTCHA image and challenge strings.
      |
      |- ReCaptcha - Obtain reCaptcha images and challenge strings.
      |   \_ get() - Request an image and challenge from a reCaptcha API server.
      |
      \_ GimpCaptcha - Class for obtaining a CAPTCHA from a local cache.
          |- hmacKey - A client-specific key for HMAC generation.
          |- cacheDir - The path to the local CAPTCHA cache directory.
          |- sched - A class for timing out CAPTCHAs after an interval.
          \_ get() - Get a CAPTCHA image from the cache and create a challenge.

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

from bridgedb import crypto
from bridgedb import schedule
from bridgedb.txrecaptcha import API_SSL_SERVER


class CaptchaExpired(ValueError):
    """Raised when a client's CAPTCHA is too stale."""

class CaptchaKeyError(Exception):
    """Raised if a CAPTCHA system's keys are invalid or missing."""

class GimpCaptchaError(Exception):
    """General exception raised when a Gimp CAPTCHA cannot be retrieved."""


class ICaptcha(Interface):
    """Interface specification for CAPTCHAs."""

    image = Attribute(
        "A string containing the contents of a CAPTCHA image file.")
    challenge = Attribute(
        "A unique string associated with the dispursal of this CAPTCHA.")
    publicKey = Attribute(
        "A public key used for encrypting CAPTCHA challenge strings.")
    secretKey = Attribute(
        "A private key used for decrypting challenge strings during CAPTCHA"
        "solution verification.")

    def get():
        """Retrieve a new CAPTCHA image."""


class Captcha(object):
    """A generic CAPTCHA base class.

    :ivar str image: The CAPTCHA image.
    :ivar str challenge: A challenge string which should permit checking of
        the client's CAPTCHA solution in some manner. In stateless protocols
        such as HTTP, this should be passed along to the client with the
        CAPTCHA image.
    :ivar publicKey: A public key used for encrypting CAPTCHA challenge strings.
    :ivar secretKey: A private key used for decrypting challenge strings during
        CAPTCHA solution verification.
    """
    implements(ICaptcha)

    def __init__(self, publicKey=None, secretKey=None):
        """Obtain a new CAPTCHA for a client."""
        self.image = None
        self.challenge = None
        self.publicKey = publicKey
        self.secretKey = secretKey

    def get(self):
        """Retrieve a new CAPTCHA image and its associated challenge string.

        The image and challenge will be stored as :ivar:`image` and
        :ivar:`challenge, respectively.
        """
        self.image = None
        self.challenge = None


class ReCaptcha(Captcha):
    """A CAPTCHA obtained from a remote reCaptcha_ API server.

    :ivar str image: The CAPTCHA image.
    :ivar str challenge: The ``'recaptcha_challenge_response'`` HTTP form
        field to pass to the client, along with the CAPTCHA image. See
        :doc:`BridgeDB's captcha.html <templates/captcha.html>` Mako_ template
        for an example usage.
    :ivar str publicKey: The public reCaptcha API key.
    :ivar str secretKey: The private reCaptcha API key.

    .. _reCaptcha: https://code.google.com/p/recaptcha/
    .. _Mako: http://docs.makotemplates.org/en/latest/syntax.html#page
    """

    def __init__(self, publicKey=None, secretKey=None):
        """Create a new ReCaptcha CAPTCHA.

        :param str publicKey: The public reCaptcha API key.
        :param str secretKey: The private reCaptcha API key.
        """
        super(ReCaptcha, self).__init__(publicKey=publicKey,
                                        secretKey=secretKey)

    def get(self):
        """Retrieve a CAPTCHA from the reCaptcha API server.

        This simply requests a new CAPTCHA from
        ``recaptcha.client.captcha.API_SSL_SERVER`` and parses the returned
        HTML to extract the CAPTCHA image and challenge string. The image is
        stored at ``ReCaptcha.image`` and the challenge string at
        ``ReCaptcha.challenge``.

        :raises CaptchaKeyError: If either the :ivar:`publicKey` or
            :ivar:`secretKey` are missing.
        :raises HTTPError: If the server returned any HTTP error status code.
        """
        if not self.publicKey or not self.secretKey:
            raise CaptchaKeyError('You must supply recaptcha API keys')

        urlbase = API_SSL_SERVER
        form = "/noscript?k=%s" % self.publicKey

        # Extract and store image from recaptcha
        html = urllib2.urlopen(urlbase + form).read()
        # FIXME: The remaining lines currently cannot be reliably unit tested:
        soup = BeautifulSoup(html)                           # pragma: no cover
        imgurl = urlbase + "/" +  soup.find('img')['src']    # pragma: no cover
        cField = soup.find(                                  # pragma: no cover
            'input', {'name': 'recaptcha_challenge_field'})  # pragma: no cover
        self.challenge = str(cField['value'])                # pragma: no cover
        self.image = urllib2.urlopen(imgurl).read()          # pragma: no cover


class GimpCaptcha(Captcha):
    """A locally cached CAPTCHA image which was created with gimp-captcha_.

    :ivar str secretKey: A PKCS#1 OAEP-padded, private RSA key, used for
        verifying the client's solution to the CAPTCHA.
    :ivar str publickey: A PKCS#1 OAEP-padded, public RSA key. This is used to
        hide the correct CAPTCHA solution within the
        ``captcha_challenge_field`` HTML form field. That form field is given
        to the a client along with the :ivar:`image` during the initial
        CAPTCHA request, and the client *should* give it back to us later
        during the CAPTCHA solution verification step.
    :ivar bytes hmacKey: A client-specific HMAC secret key.
    :ivar str cacheDir: The local directory which pre-generated CAPTCHA images
        have been stored in. This can be set via the ``GIMP_CAPTCHA_DIR``
        setting in the config file.
    :type sched: :class:`bridgedb.schedule.ScheduledInterval`
    :ivar sched: An time interval. After this much time has passed, the
        CAPTCHA is considered stale, and all solutions are considered invalid
        regardless of their correctness.

    .. _gimp-captcha: https://github.com/isislovecruft/gimp-captcha
    """

    sched = schedule.ScheduledInterval('minutes', 30)

    def __init__(self, publicKey=None, secretKey=None, hmacKey=None,
                 cacheDir=None):
        """Create a ``GimpCaptcha`` which retrieves images from **cacheDir**.

        :param str publickey: A PKCS#1 OAEP-padded, public RSA key, used for
            creating the ``captcha_challenge_field`` string to give to a
            client.
        :param str secretKey: A PKCS#1 OAEP-padded, private RSA key, used for
            verifying the client's solution to the CAPTCHA.
        :param bytes hmacKey: A client-specific HMAC secret key.
        :param str cacheDir: The local directory which pre-generated CAPTCHA
            images have been stored in. This can be set via the
            ``GIMP_CAPTCHA_DIR`` setting in the config file.
        :raises GimpCaptchaError: if :ivar:`cacheDir` is not a directory.
        :raises CaptchaKeyError: if any of :ivar:`secretKey`,
            :ivar:`publicKey`, or :ivar:`hmacKey` are invalid or missing.
        """
        if not cacheDir or not os.path.isdir(cacheDir):
            raise GimpCaptchaError("Gimp captcha cache isn't a directory: %r"
                                   % cacheDir)
        if not (publicKey and secretKey and hmacKey):
            raise CaptchaKeyError(
                "Invalid key supplied to GimpCaptcha: SK=%r PK=%r HMAC=%r"
                % (secretKey, publicKey, hmacKey))

        super(GimpCaptcha, self).__init__(publicKey=publicKey,
                                          secretKey=secretKey)
        self.hmacKey = hmacKey
        self.cacheDir = cacheDir
        self.answer = None

    @classmethod
    def check(cls, challenge, solution, secretKey, hmacKey):
        """Check a client's CAPTCHA **solution** against the **challenge**.

        :param str challenge: The contents of the
            ``'captcha_challenge_field'`` HTTP form field.
        :param str solution: The client's proposed solution to the CAPTCHA
            that they were presented with.
        :param str secretKey: A PKCS#1 OAEP-padded, private RSA key, used for
            verifying the client's solution to the CAPTCHA.
        :param bytes hmacKey: A private key for generating HMACs.
        :raises CaptchaExpired: if the **solution** was for a stale CAPTCHA.
        :rtype: bool
        :returns: ``True`` if the CAPTCHA solution was correct and not
            stale. ``False`` otherwise.
        """
        hmacIsValid = False

        if not solution:
            return hmacIsValid

        logging.debug("Checking CAPTCHA solution %r against challenge %r"
                      % (solution, challenge))
        try:
            decoded = urlsafe_b64decode(challenge)
            hmacFromBlob = decoded[:20]
            encBlob = decoded[20:]
            hmacNew = crypto.getHMAC(hmacKey, encBlob)
            hmacIsValid = hmacNew == hmacFromBlob
        except Exception:
            return False
        finally:
            if hmacIsValid:
                try:
                    answerBlob = secretKey.decrypt(encBlob)

                    timestamp = answerBlob[:12].lstrip('0')
                    then = cls.sched.nextIntervalStarts(int(timestamp))
                    now = int(time.time())
                    answer = answerBlob[12:]
                except Exception as error:
                    logging.warn(error.message)
                else:
                    # If the beginning of the 'next' interval (the interval
                    # after the one when the CAPTCHA timestamp was created)
                    # has already passed, then the CAPTCHA is stale.
                    if now >= then:
                        exp = schedule.fromUnixSeconds(then).isoformat(sep=' ')
                        raise CaptchaExpired("Solution %r was for a CAPTCHA "
                                             "which already expired at %s."
                                             % (solution, exp))
                    if solution.lower() == answer.lower():
                        return True
            return False

    def createChallenge(self, answer):
        """Encrypt-then-HMAC a timestamp plus the CAPTCHA **answer**.

        A challenge string consists of a URL-safe, base64-encoded string which
        contains an ``HMAC`` concatenated with an ``ENC_BLOB``, in the
        following form::

            CHALLENGE := B64( HMAC | ENC_BLOB )
            ENC_BLOB := RSA_ENC( ANSWER_BLOB )
            ANSWER_BLOB := ( TIMESTAMP | ANSWER )

        where
          * ``B64`` is a URL-safe base64-encode function,
          * ``RSA_ENC`` is the PKCS#1 RSA-OAEP encryption function,
          * and the remaining feilds are specified as follows:

        +-------------+--------------------------------------------+----------+
        | Field       | Description                                | Length   |
        +=============+============================================+==========+
        | HMAC        | An HMAC of the ``ENC_BLOB``, created with  | 20 bytes |
        |             | the client-specific :ivar:`hmacKey`, by    |          |
        |             | applying :func:`~crypto.getHMAC` to the    |          |
        |             | ``ENC_BLOB``.                              |          |
        +-------------+--------------------------------------------+----------+
        | ENC_BLOB    | An encrypted ``ANSWER_BLOB``, created with | varies   |
        |             | a PKCS#1 OAEP-padded RSA :ivar:`publicKey`.|          |
        +-------------+--------------------------------------------+----------+
        | ANSWER_BLOB | Contains the concatenated ``TIMESTAMP``    | varies   |
        |             | and ``ANSWER``.                            |          |
        +-------------+--------------------------------------------+----------+
        | TIMESTAMP   | A Unix Epoch timestamp, in seconds,        | 12 bytes |
        |             | left-padded with "0"s.                     |          |
        +-------------+--------------------------------------------+----------+
        | ANSWER      | A string containing answer to this         | 8 bytes  |
        |             | CAPTCHA :ivar:`image`.                     |          |
        +-------------+--------------------------------------------+----------+

        The steps taken to produce a ``CHALLENGE`` are then:

          1. Create a ``TIMESTAMP``, and pad it on the left with ``0``s to 12
             bytes in length.

          2. Next, take the **answer** to this CAPTCHA :ivar:`image: and
             concatenate the padded ``TIMESTAMP`` and the ``ANSWER``, forming
             an ``ANSWER_BLOB``.

          3. Encrypt the resulting ``ANSWER_BLOB`` to :ivar:`publicKey` to
             create the ``ENC_BLOB``.

          4. Use the client-specific :ivar:`hmacKey` to apply the
             :func:`~crypto.getHMAC` function to the ``ENC_BLOB``, obtaining
             an ``HMAC``.

          5. Create the final ``CHALLENGE`` string by concatenating the
             ``HMAC`` and ``ENC_BLOB``, then base64-encoding the result.

        :param str answer: The answer to a CAPTCHA.
        :rtype: str
        :returns: A challenge string.
        """
        timestamp = str(int(time.time())).zfill(12)
        blob = timestamp + answer
        encBlob = self.publicKey.encrypt(blob)
        hmac = crypto.getHMAC(self.hmacKey, encBlob)
        challenge = urlsafe_b64encode(hmac + encBlob)
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

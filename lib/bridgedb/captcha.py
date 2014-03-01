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

import urllib2

from BeautifulSoup import BeautifulSoup
from recaptcha.client import captcha as recaptcha
from zope.interface import Interface, Attribute, implements


class ReCaptchaKeyError(Exception):
    """Exception raised when recaptcha API keys are not supplied"""

    def __init__(self):
        msg = 'You must supply recaptcha API keys'
        Exception.__init__(self, msg)

class ICaptcha(Interface):
    """Interface specification for CAPTCHAs."""
    image = Attribute("A CAPTCHA image.")

    def get(self):
        """Retrieve a new CAPTCHA."""
        return None

class Captcha(object):
    """A generic CAPTCHA object."""
    implements(ICaptcha)

    def __init__(self):
        self.image = None

    def get(self):
        return self.image

class ReCaptcha(Captcha):
    """A reCaptcha CAPTCHA."""

    def __init__(self, pubkey=None, privkey=None):
        self.pubkey = pubkey
        self.privkey = privkey
        self.image = None
        super(ReCaptcha, self).__init__()

    def get(self):
        """Retrieve a CAPTCHA from the reCaptcha API server.

        This simply requests a new CAPTCHA from
        ``recaptcha.client.captcha.API_SSL_SERVER`` and parses the returned
        HTML to extract the CAPTCHA image and challenge string. The image is
        stored at ``ReCaptcha.image`` and the challenge string at
        ``ReCaptcha.challenge``.
        """
        if (self.pubkey == '') or (self.privkey == ''):
            raise ReCaptchaKeyError
        urlbase = recaptcha.API_SSL_SERVER
        form = "/noscript?k=%s" % self.pubkey

        # extract and store image from captcha
        html = urllib2.urlopen(urlbase+form).read()
        soup = BeautifulSoup(html)
        imgurl = urlbase+"/"+ soup.find('img')['src']
        self.challenge = str(soup.find('input', {'name' : 'recaptcha_challenge_field'})['value'])
        self.image = urllib2.urlopen(imgurl).read()


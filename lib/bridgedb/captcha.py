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

"""
This module wraps the recaptcha api and proxies requests to protect privacy.
"""

from recaptcha.client import captcha as recaptcha
from BeautifulSoup import BeautifulSoup
import urllib2

class Raptcha():
    """ A recaptcha captcha and method to request them """

    def __init__(self, pubkey=None, privkey=None):
        self.pubkey = pubkey
        self.privkey = privkey
        self.image = None
        self.challenge = None

    def get(self):
        """ gets a fresh captcha """

        if (self.pubkey == '') or (self.privkey == ''):
            raise RaptchaKeyError
        urlbase = recaptcha.API_SERVER
        form = "/noscript?k=%s" % self.pubkey

        # extract and store image from captcha
        html = urllib2.urlopen(urlbase+form).read()
        soup = BeautifulSoup(html)
        imgurl = urlbase+"/"+ soup.find('img')['src']
        self.challenge = str(soup.find('input', {'name' : 'recaptcha_challenge_field'})['value'])
        self.image = urllib2.urlopen(imgurl).read()

class RaptchaKeyError(Exception):
    """ Exception raised when recaptcha API keys are not supplied"""
    def __init__(self):
        msg = 'You must supply recaptcha API keys'
        Exception.__init__(self, msg)

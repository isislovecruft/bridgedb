# Raptcha
# Copyright (c) 2010, The Tor Project, Inc.
# See LICENSE for licensing information

"""
This module wraps the recaptcha api and proxies requests to protect privacy.
"""
import recaptcha.client.captcha as captcha
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
        urlbase = captcha.API_SERVER
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

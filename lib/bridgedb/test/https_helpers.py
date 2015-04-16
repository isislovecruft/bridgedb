# -*- coding: utf-8 -*-
#
# This file is part of BridgeDB, a Tor bridge distribution system.
#
# :authors: Isis Lovecruft 0xA3ADB67A2CDB8B35 <isis@torproject.org>
# :copyright: (c) 2013-2015, Isis Lovecruft
#             (c) 2007-2015, The Tor Project, Inc.
# :license: see LICENSE for licensing information


"""Helpers for testing the HTTPS Distributor and its servers."""


import io

from twisted.web.test import requesthelper

from bridgedb.test import util
from bridgedb.persistent import Conf


SERVER_PUBLIC_FQDN = 'bridges.torproject.org'
SERVER_PUBLIC_EXTERNAL_IP = '38.229.72.19'
HTTPS_DIST = True
HTTPS_BIND_IP = None
HTTPS_PORT = None
HTTPS_N_BRIDGES_PER_ANSWER = 3
HTTPS_INCLUDE_FINGERPRINTS = True
HTTPS_KEY_FILE = 'privkey.pem'
HTTPS_CERT_FILE = 'cert'
N_IP_CLUSTERS = 4
HTTPS_ROTATION_PERIOD = "3 hours"
HTTP_UNENCRYPTED_BIND_IP = None
HTTP_UNENCRYPTED_PORT = None
HTTP_USE_IP_FROM_FORWARDED_HEADER = False
RECAPTCHA_ENABLED = False
RECAPTCHA_PUB_KEY = ''
RECAPTCHA_SEC_KEY = ''
RECAPTCHA_REMOTEIP = ''
GIMP_CAPTCHA_ENABLED = True
GIMP_CAPTCHA_DIR = 'captchas'
GIMP_CAPTCHA_HMAC_KEYFILE = 'captcha_hmac_key'
GIMP_CAPTCHA_RSA_KEYFILE = 'captcha_rsa_key'

TEST_CONFIG_FILE = io.StringIO(unicode("""\
SERVER_PUBLIC_FQDN = %r
SERVER_PUBLIC_EXTERNAL_IP = %r
HTTPS_DIST = %r
HTTPS_BIND_IP = %r
HTTPS_PORT = %r
HTTPS_N_BRIDGES_PER_ANSWER = %r
HTTPS_INCLUDE_FINGERPRINTS = %r
HTTPS_KEY_FILE = %r
HTTPS_CERT_FILE = %r
N_IP_CLUSTERS = %r
HTTPS_ROTATION_PERIOD = %r
HTTP_UNENCRYPTED_BIND_IP = %r
HTTP_UNENCRYPTED_PORT = %r
HTTP_USE_IP_FROM_FORWARDED_HEADER = %r
RECAPTCHA_ENABLED = %r
RECAPTCHA_PUB_KEY = %r
RECAPTCHA_SEC_KEY = %r
RECAPTCHA_REMOTEIP = %r
GIMP_CAPTCHA_ENABLED = %r
GIMP_CAPTCHA_DIR = %r
GIMP_CAPTCHA_HMAC_KEYFILE = %r
GIMP_CAPTCHA_RSA_KEYFILE = %r
""" % (SERVER_PUBLIC_FQDN,
       SERVER_PUBLIC_EXTERNAL_IP,
       HTTPS_DIST,
       HTTPS_BIND_IP,
       HTTPS_PORT,
       HTTPS_N_BRIDGES_PER_ANSWER,
       HTTPS_INCLUDE_FINGERPRINTS,
       HTTPS_KEY_FILE,
       HTTPS_CERT_FILE,
       N_IP_CLUSTERS,
       HTTPS_ROTATION_PERIOD,
       HTTP_UNENCRYPTED_BIND_IP,
       HTTP_UNENCRYPTED_PORT,
       HTTP_USE_IP_FROM_FORWARDED_HEADER,
       RECAPTCHA_ENABLED,
       RECAPTCHA_PUB_KEY,
       RECAPTCHA_SEC_KEY,
       RECAPTCHA_REMOTEIP,
       GIMP_CAPTCHA_ENABLED,
       GIMP_CAPTCHA_DIR,
       GIMP_CAPTCHA_HMAC_KEYFILE,
       GIMP_CAPTCHA_RSA_KEYFILE)))


def _createConfig(configFile=TEST_CONFIG_FILE):
    configuration = {}
    TEST_CONFIG_FILE.seek(0)
    compiled = compile(configFile.read(), '<string>', 'exec')
    exec compiled in configuration
    config = Conf(**configuration)
    return config


class DummyIPBasedDistributor(object):
    """A mocked :class:`bridgedb.Dist.IPBasedDistributor` which is used to test
    :class:`bridgedb.https.server.BridgesResource`.
    """
    _bridge_class = util.DummyBridge
    _bridgesPerResponseMin = 3

    def getBridges(self, bridgeRequest=None, epoch=None, N=1):
        """Needed because it's called in
        :meth:`BridgesResource.getBridgeRequestAnswer`."""
        return [self._bridge_class() for _ in range(self._bridgesPerResponseMin)]


class DummyRequest(requesthelper.DummyRequest):
    """Wrapper for :api:`twisted.test.requesthelper.DummyRequest` to add
    redirect support.
    """
    def __init__(self, *args, **kwargs):
        requesthelper.DummyRequest.__init__(self, *args, **kwargs)
        self.redirect = self._redirect(self)

    def URLPath(self):
        """Fake the missing Request.URLPath too."""
        return self.uri

    def _redirect(self, request):
        """Stub method to add a redirect() method to DummyResponse."""
        newRequest = type(request)
        newRequest.uri = request.uri
        return newRequest

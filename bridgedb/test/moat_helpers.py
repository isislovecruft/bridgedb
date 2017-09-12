# -*- coding: utf-8 -*-
#
# This file is part of BridgeDB, a Tor bridge distribution system.
#
# :authors: Isis Lovecruft 0xA3ADB67A2CDB8B35 <isis@torproject.org>
# :copyright: (c) 2013-2017, Isis Lovecruft
#             (c) 2007-2017, The Tor Project, Inc.
# :license: see LICENSE for licensing information


"""Helpers for testing the HTTPS Distributor and its servers."""


import io

from bridgedb.persistent import Conf

from . import util


GIMP_CAPTCHA_DIR = 'captchas'
SERVER_PUBLIC_FQDN = 'bridges.torproject.org'
SUPPORTED_TRANSPORTS = {
    'obfs2': False,
    'obfs3': True,
    'obfs4': True,
    'scramblesuit': True,
    'fte': True,
}
MOAT_DIST = True
MOAT_DIST_VIA_MEEK_ONLY = True
MOAT_TLS_CERT_FILE="moat-tls.crt"
MOAT_TLS_KEY_FILE="moat-tls.pem"
if MOAT_DIST_VIA_MEEK_ONLY:
    MOAT_SERVER_PUBLIC_ROOT = '/meek/moat'
else:
    MOAT_SERVER_PUBLIC_ROOT = '/moat'
MOAT_BRIDGES_PER_ANSWER = 3
MOAT_TRANSPORT_PREFERENCE_LIST = ["obfs4", "vanilla"]
MOAT_HTTPS_IP = '127.0.0.1'
MOAT_HTTPS_PORT = None
MOAT_HTTP_IP = None
MOAT_HTTP_PORT = None
MOAT_USE_IP_FROM_FORWARDED_HEADER = True
MOAT_N_IP_CLUSTERS = 4
MOAT_ROTATION_PERIOD = "3 hours"
MOAT_GIMP_CAPTCHA_HMAC_KEYFILE = 'moat_captcha_hmac_key'
MOAT_GIMP_CAPTCHA_RSA_KEYFILE = 'moat_captcha_rsa_key'

TEST_CONFIG_FILE = io.StringIO(unicode("""\
GIMP_CAPTCHA_DIR = %r
SERVER_PUBLIC_FQDN = %r
SUPPORTED_TRANSPORTS = %r
MOAT_DIST = %r
MOAT_DIST_VIA_MEEK_ONLY = %r
MOAT_TLS_CERT_FILE = %r
MOAT_TLS_KEY_FILE = %r
MOAT_SERVER_PUBLIC_ROOT = %r
MOAT_HTTPS_IP = %r
MOAT_HTTPS_PORT = %r
MOAT_HTTP_IP = %r
MOAT_HTTP_PORT = %r
MOAT_BRIDGES_PER_ANSWER = %r
MOAT_TRANSPORT_PREFERENCE_LIST = %r
MOAT_USE_IP_FROM_FORWARDED_HEADER = %r
MOAT_N_IP_CLUSTERS = %r
MOAT_ROTATION_PERIOD = %r
MOAT_GIMP_CAPTCHA_HMAC_KEYFILE = %r
MOAT_GIMP_CAPTCHA_RSA_KEYFILE = %r
""" % (GIMP_CAPTCHA_DIR,
       SERVER_PUBLIC_FQDN,
       SUPPORTED_TRANSPORTS,
       MOAT_DIST,
       MOAT_DIST_VIA_MEEK_ONLY,
       MOAT_TLS_CERT_FILE,
       MOAT_TLS_KEY_FILE,
       MOAT_SERVER_PUBLIC_ROOT,
       MOAT_HTTPS_IP,
       MOAT_HTTPS_PORT,
       MOAT_HTTP_IP,
       MOAT_HTTP_PORT,
       MOAT_BRIDGES_PER_ANSWER,
       MOAT_TRANSPORT_PREFERENCE_LIST,
       MOAT_USE_IP_FROM_FORWARDED_HEADER,
       MOAT_N_IP_CLUSTERS,
       MOAT_ROTATION_PERIOD,
       MOAT_GIMP_CAPTCHA_HMAC_KEYFILE,
       MOAT_GIMP_CAPTCHA_RSA_KEYFILE)))

def _createConfig(configFile=TEST_CONFIG_FILE):
    configuration = {}
    TEST_CONFIG_FILE.seek(0)
    compiled = compile(configFile.read(), '<string>', 'exec')
    exec compiled in configuration
    config = Conf(**configuration)
    return config


class DummyMoatDistributor(object):
    """A mocked :class:`bridgedb.distributors.moat.distributor.MoatDistributor`
    which is used to test
    :class:`bridgedb.distributors.moat.server.CaptchaFetchResource`.
    """
    _bridge_class = util.DummyBridge
    _bridgesPerResponseMin = 3

    def getBridges(self, bridgeRequest=None, epoch=None):
        """Needed because it's called in
        :meth:`BridgesResource.getBridgeRequestAnswer`."""
        return [self._bridge_class() for _ in range(self._bridgesPerResponseMin)]

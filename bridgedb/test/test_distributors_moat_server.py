# -*- coding: utf-8 -*-
#_____________________________________________________________________________
#
# This file is part of BridgeDB, a Tor bridge distribution system.
#
# :authors: Isis Lovecruft 0xA3ADB67A2CDB8B35 <isis@torproject.org>
# :copyright: (c) 2014-2017, Isis Lovecruft
#             (c) 2014-2017, The Tor Project, Inc.
# :license: see LICENSE for licensing information
#_____________________________________________________________________________

"""Unittests for :mod:`bridgedb.distributors.moat.server`."""

from __future__ import print_function

import base64
import io
import json
import logging
import os
import shutil
import tempfile

from twisted.trial import unittest
from twisted.web.resource import Resource
from twisted.web.test import requesthelper

from bridgedb import crypto
from bridgedb.distributors.moat import server
from bridgedb.schedule import ScheduledInterval

from bridgedb.test.moat_helpers import _createConfig
from bridgedb.test.moat_helpers import DummyMoatDistributor
from bridgedb.test.https_helpers import DummyRequest
from bridgedb.test.util import DummyBridge
from bridgedb.test.util import DummyMaliciousBridge


# For additional logger output for debugging, comment out the following:
logging.disable(50)
# and then uncomment the following line:
#server.logging.getLogger().setLevel(10)


# These keys are hardcoded so that we can test both expired and
# unexpired CAPTCHAs which were/are produced with them.
CAPTCHA_KEY = base64.b64decode("tFh0hkskhDBulvBtYkYy7qlQhyZh2MKsIOfaAmmvinQ=")
HMAC_KEY = base64.b64decode("vJPta7PflEb/qalt5Klgn9wyfgs=")

SECRET_KEY = crypto.PKCS1_OAEP.new(crypto.RSA.importKey("""\
-----BEGIN RSA PRIVATE KEY-----
MIIEpQIBAAKCAQEAtz551eYMzSE8a56TGFRt4+bhZOgVCShBjaXv0LfuFtF4KXhv
cMXG8Zo9jw0M8HCk9YLhb40bLaeSxemcoaHiuC/zxgL8ECQ7GMVO6vi409UWRnl7
VpCqyFPXg+V89TM67IsMejT8CDG4g62DYgSQ0Fpl5AsFd3RN2mQ38qdrmoBTXxQt
cmMXkEgDN20ZoVRFbWa+KurX9pv74wtNqUY2uUMxyGwXIrBfi6O3cyyjUAoSXsJT
iuKmgcuzE9+fDKzMftEf+k8OSs/DQWYARefQBCTndzha9ICwxFM5L3CWsPQxKtS4
mkILRGLZSHYeswynwH98Swimgyv2FSqOZN9eYQIDAQABAoIBAQC0S1JQ9RKvWf46
3UFZdOjSjb5DLF5WLjehiR0WPYKTDPKvywHK8a221c2vzGVoxUxpC6eHvEx7dR9i
f2JPXhrWose1kgY0U5GZ47isVKB2PHi4SpriJ2EBzgyEh+2UzB0z0/Qo4a0A2vrz
BGv6qwdZGTibUYTFbbeUI3sw0y16SxHPeGaYtfyLcx5/Nwd92V9NZ1pyaivVt4Uu
XgHnYxG7Y1uurSv6sdPouUN+H1o9msBm6EMRXjDrCAyVr0gmH2KQmnWedwSiY+eh
n5hP8jkOEQntxirMM5AR8N/KSXJdt9nccRPbamInn4eK1wlOzJJzwLpu8hhwJ+fc
6dWfBP9hAoGBAMxiSDtYqai6hTongIyKasycm14F0Xzcd5dVBwW1ANLdWbC32ti9
n7i6TD7Fe2vfmiNpylMLbYLt5zODHT3eb3l1cWWpvkrMmxkvfj3to9sJfCg2p+jt
WzxugmSu9qO03C9nhSsFlD2Li754nPVCa5gk/1Gnxt9+RRI2Qzb7r1GFAoGBAOWF
eHJAO2SmZBc9doRqUgQXcZin/60f9PpxPqHtT8NzBItSxPSlkGYspDJaxPZfl5Y1
7MZMNN6vBTitKXO3JXYZwCD+Y8s+trd/qm/vbco2SinWlgRlZyqcyBCvGKfBMUg/
Nr8mRPyZ18yBEj5OtYadJcRCERk3ERWSt/ndLwItAoGAC/20KS8xfQG8cUYCB7zT
OT/y6ZhDyySQK6PEbrRI4RY1feW7hD3T0h2z/XbOn+yVeYBqa2bfPPBCQUZu/8M+
HQ0j4wgLbw4EB30+1dlMZLxwuVdDkKnkUW5WXhvZwo8I4AsdyAFiyh2WzEz9QHJu
J5X8GMlUJKae3MusM9yeU5UCgYEAw8unYzd+My9qZRTunKkiTBE/u61dA/AmCNtA
Rdxu1dmxf7TdBaKTW0Yr0DT0nwQPCXn5AXSTCYAeoSm/GdKb53KyHrNEqGZYcpM6
7wA+FWlYvPYsxZVHe+eBGBJ2ouzAwNQEPO5FnYMTv4Y/7N0yJ6K5TAHcGjmKnm+p
+EICTwUCgYEArF7zfcaxRXQtNKKEIYR9Q+zL/+fQEF2lxre61UNxpS0CmDrrAZwu
oa7cfLxocTUpYp7atUINzwVQgVd6AWta3v/PoXhkxo/CRd7pheyeH/ypFa7vAkzO
zZAlI9uLR/7XevId2W7b8U+8AWtxi3RLXSId9QzGRvjkoThBAKfLM30=
-----END RSA PRIVATE KEY-----"""))

PUBLIC_KEY = crypto.PKCS1_OAEP.new(crypto.RSA.importKey("""\
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtz551eYMzSE8a56TGFRt
4+bhZOgVCShBjaXv0LfuFtF4KXhvcMXG8Zo9jw0M8HCk9YLhb40bLaeSxemcoaHi
uC/zxgL8ECQ7GMVO6vi409UWRnl7VpCqyFPXg+V89TM67IsMejT8CDG4g62DYgSQ
0Fpl5AsFd3RN2mQ38qdrmoBTXxQtcmMXkEgDN20ZoVRFbWa+KurX9pv74wtNqUY2
uUMxyGwXIrBfi6O3cyyjUAoSXsJTiuKmgcuzE9+fDKzMftEf+k8OSs/DQWYARefQ
BCTndzha9ICwxFM5L3CWsPQxKtS4mkILRGLZSHYeswynwH98Swimgyv2FSqOZN9e
YQIDAQAB
-----END PUBLIC KEY-----"""))


class MiscellaneousTests(unittest.TestCase):
    """Tests for helper functions in :mod:`bridgedb.distributors.moat.server`."""

    def setUp(self):
        self.config = _createConfig()

    def test_setRoot(self):
        """If we call `setRoot()` with `root="/meek/moat"` then the public
        root directory of the server should be "/meek/moat".
        """
        server.setRoot("/meek/moat")
        self.assertEqual(server.getRoot(), "/meek/moat")

    def test_getFQDNAndRoot(self):
        """If the FQDN is set to "bridges.torproject.org" and we call `setRoot()`
        with `root="/meek/moat"` then the public root directory of the server
        should be "/meek/moat".
        """
        server.setFQDN("bridges.torproject.org", https=True)
        server.setRoot("/meek/moat")

        self.assertEqual(server.getFQDNAndRoot(),
                         "https://bridges.torproject.org/meek/moat")

    def test_getFQDNAndRoot_no_slash(self):
        """If the FQDN is set to "bridges.torproject.org" and we call `setRoot()`
        with `root="meek/moat"` then the public root directory of the server
        should be "bridges.torproject.org/meek/moat".
        """
        server.setFQDN("bridges.torproject.org", https=True)
        server.setRoot("meek/moat")  # missing the "/" prefix

        self.assertEqual(server.getFQDNAndRoot(),
                         "https://bridges.torproject.org/meek/moat")

    def test_setPreferredTransports(self):
        """Setting the pluggable transport preference list to ["dinosaur"]
        should set it thusly.
        """
        prefs = ["dinosaur"]

        server.setPreferredTransports(prefs)

        self.assertEqual(server.getPreferredTransports(), prefs)

    def test_setSupportedPreferences(self):
        """Taking the ``SUPPORTED_TRANSPORTS`` config option (a dict) and
        passing it to ``setSupportedTransports()`` should convert it into a list
        for the items in the dict whose value was ``True``.
        """
        server.setSupportedTransports(self.config.SUPPORTED_TRANSPORTS)

        self.assertItemsEqual(server.getSupportedTransports(),
                              ["obfs4", "obfs3", "scramblesuit", "fte", "vanilla"])


class JsonAPIResourceTests(unittest.TestCase):
    """Tests for :class:`bridgedb.distributors.moat.server.JsonAPIResource`."""

    def setUp(self):
        self.pagename = b''
        self.resource = server.JsonAPIResource()
        self.root = Resource()
        self.root.putChild(self.pagename, self.resource)

    def test_getClientIP(self):
        request = DummyRequest([self.pagename])
        request.method = b'GET'

        self.resource.getClientIP(request)

    def test_formatDataForResponse(self):
        request = DummyRequest([self.pagename])
        request.method = b'GET'

        data = {'data': { 'version': 'wow',
                          'dinosaurs': 'cool',
                          'triceratops': 'awesome',
                          'velociraptors': 'terrifying', }}

        rendered = self.resource.formatDataForResponse(data, request)

        self.assertTrue(rendered)
        self.assertTrue(request.responseHeaders.hasHeader('content-type'))
        self.assertTrue(request.responseHeaders.hasHeader('server'))
        self.assertEqual(request.responseHeaders.getRawHeaders('content-type'),
                         ['application/vnd.api+json'])

    def test_formatDataForResponse_no_data(self):
        request = DummyRequest([self.pagename])
        request.method = b'GET'

        rendered = self.resource.formatDataForResponse(None, request)

        self.assertEqual(rendered, b'')


class JsonAPIErrorResourceTests(unittest.TestCase):
    """Tests for :class:`bridgedb.distributors.moat.server.JsonAPIErrorResource`."""

    def setUp(self):
        self.pagename = b''
        self.root = Resource()

    def use_resource(self, resource):
        self.resource = resource
        self.root.putChild(self.pagename, self.resource)

    def do_render_for_method(self, method):
        request = DummyRequest([self.pagename])
        request.method = method

        rendered = self.resource.render(request)

        self.assertTrue(rendered)
        self.assertTrue(request.responseHeaders.hasHeader('content-type'))
        self.assertTrue(request.responseHeaders.hasHeader('server'))
        self.assertEqual(request.responseHeaders.getRawHeaders('content-type'),
                         ['application/vnd.api+json'])

        decoded = json.loads(rendered)

        self.assertTrue(decoded)
        self.assertIsNotNone(decoded.get('errors'))

        errors = decoded['errors']

        self.assertEqual(len(errors), 1)

        error = errors[0]

        return error

    def test_render_GET(self):
        self.use_resource(server.JsonAPIErrorResource())
        error = self.do_render_for_method(b'GET')

    def test_render_POST(self):
        self.use_resource(server.JsonAPIErrorResource())
        error = self.do_render_for_method(b'POST')

    def test_resource200_render_GET(self):
        self.use_resource(server.JsonAPIErrorResource())
        error = self.do_render_for_method(b'GET')

        self.assertEqual(error['id'], 0)
        self.assertEqual(error['type'], '')
        self.assertEqual(error['code'], 200)
        self.assertEqual(error['status'], 'OK')
        self.assertEqual(error['detail'], '')

    def test_resource403_render_GET(self):
        self.use_resource(server.resource403)
        error = self.do_render_for_method(b'GET')

        self.assertEqual(error['code'], 403)
        self.assertEqual(error['status'], 'Forbidden')

    def test_resource406_render_GET(self):
        self.use_resource(server.resource406)
        error = self.do_render_for_method(b'GET')

        self.assertEqual(error['code'], 406)
        self.assertEqual(error['status'], 'Not Acceptable')

    def test_resource415_render_GET(self):
        self.use_resource(server.resource415)
        error = self.do_render_for_method(b'GET')

        self.assertEqual(error['code'], 415)
        self.assertEqual(error['status'], 'Unsupported Media Type')

    def test_resource419_render_GET(self):
        self.use_resource(server.resource419)
        error = self.do_render_for_method(b'GET')

        self.assertEqual(error['code'], 419)
        self.assertEqual(error['status'], "No You're A Teapot")

    def test_resource501_render_GET(self):
        self.use_resource(server.resource501)
        error = self.do_render_for_method(b'GET')

        self.assertEqual(error['code'], 501)
        self.assertEqual(error['status'], 'Not Implemented')


class CustomErrorHandlingResourceTests(unittest.TestCase):
    """Tests for :class:`bridgedb.distributors.moat.server.CustomErrorHandlingResource`."""

    def setUp(self):
        self.pagename = b''
        self.resource = server.CustomErrorHandlingResource()
        self.root = Resource()
        self.root.putChild(self.pagename, self.resource)

    def test_getChild(self):
        request = DummyRequest(['foo'])
        request.method = b'GET'
        response_resource = self.resource.getChild('/foo', request)

        self.assertTrue(response_resource)
        self.assertIsInstance(response_resource, server.JsonAPIErrorResource)

        response = response_resource.render(request)
        detail = json.loads(response)['errors'][0]['detail']

        self.assertIn('does not implement GET http://dummy/', detail)


class JsonAPIDataResourceTests(unittest.TestCase):
    """Tests for :class:`bridgedb.distributors.moat.server.JsonAPIDataResource`."""

    def setUp(self):
        self.resource = server.JsonAPIDataResource()

    def test_checkRequestHeaders_no_headers(self):
        request = DummyRequest([''])
        self.resource.checkRequestHeaders(request)

    def test_checkRequestHeaders_different_content_type(self):
        request = DummyRequest([''])
        self.resource.checkRequestHeaders(request)
        request.requestHeaders.addRawHeader('Content-Type', 'application/html')

    def test_checkRequestHeaders_with_media_type(self):
        request = DummyRequest([''])
        self.resource.checkRequestHeaders(request)
        request.requestHeaders.addRawHeader('Content-Type', 'application/vnd.api+json;mp3')


class CaptchaFetchResourceTests(unittest.TestCase):
    """Tests for :class:`bridgedb.distributors.moat.server.CaptchaFetchResource`."""

    def setUp(self):
        self.topDir = os.getcwd().rstrip('_trial_temp')
        self.captchaDir = os.path.join(self.topDir, 'captchas')
        self.captchaKey = CAPTCHA_KEY
        self.hmacKey = HMAC_KEY
        self.secretKey, self.publicKey = SECRET_KEY, PUBLIC_KEY
        self.resource = server.CaptchaFetchResource(self.hmacKey,
                                                    self.publicKey,
                                                    self.secretKey,
                                                    self.captchaDir)
        self.pagename = b'fetch'
        self.root = Resource()
        self.root.putChild(self.pagename, self.resource)

        self.make_captcha_directory()

    def make_captcha_directory(self):
        if not os.path.isdir(self.captchaDir):
            os.mkdir(self.captchaDir)

    def create_POST_with_data(self, data):
        request = DummyRequest([self.pagename])
        request.requestHeaders.addRawHeader('Content-Type', 'application/vnd.api+json')
        request.requestHeaders.addRawHeader('Accept', 'application/vnd.api+json')
        request.method = b'POST'
        request.writeContent(data)

        return request

    def create_valid_POST(self):
        data = {
            'data': [{
                'type': 'client-transports',
                'version': server.MOAT_API_VERSION,
                'supported': ['obfs4'],
            }]
        }
        encoded_data = json.dumps(data)

        return self.create_POST_with_data(encoded_data)

    def create_valid_POST_with_unsupported_transports(self):
        data = {
            'data': [{
                'type': 'client-transports',
                'version': server.MOAT_API_VERSION,
                'supported': ['obfs4', 'dinosaur', 'karlthefog'],
            }]
        }
        encoded_data = json.dumps(data)

        return self.create_POST_with_data(encoded_data)

    def test_init(self):
        self.assertTrue(self.resource)

    def test_checkRequestHeaders_missing_content_type(self):
        data = {
            'data': [{
                'type': 'client-transports',
                'version': server.MOAT_API_VERSION,
                'supported': ['obfs4'],
            }]
        }
        encoded_data = json.dumps(data)

        request = DummyRequest([self.pagename])
        request.requestHeaders.removeHeader('Content-Type')
        request.requestHeaders.addRawHeader('Accept', 'application/vnd.api+json')
        request.method = b'POST'
        request.writeContent(encoded_data)

    def test_checkRequestHeaders_missing_accept(self):
        data = {
            'data': [{
                'type': 'client-transports',
                'version': server.MOAT_API_VERSION,
                'supported': ['obfs4'],
            }]
        }
        encoded_data = json.dumps(data)

        request = DummyRequest([self.pagename])
        request.requestHeaders.addRawHeader('Content-Type', 'application/vnd.api+json')
        request.requestHeaders.removeHeader('Accept')
        request.method = b'POST'
        request.writeContent(encoded_data)

    def test_checkRequestHeaders_content_type_with_media_parameters(self):
        data = {
            'data': [{
                'type': 'client-transports',
                'version': server.MOAT_API_VERSION,
                'supported': ['obfs4'],
            }]
        }
        encoded_data = json.dumps(data)

        request = DummyRequest([self.pagename])
        request.requestHeaders.addRawHeader('Content-Type', 'application/vnd.api+json;mp3')
        request.method = b'POST'
        request.writeContent(encoded_data)

    def test_checkRequestHeaders_accept_with_media_parameters(self):
        data = {
            'data': [{
                'type': 'client-transports',
                'version': server.MOAT_API_VERSION,
                'supported': ['obfs4'],
            }]
        }
        encoded_data = json.dumps(data)

        request = DummyRequest([self.pagename])
        request.requestHeaders.addRawHeader('Accept', 'application/vnd.api+json;mp3')
        request.method = b'POST'
        request.writeContent(encoded_data)

    def test_getCaptchaImage(self):
        request = DummyRequest([self.pagename])
        request.method = b'GET'

        image, challenge = self.resource.getCaptchaImage(request)

        self.assertIsNotNone(image)
        self.assertIsNotNone(challenge)

    def test_getCaptchaImage_empty_captcha_dir(self):
        request = DummyRequest([self.pagename])
        request.method = b'GET'

        captchaDirOrig = self.resource.captchaDir
        captchaDirNew = tempfile.mkdtemp()
        self.resource.captchaDir = captchaDirNew
        image, challenge = self.resource.getCaptchaImage(request)
        self.resource.captchaDir = captchaDirOrig
        shutil.rmtree(captchaDirNew)

        self.assertIsNone(image)
        self.assertIsNone(challenge)

    def test_extractSupportedTransports_missing_type(self):
        data = {
            'data': [{
                'version': server.MOAT_API_VERSION,
                'supported': ['obfs4'],
            }]
        }
        encoded_data = json.dumps(data)
        request = self.create_POST_with_data(encoded_data)
        supported = self.resource.extractSupportedTransports(request)

    def test_extractSupportedTransports_missing_version(self):
        data = {
            'data': [{
                'type': 'client-transports',
                'supported': ['obfs4'],
            }]
        }
        encoded_data = json.dumps(data)
        request = self.create_POST_with_data(encoded_data)
        supported = self.resource.extractSupportedTransports(request)

    def test_extractSupportedTransports_missing_supported(self):
        data = {
            'data': [{
                'type': 'client-transports',
                'version': server.MOAT_API_VERSION,
            }]
        }
        encoded_data = json.dumps(data)
        request = self.create_POST_with_data(encoded_data)
        supported = self.resource.extractSupportedTransports(request)

    def test_extractSupportedTransports_wrong_type(self):
        data = {
            'data': [{
                'type': 'totoro',
                'version': server.MOAT_API_VERSION,
                'supported': ['obfs4'],
            }]
        }
        encoded_data = json.dumps(data)
        request = self.create_POST_with_data(encoded_data)
        supported = self.resource.extractSupportedTransports(request)

    def test_extractSupportedTransports_wrong_version(self):
        data = {
            'data': [{
                'type': 'client-transports',
                'version': '0.0.1', # this version never existed
                'supported': ['obfs4'],
            }]
        }
        encoded_data = json.dumps(data)
        request = self.create_POST_with_data(encoded_data)
        supported = self.resource.extractSupportedTransports(request)

    def test_extractSupportedTransports_none_supported(self):
        data = {
            'data': [{
                'type': 'client-transports',
                'version': server.MOAT_API_VERSION,
                'supported': [],
            }]
        }
        encoded_data = json.dumps(data)
        request = self.create_POST_with_data(encoded_data)
        supported = self.resource.extractSupportedTransports(request)

    def test_extractSupportedTransports_preferred_transport(self):
        request = self.create_valid_POST()
        supported = self.resource.extractSupportedTransports(request)

        self.assertEqual(supported, ['obfs4'])

    def test_extractSupportedTransports_preferred_and_unknown_transports(self):
        request = self.create_valid_POST_with_unsupported_transports()
        supported = self.resource.extractSupportedTransports(request)

        self.assertEqual(supported, ['obfs4', 'dinosaur', 'karlthefog'])

    def test_getPreferredTransports_preferred_transport(self):
        preferred = self.resource.getPreferredTransports(['obfs4'])

        self.assertEqual(preferred, 'obfs4')

    def test_getPreferredTransports_unknown_transport(self):
        preferred = self.resource.getPreferredTransports(['dinosaur'])

        self.assertItemsEqual(preferred,
                              ['obfs4', 'obfs3', 'fte', 'scramblesuit', 'vanilla'])

    def assert_data_is_ok(self, decoded):
        self.assertIsNone(decoded.get('errors'))
        self.assertIsNotNone(decoded.get('data'))

        datas = decoded['data']

        self.assertEqual(len(datas), 1)

        data = datas[0]

        self.assertEqual(data["type"], "moat-challenge")
        self.assertEqual(data["version"], server.MOAT_API_VERSION)
        self.assertIsNotNone(data["challenge"])
        self.assertIsNotNone(data["image"])
        self.assertIsNotNone(data["transport"])

    def test_render_POST(self):
        request = self.create_valid_POST()
        response = self.resource.render(request)

        decoded = json.loads(response)

        self.assertTrue(decoded)
        self.assert_data_is_ok(decoded)


class CaptchaCheckResourceTests(unittest.TestCase):
    """Tests for :class:`bridgedb.distributors.moat.server.CaptchaCheckResource`."""

    def setUp(self):
        self.topDir = os.getcwd().rstrip('_trial_temp')
        self.captchaDir = os.path.join(self.topDir, 'captchas')
        self.captchaKey = CAPTCHA_KEY
        self.hmacKey = HMAC_KEY
        self.secretKey, self.publicKey = SECRET_KEY, PUBLIC_KEY
        self.distributor = DummyMoatDistributor()
        self.schedule = ScheduledInterval("10", "minutes")
        self.resource = server.CaptchaCheckResource(self.distributor,
                                                    self.schedule, 3,
                                                    self.hmacKey,
                                                    self.publicKey,
                                                    self.secretKey,
                                                    useForwardedHeader=False)
        self.pagename = b'check'
        self.root = Resource()
        self.root.putChild(self.pagename, self.resource)

        self.solution = 'Tvx74PMy'
        self.expiredChallenge = (
            "Vu-adMmSRsgr9PmPpGAznhrBQlys3zMkczIG2YQ7AngWqWnVn2y-LdAl8iHkrqkNhn"
            "iyre02ZlUf5KD_KDqh_Km3dIoksOMW3eUuargLLnhIUldJ4PvSXPb7pwGev_FDY4gF"
            "QDcmkrhFZm6RPzFWRgJjyY-2v6HRrmAMAGjGXSXnAc-8tDvVFSpo5Cce-saZou5W4G"
            "TjzVcyG0WkXELA2nX8rozIDIr3mUyB1vb3f53KbW5b_oCEVC_LCSoxqjnS6ZSQpNzK"
            "iz_PdOD2GIGPeclwiHAWM1pOS4cQVsTQR_z4ojZbpLiSp35n4Qbb11YOoreovZzlbS"
            "7W38rAsTirkdeugcNq82AxKP3phEkyRcw--CzV")

    def create_POST_with_data(self, data):
        request = DummyRequest([self.pagename])
        request.requestHeaders.addRawHeader('Content-Type', 'application/vnd.api+json')
        request.requestHeaders.addRawHeader('Accept', 'application/vnd.api+json')
        request.method = b'POST'

        request.writeContent(data)

        return request

    def create_valid_POST_with_challenge(self, challenge):
        data = {
            'data': [{
                'id': 2,
                'type': 'moat-solution',
                'version': server.MOAT_API_VERSION,
                'transport': 'obfs4',
                'challenge': challenge,
                'solution': self.solution,
                'qrcode': False,
            }]
        }
        encoded_data = json.dumps(data)

        return self.create_POST_with_data(encoded_data)

    def create_valid_POST_make_new_challenge(self):
        request = DummyRequest([self.pagename])
        request.client = requesthelper.IPv4Address('TCP', '3.3.3.3', 443)
        request.requestHeaders.addRawHeader('Content-Type', 'application/vnd.api+json')
        request.requestHeaders.addRawHeader('Accept', 'application/vnd.api+json')
        request.requestHeaders.addRawHeader('X-Forwarded-For', '3.3.3.3')

        resource = server.CaptchaFetchResource(self.hmacKey, self.publicKey,
                                               self.secretKey, self.captchaDir,
                                               useForwardedHeader=False)
        image, challenge = resource.getCaptchaImage(request)

        request = self.create_valid_POST_with_challenge(challenge)
        request.client = requesthelper.IPv4Address('TCP', '3.3.3.3', 443)
        request.requestHeaders.addRawHeader('X-Forwarded-For', '3.3.3.3')

        return request

    def test_withoutBlockIn(self):
        data = {
            'data': [{
                'id': 2,
                'type': 'moat-solution',
                'version': server.MOAT_API_VERSION,
                'transport': 'obfs4',
                'challenge': self.expiredChallenge,
                'solution': self.solution,
                'qrcode': False,
                'unblocked': ['us', 'ir', 'sy'],
            }]
        }
        encoded_data = json.dumps(data)
        request = self.create_POST_with_data(encoded_data)

        self.resource.render(request)

    def test_extractClientSolution(self):
        request = self.create_valid_POST_make_new_challenge()
        encoded_content = request.content.read()
        content = json.loads(encoded_content)['data'][0]
        qrcode, transport, challenge, solution = self.resource.extractClientSolution(content)

        self.assertFalse(qrcode)
        self.assertIsNotNone(transport)
        self.assertIsNotNone(challenge)
        self.assertIsNotNone(solution)

    def test_extractClientSolution_missing_id(self):
        data = {
            'data': [{
                'type': 'moat-solution',
                'version': server.MOAT_API_VERSION,
                'transport': 'obfs4',
                'challenge': self.expiredChallenge,
                'solution': self.solution,
                'qrcode': False,
            }]
        }
        qrcode, transport, challenge, solution = self.resource.extractClientSolution(data['data'][0])

        self.assertFalse(qrcode)
        self.assertIsNone(transport)
        self.assertIsNone(challenge)
        self.assertIsNone(solution)

    def test_extractClientSolution_wrong_id(self):
        data = {
            'data': [{
                'id': 69,  # nice
                'type': 'moat-solution',
                'version': server.MOAT_API_VERSION,
                'transport': 'obfs4',
                'challenge': self.expiredChallenge,
                'solution': self.solution,
                'qrcode': False,
            }]
        }
        qrcode, transport, challenge, solution = self.resource.extractClientSolution(data['data'][0])

        self.assertFalse(qrcode)
        self.assertIsNone(transport)
        self.assertIsNone(challenge)
        self.assertIsNone(solution)

    def test_extractClientSolution_weird_transport(self):
        data = {
            'data': [{
                'id': 2,
                'type': 'moat-solution',
                'version': server.MOAT_API_VERSION,
                'transport': 'dinosaur',
                'challenge': self.expiredChallenge,
                'solution': self.solution,
                'qrcode': False,
            }]
        }
        qrcode, transport, challenge, solution = self.resource.extractClientSolution(data['data'][0])

        self.assertFalse(qrcode)
        self.assertIsNone(transport)
        self.assertIsNone(challenge)
        self.assertIsNone(solution)

    def test_extractClientSolution_wrong_version(self):
        data = {
            'data': [{
                'id': 2,
                'type': 'moat-solution',
                'version': '0.0.1',  # this version never existed
                'transport': 'obfs4',
                'challenge': self.expiredChallenge,
                'solution': self.solution,
                'qrcode': False,
            }]
        }
        qrcode, transport, challenge, solution = self.resource.extractClientSolution(data['data'][0])

        self.assertFalse(qrcode)
        self.assertIsNone(transport)
        self.assertIsNone(challenge)
        self.assertIsNone(solution)

    def test_extractClientSolution_wrong_type(self):
        data = {
            'data': [{
                'id': 2,
                'type': 'boat-revolution',
                'version': server.MOAT_API_VERSION,
                'transport': 'obfs4',
                'challenge': self.expiredChallenge,
                'solution': self.solution,
                'qrcode': False,
            }]
        }
        qrcode, transport, challenge, solution = self.resource.extractClientSolution(data['data'][0])

        self.assertFalse(qrcode)
        self.assertIsNone(transport)
        self.assertIsNone(challenge)
        self.assertIsNone(solution)

    def test_failureResponse_5(self):
        request = self.create_valid_POST_with_challenge(self.expiredChallenge)
        response = self.resource.failureResponse(5, request)
        decoded = json.loads(response)

        self.assertTrue(decoded)
        self.assertIsNotNone(decoded.get('errors'))

        errors = decoded['errors']
        self.assertEqual(len(errors), 1)

        error = errors[0]
        self.assertEqual(error['status'], "No You're A Teapot")
        self.assertEqual(error['code'], 419)
        self.assertEqual(error['detail'], "The CAPTCHA challenge timed out.")
        self.assertEqual(error['id'], 5)

    def test_checkSolution(self):
        request = self.create_valid_POST_make_new_challenge()
        request.client = requesthelper.IPv4Address('TCP', '3.3.3.3', 443)
        clientIP = self.resource.getClientIP(request)
        encoded_content = request.content.read()
        content = json.loads(encoded_content)['data'][0]
        qrcode, transport, challenge, solution = self.resource.extractClientSolution(content)
        result = self.resource.checkSolution(challenge, solution, clientIP)

        self.assertTrue(result)

    def test_render_POST_expired(self):
        request = self.create_valid_POST_with_challenge(self.expiredChallenge)
        request.client = requesthelper.IPv4Address('TCP', '3.3.3.3', 443)
        response = self.resource.render(request)
        decoded = json.loads(response)

        self.assertTrue(decoded)
        self.assertIsNotNone(decoded.get('errors'))

        errors = decoded['errors']
        self.assertEqual(len(errors), 1)

        error = errors[0]
        self.assertEqual(error['status'], "No You're A Teapot")
        self.assertEqual(error['code'], 419)
        self.assertEqual(error['detail'], "The CAPTCHA solution was incorrect.")
        self.assertEqual(error['version'], server.MOAT_API_VERSION)
        self.assertEqual(error['type'], "moat-bridges")
        self.assertEqual(error['id'], 4)

    def test_getBridgeLines(self):
        request = self.create_valid_POST_with_challenge(self.expiredChallenge)
        request.client = requesthelper.IPv4Address('TCP', '3.3.3.3', 443)
        encoded_content = request.content.read()
        content = json.loads(encoded_content)['data'][0]

        bridgelines = self.resource.getBridgeLines('3.3.3.3', content)

        self.assertTrue(bridgelines)

    def test_getBridgeLines_no_data(self):
        request = self.create_valid_POST_with_challenge(self.expiredChallenge)
        request.client = requesthelper.IPv4Address('TCP', '3.3.3.3', 443)

        bridgelines = self.resource.getBridgeLines('3.3.3.3', None)

        self.assertIsNone(bridgelines)

    def test_render_POST_unexpired(self):
        request = self.create_valid_POST_make_new_challenge()
        response = self.resource.render(request)
        decoded = json.loads(response)

        self.assertTrue(decoded)
        self.assertIsNotNone(decoded.get('data'))

        datas = decoded['data']
        self.assertEqual(len(datas), 1)

        data = datas[0]
        self.assertIsNone(data['qrcode'])
        self.assertIsNotNone(data['bridges'])
        self.assertEqual(data['version'], server.MOAT_API_VERSION)
        self.assertEqual(data['type'], 'moat-bridges')
        self.assertEqual(data['id'], 3)

    def test_render_POST_unexpired_with_qrcode(self):
        request = DummyRequest([self.pagename])
        request.client = requesthelper.IPv4Address('TCP', '3.3.3.3', 443)
        request.requestHeaders.addRawHeader('Content-Type', 'application/vnd.api+json')
        request.requestHeaders.addRawHeader('Accept', 'application/vnd.api+json')
        request.requestHeaders.addRawHeader('X-Forwarded-For', '3.3.3.3')

        resource = server.CaptchaFetchResource(self.hmacKey, self.publicKey,
                                               self.secretKey, self.captchaDir,
                                               useForwardedHeader=False)
        image, challenge = resource.getCaptchaImage(request)

        data = {
            'data': [{
                'id': 2,
                'type': 'moat-solution',
                'version': server.MOAT_API_VERSION,
                'transport': 'obfs4',
                'challenge': challenge,
                'solution': self.solution,
                'qrcode': 'true',
            }]
        }
        encoded_data = json.dumps(data)
        request = self.create_POST_with_data(encoded_data)
        request.client = requesthelper.IPv4Address('TCP', '3.3.3.3', 443)
        request.requestHeaders.addRawHeader('X-Forwarded-For', '3.3.3.3')

        response = self.resource.render(request)
        decoded = json.loads(response)

        self.assertTrue(decoded)
        self.assertIsNotNone(decoded.get('data'))

        datas = decoded['data']
        self.assertEqual(len(datas), 1)

        data = datas[0]
        self.assertIsNotNone(data['qrcode'])
        self.assertIsNotNone(data['bridges'])
        self.assertEqual(data['version'], server.MOAT_API_VERSION)
        self.assertEqual(data['type'], 'moat-bridges')
        self.assertEqual(data['id'], 3)


class AddMoatServerTests(unittest.TestCase):
    """Tests for :func:`bridgedb.distributors.moat.server.addMoatServer()`."""

    def setUp(self):
        self.config = _createConfig()
        self.distributor = DummyMoatDistributor()

    def test_addMoatServer(self):
        server.addMoatServer(self.config, self.distributor)

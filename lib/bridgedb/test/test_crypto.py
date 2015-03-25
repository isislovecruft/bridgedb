# -*- coding: utf-8 -*-
#
# This file is part of BridgeDB, a Tor bridge distribution system.
#
# :authors: Isis Lovecruft 0xA3ADB67A2CDB8B35 <isis@torproject.org>
#           please also see AUTHORS file
# :copyright: (c) 2013-2015, Isis Lovecruft
#             (c) 2007-2015, The Tor Project, Inc.
#             (c) 2007-2015, all entities within the AUTHORS file
# :license: 3-Clause BSD, see LICENSE for licensing information

"""Unittests for :mod:`bridgedb.crypto`."""

from __future__ import print_function
from __future__ import unicode_literals

import base64
import io
import logging
import math
import os
import shutil

import OpenSSL

from twisted import version as _twistedversion
from twisted.internet import defer
from twisted.python.versions import Version
from twisted.trial import unittest
from twisted.test.proto_helpers import StringTransport
from twisted.web.test import test_agent as txtagent

from bridgedb import crypto
from bridgedb import txrecaptcha
from bridgedb.persistent import Conf
from bridgedb.test.util import fileCheckDecorator
from bridgedb.test.email_helpers import _createConfig


logging.disable(50)

SEKRIT_KEY  = b'v\x16Xm\xfc\x1b}\x063\x85\xaa\xa5\xf9\xad\x18\xb2P\x93\xc6k\xf9'
SEKRIT_KEY += b'\x8bI\xd9\xb8xw\xf5\xec\x1b\x7f\xa8'


class DummyEndpoint(object):
    """An endpoint that uses a fake transport."""

    def connect(self, factory):
        """Returns a connection to a
        :api:`twisted.test.proto_helpers.StringTransport`.
        """
        protocol = factory.buildProtocol(None)
        protocol.makeConnection(StringTransport())
        return defer.succeed(protocol)


class GetKeyTests(unittest.TestCase):
    """Tests for :func:`bridgedb.crypto.getKey`."""

    def test_getKey_nokey(self):
        """Test retrieving the secret_key from an empty file."""
        filename = os.path.join(os.getcwd(), 'sekrit')
        key = crypto.getKey(filename)
        self.failUnlessIsInstance(key, basestring,
                                  "key isn't a string! type=%r" % type(key))

    def test_getKey_tmpfile(self):
        """Test retrieving the secret_key from a new tmpfile."""
        filename = self.mktemp()
        key = crypto.getKey(filename)
        self.failUnlessIsInstance(key, basestring,
                                  "key isn't a string! type=%r" % type(key))

    def test_getKey_keyexists(self):
        """Write the example key to a file and test reading it back."""
        filename = self.mktemp()
        with open(filename, 'wb') as fh:
            fh.write(SEKRIT_KEY)
            fh.flush()

        key = crypto.getKey(filename)
        self.failUnlessIsInstance(key, basestring,
                                  "key isn't a string! type=%r" % type(key))
        self.assertEqual(SEKRIT_KEY, key,
                         """The example key and the one read from file differ!
                         key (in hex): %s
                         SEKRIT_KEY (in hex): %s"""
                         % (key.encode('hex'), SEKRIT_KEY.encode('hex')))


class InitializeGnuPGTests(unittest.TestCase):
    """Unittests for :func:`bridgedb.crypto.initializeGnupG`."""

    def _moveGnuPGHomedir(self):
        """Move the .gnupg/ directory from the top-level of this repo to the
        current working directory.

        :rtype: str
        :returns: The full path to the new gnupg home directory.
        """
        here         = os.getcwd()
        topDir       = here.rstrip('_trial_temp')
        gnupghome    = os.path.join(topDir, '.gnupg')
        gnupghomeNew = os.path.join(here, '.gnupg')

        if os.path.isdir(gnupghomeNew):
            shutil.rmtree(gnupghomeNew)

        shutil.copytree(gnupghome, gnupghomeNew)

        return gnupghomeNew

    def _writePassphraseToFile(self, passphrase, filename):
        """Write **passphrase** to the file at **filename**.

        :param str passphrase: The GnuPG passphase.
        :param str filename: The file to write the passphrase to.
        """
        fh = open(filename, 'w')
        fh.write(passphrase)
        fh.flush()
        fh.close()

    def setUp(self):
        """Create a config object and setup our gnupg home directory."""
        self.config = _createConfig()
        self.gnupghome = self._moveGnuPGHomedir()
        self.config.EMAIL_GPG_HOMEDIR = self.gnupghome

        self.passphraseFile = 'gpg-passphrase-file'
        self._writePassphraseToFile('sekrit', self.passphraseFile)

    def test_crypto_initializeGnuPG(self):
        """crypto.initializeGnuPG() should return a 2-tuple with a gpg object
        and a signing function.
        """
        gpg, signfunc = crypto.initializeGnuPG(self.config)
        self.assertIsNotNone(gpg)
        self.assertIsNotNone(signfunc)

    def test_crypto_initializeGnuPG_disabled(self):
        """When EMAIL_GPG_SIGNING_ENABLED=False, crypto.initializeGnuPG()
        should return a 2-tuple of None.
        """
        self.config.EMAIL_GPG_SIGNING_ENABLED = False
        gpg, signfunc = crypto.initializeGnuPG(self.config)

        self.assertIsNone(gpg)
        self.assertIsNone(signfunc)

    def test_crypto_initializeGnuPG_no_secrets(self):
        """When the secring.gpg is missing, crypto.initializeGnuPG() should
        return a 2-tuple of None.
        """
        secring = os.path.join(self.gnupghome, 'secring.gpg')
        if os.path.isfile(secring):
            os.remove(secring)

        gpg, signfunc = crypto.initializeGnuPG(self.config)
        self.assertIsNone(gpg)
        self.assertIsNone(signfunc)

    def test_crypto_initializeGnuPG_no_publics(self):
        """When the pubring.gpg is missing, crypto.initializeGnuPG() should
        return a 2-tuple of None.
        """
        pubring = os.path.join(self.gnupghome, 'pubring.gpg')
        if os.path.isfile(pubring):
            os.remove(pubring)

        gpg, signfunc = crypto.initializeGnuPG(self.config)
        self.assertIsNone(gpg)
        self.assertIsNone(signfunc)

    def test_crypto_initializeGnuPG_with_passphrase(self):
        """crypto.initializeGnuPG() should initialize correctly when a
        passphrase is given but no passphrase is needed.
        """
        self.config.EMAIL_GPG_PASSPHRASE = 'password'
        gpg, signfunc = crypto.initializeGnuPG(self.config)
        self.assertIsNotNone(gpg)
        self.assertIsNotNone(signfunc)

    def test_crypto_initializeGnuPG_with_passphrase_file(self):
        """crypto.initializeGnuPG() should initialize correctly when a
        passphrase file is given but no passphrase is needed.
        """
        self.config.EMAIL_GPG_PASSPHRASE_FILE = self.passphraseFile
        gpg, signfunc = crypto.initializeGnuPG(self.config)
        self.assertIsNotNone(gpg)
        self.assertIsNotNone(signfunc)

    def test_crypto_initializeGnuPG_missing_passphrase_file(self):
        """crypto.initializeGnuPG() should initialize correctly if a passphrase
        file is given but that file is missing (when no passphrase is actually
        necessary).
        """
        self.config.EMAIL_GPG_PASSPHRASE_FILE = self.passphraseFile
        os.remove(self.passphraseFile)
        gpg, signfunc = crypto.initializeGnuPG(self.config)
        self.assertIsNotNone(gpg)
        self.assertIsNotNone(signfunc)

    def test_crypto_initializeGnuPG_signingFunc(self):
        """crypto.initializeGnuPG() should return a signing function which
        produces OpenPGP signatures.
        """
        gpg, signfunc = crypto.initializeGnuPG(self.config)
        self.assertIsNotNone(gpg)
        self.assertIsNotNone(signfunc)

        sig = signfunc("This is a test of the public broadcasting system.")
        print(sig)
        self.assertIsNotNone(sig)
        self.assertTrue(sig.startswith('-----BEGIN PGP SIGNED MESSAGE-----'))

    def test_crypto_initializeGnuPG_nonexistent_default_key(self):
        """When the key specified by EMAIL_GPG_PRIMARY_KEY_FINGERPRINT doesn't
        exist in the keyrings, crypto.initializeGnuPG() should return a 2-tuple
        of None.
        """
        self.config.EMAIL_GPG_PRIMARY_KEY_FINGERPRINT = 'A' * 40
        gpg, signfunc = crypto.initializeGnuPG(self.config)
        self.assertIsNone(gpg)
        self.assertIsNone(signfunc)


class RemovePKCS1PaddingTests(unittest.TestCase):
    """Unittests for :func:`bridgedb.crypto.removePKCS1Padding`."""

    def setUp(self):
        """This blob *is* actually a correctly formed PKCS#1 padded signature
        on the descriptor::

        @purpose bridge
        router ExhalesPeppier 118.16.116.176 35665 0 0
        or-address [eef2:d52a:cf1b:552f:375d:f8d0:a72b:e794]:35664
        platform Tor 0.2.4.5-alpha on Linux
        protocols Link 1 2 Circuit 1
        published 2014-11-03 21:21:43
        fingerprint FA04 5CFF AB95 BA20 C994 FE28 9B23 583E F80F 34DA
        uptime 10327748
        bandwidth 2247108152 2540209215 1954007088
        extra-info-digest 571BF23D8F24F052483C1333EBAE9B91E4A6F422
        onion-key
        -----BEGIN RSA PUBLIC KEY-----
        MIGJAoGBAK7+a033aUqc97SWFVGFwR3ybQ0jG1HTPtsv2/fUfZPwCaf21ly4zIvH
        9uNhtkcPH2p55X+n5M7OUaQawOzbwL4tSR9SLy9bGuZdWLbhu2GHQWmDkAB7BtHp
        UC+uGTN3jvQXEG2xlzpb+lOVUVNXLhL5kFmAXxL+iwN4TeEv/iCnAgMBAAE=
        -----END RSA PUBLIC KEY-----
        signing-key
        -----BEGIN RSA PUBLIC KEY-----
        MIGJAoGBANxmgJ6S3rBAGcvQu2tWBaHByJxeJkdGbxID2b8cITPaNmcl72e3Kd44
        GGIkoKhkX0SAO+i2U+Q41u/DPEBWLxhpl9GAFJZ10dcT18lL36yaK6FRDOcF9jx9
        0A023/kwXd7QQDWqP7Fso+141bzit6ENvNmE1mvEeIoAR+EpJB1tAgMBAAE=
        -----END RSA PUBLIC KEY-----
        contact Somebody <somebody@example.com>
        ntor-onion-key 0Mfi/Af7zLmdNdrmJyPbZxPJe7TZU/hV4Z865g3g+k4
        reject *:*
        router-signature
        -----BEGIN SIGNATURE-----
        PsGGIP+V9ZXWIHjK943CMAPem3kFbO9kt9rvrPhd64u0f7ytB/qZGaOg1IEWki1I
        f6ZNjrthxicm3vnEUdhpRsyn7MUFiQmqLjBfqdzh0GyfrtU5HHr7CBV3tuhgVhik
        uY1kPNo1C8wkmuy31H3V7NXj+etZuzZN66qL3BiQwa8=
        -----END SIGNATURE-----

        However, for the blob to be valid it would need to be converted from
        base64-decoded bytes to a long, then raised by the power of the public
        exponent within the ASN.1 DER decoded signing-key (mod that key's
        public modulus), then re-converted back into bytes before attempting
        to remove the PKCS#1 padding. (See
        :meth:`bridedb.bridges.Bridge._verifyExtraInfoSignature`.)
        """
        blob = ('PsGGIP+V9ZXWIHjK943CMAPem3kFbO9kt9rvrPhd64u0f7ytB/qZGaOg1IEWk'
                'i1If6ZNjrthxicm3vnEUdhpRsyn7MUFiQmqLjBfqdzh0GyfrtU5HHr7CBV3tu'
                'hgVhikuY1kPNo1C8wkmuy31H3V7NXj+etZuzZN66qL3BiQwa8=')
        self.blob = base64.b64decode(blob)

    def test_crypto_removePKCS1Padding_bad_padding(self):
        """removePKCS1Padding() with a blob with a bad PKCS#1 identifier mark
        should raise PKCS1PaddingError.
        """
        self.assertRaises(crypto.PKCS1PaddingError,
                          crypto.removePKCS1Padding,
                          self.blob)

    def test_crypto_removePKCS1Padding_missing_padding(self):
        """removePKCS1Padding() with a blob with a missing PKCS#1 identifier
        mark should raise PKCS1PaddingError.
        """
        self.assertRaises(crypto.PKCS1PaddingError,
                          crypto.removePKCS1Padding,
                          b'\x99' + self.blob)


class SSLVerifyingContextFactoryTests(unittest.TestCase,
                                      txtagent.FakeReactorAndConnectMixin):
    """Tests for :class:`bridgedb.crypto.SSLVerifyingContextFactory`."""

    _certificateText = (
        "-----BEGIN CERTIFICATE-----\n"
        "MIIEdjCCA16gAwIBAgIITcyHZlE/AhQwDQYJKoZIhvcNAQEFBQAwSTELMAkGA1UE\n"
        "BhMCVVMxEzARBgNVBAoTCkdvb2dsZSBJbmMxJTAjBgNVBAMTHEdvb2dsZSBJbnRl\n"
        "cm5ldCBBdXRob3JpdHkgRzIwHhcNMTQwMjEyMTUxMTE2WhcNMTQwNjEyMDAwMDAw\n"
        "WjBoMQswCQYDVQQGEwJVUzETMBEGA1UECAwKQ2FsaWZvcm5pYTEWMBQGA1UEBwwN\n"
        "TW91bnRhaW4gVmlldzETMBEGA1UECgwKR29vZ2xlIEluYzEXMBUGA1UEAwwOd3d3\n"
        "Lmdvb2dsZS5jb20wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCt3TOf\n"
        "VOf4vfy4IROcEyiFzAJA+B3xkMccwA4anaD6VyGSFglRn5Oht3t+G0Mnu/LMuGba\n"
        "EE6NEBEUEbH8KMlAcVRj58LoFIzulaRCdkVX7JK9R+kU05sggvIl1Q2quaWSjiMQ\n"
        "SpyvKz1I2cmU5Gm4MfW/66M5ZJO323VrV19ydrgAtdbNnvVj85asrSyzwEBNxzNC\n"
        "N6OQtOmTt4I7KLXqkROtTmTFvhAGBsvhG0hJZWhoP1aVsFO+KcE2OaIIxWQ4ckW7\n"
        "BJEgYaXfgHo01LdR55aevGUqLfsdyT+GMZrG9k7eqAw4cq3ML2Y6RiyzskqoQL30\n"
        "3OdYjKTIcU+i3BoFAgMBAAGjggFBMIIBPTAdBgNVHSUEFjAUBggrBgEFBQcDAQYI\n"
        "KwYBBQUHAwIwGQYDVR0RBBIwEIIOd3d3Lmdvb2dsZS5jb20waAYIKwYBBQUHAQEE\n"
        "XDBaMCsGCCsGAQUFBzAChh9odHRwOi8vcGtpLmdvb2dsZS5jb20vR0lBRzIuY3J0\n"
        "MCsGCCsGAQUFBzABhh9odHRwOi8vY2xpZW50czEuZ29vZ2xlLmNvbS9vY3NwMB0G\n"
        "A1UdDgQWBBQN7uQBzGDjvKRna111g9iPPtaXVTAMBgNVHRMBAf8EAjAAMB8GA1Ud\n"
        "IwQYMBaAFErdBhYbvPZotXb1gba7Yhq6WoEvMBcGA1UdIAQQMA4wDAYKKwYBBAHW\n"
        "eQIFATAwBgNVHR8EKTAnMCWgI6Ahhh9odHRwOi8vcGtpLmdvb2dsZS5jb20vR0lB\n"
        "RzIuY3JsMA0GCSqGSIb3DQEBBQUAA4IBAQBrVp/xys2ABQvWPxpVrYaXiaoBXdxu\n"
        "RVVXp5Lyu8IipKqFJli81hOX9eqPG7biYeph9HiKnW31xsXebaVlWWL3NXOh5X83\n"
        "wpzozL0AkxskTMHQknrbIGLtmG67H71aKYyCthHEjawLmYjjvkcF6f9fKdYENM4C\n"
        "skz/yjtlPBQFAuT6J9w0b3qtc42sHNlpgIOdIRQc2YCD0p6jAo+wKjoRuRu3ILKj\n"
        "oCVrOPbDMPN4a2gSmK8Ur0aHuEpcNghg6HJsVSANokIIwQ/r4niqL5yotsangP/5\n"
        "rR97EIYKFz7C6LMy/PIe8xFTIyKMtM59IcpUDIwCLlM9JtNdwN4VpyKy\n"
        "-----END CERTIFICATE-----\n")

    def setUp(self):
        """Create a fake reactor for these tests."""
        self.reactor = self.Reactor()
        self.url = 'https://www.example.com/someresource.html#andatag'

    def test_getHostnameFromURL(self):
        """``getHostnameFromURL()`` should return a hostname from a URI."""
        if _twistedversion >= Version('twisted', 14, 0, 0):
            raise unittest.SkipTest(
                ("The SSLVerifyingContextFactory is no longer necessary in "
                 "Twisted>=14.0.0, because the way in which TLS certificates "
                 "are checked now includes certificate pinning, and the "
                 "SSLVerifyingContextFactory only implemented strict hostname "
                 "checking."))

        agent = txrecaptcha._getAgent(self.reactor, self.url)
        contextFactory = agent._contextFactory
        self.assertRegexpMatches(contextFactory.hostname,
                                 '.*www\.example\.com')

    def test_verifyHostname_mismatching(self):
        """Check that ``verifyHostname()`` returns ``False`` when the
        ``SSLVerifyingContextFactory.hostname`` does not match the one found
        in the level 0 certificate subject CN.
        """
        if _twistedversion >= Version('twisted', 14, 0, 0):
            raise unittest.SkipTest(
                ("The SSLVerifyingContextFactory is no longer necessary in "
                 "Twisted>=14.0.0, because the way in which TLS certificates "
                 "are checked now includes certificate pinning, and the "
                 "SSLVerifyingContextFactory only implemented strict hostname "
                 "checking."))

        agent = txrecaptcha._getAgent(self.reactor, self.url)
        contextFactory = agent._contextFactory
        x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM,
                                               self._certificateText)
        conn = DummyEndpoint()
        result = contextFactory.verifyHostname(conn, x509, 0, 0, True)
        self.assertIs(result, False)

    def test_verifyHostname_matching(self):
        """Check that ``verifyHostname()`` returns ``True`` when the
        ``SSLVerifyingContextFactory.hostname`` matches the one found in the
        level 0 certificate subject CN.
        """
        hostname = 'www.google.com'
        url = 'https://' + hostname + '/recaptcha'
        contextFactory = crypto.SSLVerifyingContextFactory(url)
        self.assertEqual(contextFactory.hostname, hostname)

        x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM,
                                               self._certificateText)
        conn = DummyEndpoint()
        result = contextFactory.verifyHostname(conn, x509, 0, 0, True)
        self.assertTrue(result)

    def test_getContext(self):
        """The context factory's ``getContext()`` method should produce an
        ``OpenSSL.SSL.Context`` object.
        """
        contextFactory = crypto.SSLVerifyingContextFactory(self.url)
        self.assertIsInstance(contextFactory.getContext(),
                              OpenSSL.SSL.Context)

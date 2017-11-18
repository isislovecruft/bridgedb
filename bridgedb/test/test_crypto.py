# -*- coding: utf-8 -*-
#
# This file is part of BridgeDB, a Tor bridge distribution system.
#
# :authors: Isis Lovecruft 0xA3ADB67A2CDB8B35 <isis@torproject.org>
#           please also see AUTHORS file
# :copyright: (c) 2013-2017, Isis Lovecruft
#             (c) 2007-2017, The Tor Project, Inc.
#             (c) 2007-2017, all entities within the AUTHORS file
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

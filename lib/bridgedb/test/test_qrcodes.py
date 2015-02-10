# -*- coding: utf-8 -*-
#_____________________________________________________________________________
#
# This file is part of BridgeDB, a Tor bridge distribution system.
#
# :authors: Isis Lovecruft 0xA3ADB67A2CDB8B35 <isis@torproject.org>
#           please also see AUTHORS file
# :copyright: (c) 2007-2015, The Tor Project, Inc.
#             (c) 2014-2015, Isis Lovecruft
# :license: see LICENSE for licensing information
#_____________________________________________________________________________

"""Tests for :mod:`bridgedb.qrcodes`."""


from twisted.trial import unittest

from bridgedb import qrcodes


class GenerateQRTests(unittest.TestCase):
    """Unittests for :func:`bridgedb.qrcodes.generateQR`."""

    def setUp(self):
        self.qrcodeModule = qrcodes.qrcode
        bridgelines = [
            "obfs4 63.125.48.205:26573 441a151632806a3cc42adfecc2e6e823299db7b2 iat-mode=1 public-key=8d27ba37c5d810106b55f3fd6cdb35842007e88754184bfc0e6035f9bcede633 node-id=42d2a6ad49f93ab4b987b1a9e738425aacb8d2af",
            "obfs4 103.111.131.45:43288 cb1362f8eaf5d3c2b6fad5da300f66c4197f23e5 iat-mode=0 public-key=c75cb66ae28d8ebc6eded002c28a8ba0d06d3a78c6b5cbf9b2ade051f0775ac4 node-id=4cd66dfabbd964f8c6c4414b07cdb45dae692e19",
            "obfs4 17.194.28.21:5530 86ef8ab343e76bcd3c57ee32febe4482c98141c7 iat-mode=0 public-key=36ebe205bcdfc499a25e6923f4450fa8d48196ceb4fa0ce077d9d8ec4a36926d node-id=6b6277afcb65d33525545904e95c2fa240632660",
        ]
        self.bridgelines = '\n'.join(bridgelines)

    def tearDown(self):
        """Replace the qrcode module to its original form."""
        qrcodes.qrcode = self.qrcodeModule

    def test_generateQR(self):
        """Calling generateQR() should generate an image."""
        self.assertTrue(qrcodes.generateQR(self.bridgelines))

    def test_generateQR_bad_bridgelines(self):
        """Calling generateQR() with a bad type for the bridgelines should
        return None.
        """
        self.assertIsNone(qrcodes.generateQR(list()))

    def test_generateQR_no_bridgelines(self):
        """Calling generateQR() without bridgelines should return None."""
        self.assertIsNone(qrcodes.generateQR(""))

    def test_generateQR_no_qrcode_module(self):
        """Calling generateQR() without the qrcode module installed should
        return None.
        """
        qrcodes.qrcode = None
        self.assertIsNone(qrcodes.generateQR(self.bridgelines))

    def test_generateQR_bridgeSchema(self):
        """Calling generateQR() with bridgeSchema=True should prepend
        ``'bridge://`` to each of the QR encoded bridge lines.
        """
        # If we were to install the python-qrtools Debian package, we'd be
        # able to decode the resulting QRCode to check that it contains the
        # 'bridge://' prefix for each bridge line… but that would add another
        # Debian dependency just to unittest 5 lines of code.
        #
        # Instead:
        self.assertTrue(qrcodes.generateQR(self.bridgelines, bridgeSchema=True))

    def test_generateQR_save_nonexistent_format(self):
        """Calling generateQR() with imageFormat=u'FOOBAR' should return None.
        """
        self.assertIsNone(qrcodes.generateQR(self.bridgelines, imageFormat=u'FOOBAR'))

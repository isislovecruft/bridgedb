
"""Unittests for :class:`bridgedb.parse.descriptors` module."""

from __future__ import print_function

import io
import textwrap

from twisted.trial import unittest

HAS_STEM = False

try:
    from stem.descriptor.server_descriptor import RelayDescriptor
except (ImportError, NameError), error:
    print("There was an error importing stem: %s" % error)
else:
    HAS_STEM = True


BRIDGE_SERVER_DESCRIPTOR = '''\
router OutwitsPlod 152.78.9.20 17810 0 0
or-address [bfbd:7a90:2347:cc4:e854:64b3:2c31:124f]:17810
platform Tor 0.2.4.16-rc on Linux
protocols Link 1 2 Circuit 1
published 2014-03-12 16:07:08
fingerprint 6FA9 216C F3A0 6E89 A031 21AC C31F 70F8 DFD7 DDCC
uptime 57032961
bandwidth 2240117028 2532306205 1947927850
extra-info-digest 069EBB610CD8B02BF1BB0CAB17B99DDA73CCC91A
onion-key
-----BEGIN RSA PUBLIC KEY-----
MIGkAgEAMA0GCSqGSIb3DQEBAQUABIGPMIGMAgEAAoGBANI67YIwW8xF2v310PZt
Qc8jm0ptwLHmgBdhAzHAIGagqknjvukX5GTL0zie5covhxrQhZqjJm/gQ8inwkol
kZCue1ZQ9PHaTWjz58ESMQo41h+9Whfd8Egm2ev1+MwqlPy1Kr3rcPNIEetsmtil
DFNocpEfq1MC0tDG6qVO6/FNAgMBAAE=
-----END RSA PUBLIC KEY-----
signing-key
-----BEGIN RSA PUBLIC KEY-----
MIGkAgEAMA0GCSqGSIb3DQEBAQUABIGPMIGMAgEAAoGBALk0Ws5qPlgwKO6IQ1b/
aamtEdXEPj2DrZTF3aGYR5zoZgw9gwmkbRHjrMQ/Wj+QHg0cTFY2DsYt81QXwiv+
m1P9sshMZSZZz2P8Ld8WqUNuN7YIIJx/fj9Vy6LRFySzoyQ4FF/1Dio+JD0rvtyc
ZyRJl2aV5iYA9/TQY2zs2cxFAgMBAAE=
-----END RSA PUBLIC KEY-----
hidden-service-dir
contact Somebody <somebody@example.com>
reject *:*
router-signature
-----BEGIN SIGNATURE-----
i/nkrD4VxqWcnAlBS48hIilrE7C4DvRJhN4XWep7TXNbEC48IqFG+49xpKV6qkts
yKaUDBfD9Y1tMM0mrRjEWK0xYWX/4Ug9Xbbv2q1so4EuS35AF11d69Yf/2ppnCu7
r+qtX7csROF4KyFJYFNJUKf/hroPHKWuTGCcqzb+D68=
-----END SIGNATURE-----'''


class ParseDescriptorsTests(unittest.TestCase):
    """Unittests for :class:`bridgedb.parse.descriptors` module."""

    def test_parse_descriptors_parseBridgeDescriptorsFile(self):
        """Test for ``b.p.descriptors.parseBridgeDescriptorsFile``."""
        if not HAS_STEM:
            self.skip = True
            raise unittest.SkipTest("Couldn't import Stem.")

        from bridgedb.parse import descriptors

        descFile = io.BytesIO(BRIDGE_SERVER_DESCRIPTOR)
        routers = descriptors.parseServerDescriptorsFile(descFile)
        self.assertIsInstance(routers, list)
        bridge = routers[0]
        self.assertIsInstance(bridge, RelayDescriptor)
        self.assertEqual(bridge.address, u'152.78.9.20')
        self.assertEqual(bridge.fingerprint,
                         u'6FA9216CF3A06E89A03121ACC31F70F8DFD7DDCC')

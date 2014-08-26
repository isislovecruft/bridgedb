# -*- coding: utf-8 -*-
#
# This file is part of BridgeDB, a Tor bridge distribution system.
#
# :authors: Isis Lovecruft 0xA3ADB67A2CDB8B35 <isis@torproject.org>
# :copyright: (c) 2013-2014, Isis Lovecruft
#             (c) 2007-2014, The Tor Project, Inc.
# :license: 3-Clause BSD, see LICENSE for licensing information

"""Unittests for :class:`bridgedb.parse.descriptors` module."""

from __future__ import print_function

import io
import os
import textwrap

from twisted.trial import unittest

HAS_STEM = False

try:
    from stem.descriptor.server_descriptor import RelayDescriptor
    from stem.descriptor.extrainfo_descriptor import BridgeExtraInfoDescriptor
    from stem.descriptor.router_status_entry import RouterStatusEntryV2
    from bridgedb.parse import descriptors
except (ImportError, NameError), error:
    print("There was an error importing stem: %s" % error)
else:
    HAS_STEM = True


BRIDGE_NETWORKSTATUS_0 = '''\
r OutwitsPlod b6khbPOgbomgMSGswx9w+N/X3cw qBckYSWbwl/F/qzQWwMJWBxHZ+w 2014-03-12 16:07:08 152.78.9.20 17810 0
a [bfbd:7a90:2347:cc4:e854:64b3:2c31:124f]:17810
s Fast Guard Running Stable Valid
w Bandwidth=1902273
p reject 1-65535
'''

BRIDGE_NETWORKSTATUS_1 = '''\
r Reestablishes jPqMRoqkH62eLMXl76DqIddlpto 2BETKn1sOghC6coUkCSq/9mvPNM 2014-08-20 19:52:41 25.178.4.186 32324 0
a [d7b3:8c3e:186a:d65f:706:cbfd:8512:fd1]:32324
s Fast Guard Running Stable Valid
w Bandwidth=497963
p reject 1-65535
'''

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
-----END SIGNATURE-----
'''

BRIDGE_EXTRA_INFO_DESCRIPTOR = '''\
extra-info OutwitsPlod 6FA9216CF3A06E89A03121ACC31F70F8DFD7DDCC
published 2014-03-12 16:07:08
write-history 2014-03-12 16:07:08 (900 s) 3188736,2226176,2866176
read-history 2014-03-12 16:07:08 (900 s) 3891200,2483200,2698240
dirreq-write-history 2014-03-12 16:07:08 (900 s) 1024,0,2048
dirreq-read-history 2014-03-12 16:07:08 (900 s) 0,0,0
geoip-db-digest AAF7B842E52974556F9969A62DF8D31F9D886A33
geoip6-db-digest C2C80F4EF2908E55A764603B08A8CB99A681EA19
dirreq-stats-end 2014-03-12 16:07:08 (86400 s)
dirreq-v3-ips
dirreq-v3-reqs
dirreq-v3-resp ok=16,not-enough-sigs=0,unavailable=0,not-found=0,not-modified=0,busy=0
dirreq-v3-direct-dl complete=0,timeout=0,running=0
dirreq-v3-tunneled-dl complete=12,timeout=0,running=0
transport obfs3 152.78.9.20:17811
transport obfs2 152.78.9.20:17812
bridge-stats-end 2014-03-12 16:07:08 (86400 s)
bridge-ips ca=8
bridge-ip-versions v4=8,v6=0
bridge-ip-transports <OR>=8
router-signature
-----BEGIN SIGNATURE-----
aW1ZlxqeaGcbNSxVpMONU0ER4xgdihb9X2crguzKa/TYVweCZ2Ew7x3Rsg4cUNpr
Fb05F3Zxg6ZUTMC8gfh6leDGw5eSX7OGVaaJICTfeLbNopLVk+JKNGMJ32R/Zia0
feWndKJk/zj5ZtkMND8VVbWuJE+R6Jh2Q3L0p8IZ6J4=
-----END SIGNATURE-----
'''

BRIDGE_EXTRA_INFO_DESCRIPTOR_NEWER_DUPLICATE = '''\
extra-info OutwitsPlod 6FA9216CF3A06E89A03121ACC31F70F8DFD7DDCC
published 2014-03-12 17:07:08
write-history 2014-03-12 17:07:08 (900 s) 3188736,2226176,2866176
read-history 2014-03-12 17:07:08 (900 s) 3891200,2483200,2698240
dirreq-write-history 2014-03-12 17:07:08 (900 s) 1024,0,2048
dirreq-read-history 2014-03-12 17:07:08 (900 s) 0,0,0
geoip-db-digest AAF7B842E52974556F9969A62DF8D31F9D886A33
geoip6-db-digest C2C80F4EF2908E55A764603B08A8CB99A681EA19
dirreq-stats-end 2014-03-12 17:07:08 (86400 s)
dirreq-v3-ips
dirreq-v3-reqs
dirreq-v3-resp ok=16,not-enough-sigs=0,unavailable=0,not-found=0,not-modified=0,busy=0
dirreq-v3-direct-dl complete=0,timeout=0,running=0
dirreq-v3-tunneled-dl complete=12,timeout=0,running=0
transport obfs3 152.78.9.20:17811
transport obfs2 152.78.9.20:17812
bridge-stats-end 2014-03-12 17:07:08 (86400 s)
bridge-ips ca=8
bridge-ip-versions v4=8,v6=0
bridge-ip-transports <OR>=8
router-signature
-----BEGIN SIGNATURE-----
aW1ZlxqeaGcbNSxVpMONU0ER4xgdihb9X2crguzKa/TYVweCZ2Ew7x3Rsg4cUNpr
Fb05F3Zxg6ZUTMC8gfh6leDGw5eSX7OGVaaJICTfeLbNopLVk+JKNGMJ32R/Zia0
feWndKJk/zj5ZtkMND8VVbWuJE+R6Jh2Q3L0p8IZ6J4=
-----END SIGNATURE-----
'''


class ParseDescriptorsTests(unittest.TestCase):
    """Unittests for :class:`bridgedb.parse.descriptors` module."""

    skip = True if not HAS_STEM else False

    def setUp(self):
        """Test if we have Stem installed. Skip these tests if it's missing."""
        if self.skip:
            raise unittest.SkipTest("Couldn't import Stem.")

    def writeTestDescriptorsToFile(self, filename, *descriptors):
        """Write **descriptors** to **filename**.

        :param str filename: A filename. It will be appended to the current
            working directory automatically.
        :param str descriptors: Some optional strings containing
            descriptors. Each one will be written to **filename** as-is.
        :rtype: str
        :returns: The full path to the file which was written to.
        """
        descFilename = os.path.join(os.getcwd(), filename)
        with open(descFilename, 'w') as fh:
            for desc in descriptors:
                fh.write(desc)
                fh.flush()
        return descFilename

    def test_parse_descriptors_parseBridgeDescriptorsFile(self):
        """Test for ``b.p.descriptors.parseBridgeDescriptorsFile``."""
        descFile = io.BytesIO(BRIDGE_SERVER_DESCRIPTOR)
        routers = descriptors.parseServerDescriptorsFile(descFile)
        self.assertIsInstance(routers, list)
        bridge = routers[0]
        self.assertIsInstance(bridge, RelayDescriptor)
        self.assertEqual(bridge.address, u'152.78.9.20')
        self.assertEqual(bridge.fingerprint,
                         u'6FA9216CF3A06E89A03121ACC31F70F8DFD7DDCC')

    def test_parse_descriptors_parseBridgeNetworkStatusFile_return_type(self):
        """``b.p.descriptors.parseNetworkStatusFile`` should return a dict."""
        # Write the descriptor to a file for testing. This is necessary
        # because the function opens the networkstatus file to read it.
        descFile = self.writeTestDescriptorsToFile('networkstatus-bridges',
                                                   BRIDGE_NETWORKSTATUS_0)
        routers = descriptors.parseNetworkStatusFile(descFile)
        self.assertIsInstance(routers, dict)

    def test_parse_descriptors_parseBridgeNetworkStatusFile_one_file(self):
        """Test ``b.p.descriptors.parseNetworkStatusFile`` with one bridge
        networkstatus descriptor.
        """
        # Write the descriptor to a file for testing. This is necessary
        # because the function opens the networkstatus file to read it.
        descFile = self.writeTestDescriptorsToFile('networkstatus-bridges',
                                                   BRIDGE_NETWORKSTATUS_0)
        routers = descriptors.parseNetworkStatusFile(descFile)
        bridge = routers.items()[0]
        self.assertIsInstance(bridge, RouterStatusEntryV2)
        self.assertEqual(bridge.address, u'152.78.9.20')
        self.assertEqual(bridge.fingerprint,
                         u'6FA9216CF3A06E89A03121ACC31F70F8DFD7DDCC')

    def test_parse_descriptors_parseBridgeNetworkStatusFile_two_files(self):
        """Test ``b.p.descriptors.parseNetworkStatusFile`` with two bridge
        networkstatus descriptors.
        """
        # Write the descriptor to a file for testing. This is necessary
        # because the function opens the networkstatus file to read it.
        descFile = self.writeTestDescriptorsToFile('networkstatus-bridges',
                                                   BRIDGE_NETWORKSTATUS_0,
                                                   BRIDGE_NETWORKSTATUS_1)
        routers = descriptors.parseNetworkStatusFile(descFile)
        bridge = routers.items()[0]
        self.assertIsInstance(bridge, RouterStatusEntryV2)
        self.assertEqual(bridge.address, u'152.78.9.20')
        self.assertEqual(bridge.fingerprint,
                         u'6FA9216CF3A06E89A03121ACC31F70F8DFD7DDCC')

    def test_parse_descriptors_parseBridgeExtraInfoFiles_one_file(self):
        """Test for ``b.p.descriptors.parseBridgeExtraInfoFiles`` with only one
        bridge extrainfo file."""
        descFile = io.BytesIO(BRIDGE_EXTRA_INFO_DESCRIPTOR)
        routers = descriptors.parseBridgeExtraInfoFiles(descFile)
        self.assertIsInstance(routers, list)
        bridge = routers[0]
        self.assertIsInstance(bridge, BridgeExtraInfoDescriptor)
        self.assertEqual(bridge.address, u'152.78.9.20')
        self.assertEqual(bridge.fingerprint,
                         u'6FA9216CF3A06E89A03121ACC31F70F8DFD7DDCC')

    def test_parse_descriptors_parseBridgeExtraInfoFiles_two_files(self):
        """Test for ``b.p.descriptors.parseBridgeExtraInfoFiles`` with two
        bridge extrainfo files, and check that only the newest extrainfo
        descriptor is used."""
        descFileOne = io.BytesIO(BRIDGE_EXTRA_INFO_DESCRIPTOR)
        descFileTwo = io.BytesIO(BRIDGE_EXTRA_INFO_DESCRIPTOR_NEWER_DUPLICATE)
        routers = descriptors.parseBridgeExtraInfoFiles(descFileOne, descFileTwo)
        self.assertIsInstance(routers, list)
        bridge = routers[0]
        self.assertIsInstance(bridge, BridgeExtraInfoDescriptor)
        self.assertEqual(bridge.address, u'152.78.9.20')
        self.assertEqual(bridge.fingerprint,
                         u'6FA9216CF3A06E89A03121ACC31F70F8DFD7DDCC')

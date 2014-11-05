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
    from stem.descriptor.router_status_entry import RouterStatusEntryV3
    from bridgedb.parse import descriptors
except (ImportError, NameError), error:
    print("There was an error importing stem: %s" % error)
else:
    HAS_STEM = True


BRIDGE_NETWORKSTATUS_0 = '''\
r MiserLandfalls 4IsyTSCtChPhFPAnq5rD8yymlqA /GMC4lz8RXT/62v6kZNdmzSmopk 2014-11-04 06:23:22 2.215.61.223 4056 0
a [c5fd:4467:98a7:90be:c76a:b449:8e6f:f0a7]:4055
s Fast Guard Running Stable Valid
w Bandwidth=1678904
p reject 1-65535
'''

BRIDGE_NETWORKSTATUS_1 = '''\
r Unmentionable BgOrX0ViP5hNsK5ZvixAuPZ6EY0 NTg9NoE5ls9KjF96Dp/UdrabZ9Y 2014-11-04 12:23:37 80.44.173.87 51691 0
a [da14:7d1e:ba8e:60d0:b078:3f88:382b:5c70]:51690
s Fast Guard Running Stable Valid
w Bandwidth=24361
p reject 1-65535
'''

BRIDGE_SERVER_DESCRIPTOR = '''\
@purpose bridge
router MiserLandfalls 2.215.61.223 4056 0 0
or-address [c5fd:4467:98a7:90be:c76a:b449:8e6f:f0a7]:4055
platform Tor 0.2.2.39 on Linux
opt protocols Link 1 2 Circuit 1
published 2014-11-04 06:23:22
opt fingerprint E08B 324D 20AD 0A13 E114 F027 AB9A C3F3 2CA6 96A0
uptime 24247659
bandwidth 1977077890 2234957615 1719198165
opt extra-info-digest 1CBBB3D6158F324476E6804B7EE25623899271CB
onion-key
-----BEGIN RSA PUBLIC KEY-----
MIGJAoGBAOm4NX2wi8JmgcAyvOyiAEfq9UkzaNHK+VnSZBiPIrb5GAKFibR7S+Bb
7+x7tsT8VBNbe9QmwML2GVah3xXg68gJAksMNIgFdpud+zMhduuGd0jr7V55aLmH
ePGJYCh78B9RqfvmeTridp3pljwcAheKKH/YKi3nv1fPY0BwahurAgMBAAE=
-----END RSA PUBLIC KEY-----
signing-key
-----BEGIN RSA PUBLIC KEY-----
MIGJAoGBANd/JkrTZRT24EkK3DDc/E+Nj1QBnKIm/xXMyW0gkotFOVdewIWjwQ5z
Tn3YbDhrFN0aFYVdVwNbRhW83e+jZDkpIQuxlQOx6bT13vrzmg8ff1tH8I9EePl7
MO4v0DLPIEcu7Zfz90oC1bl36oqNsD4h0v4yK/XjVwLutIGiy3gTAgMBAAE=
-----END RSA PUBLIC KEY-----
contact Somebody <somebody@example.com>
ntor-onion-key NBsk2O6ks5qnxLhhhKPd59zi0IzfjnakoOJP+Cm8OAE
reject *:*
router-signature
-----BEGIN SIGNATURE-----
YYA5wJTHcjqXk/QBaDXHX/4Fb8W2OctF4X4VHyxH9Hsou4Ip7nzdfWzbBTcBiIrt
ybaaMO15L9Ctkli/capN+nCw2jWgivgiPnAmJNmLGeN6skTKjLPAau+839hBuQxu
P2aB/+XQfzFBA5TaWF83coDng4OGodhwHaOx10Kn7Bg=
-----END SIGNATURE-----
'''

BRIDGE_EXTRA_INFO_DESCRIPTOR = '''\
extra-info MiserLandfalls E08B324D20AD0A13E114F027AB9AC3F32CA696A0
published 2014-11-04 06:23:22
write-history 2014-11-04 06:23:22 (900 s) 3188736,2226176,2866176
read-history 2014-11-04 06:23:22 (900 s) 3891200,2483200,2698240
dirreq-write-history 2014-11-04 06:23:22 (900 s) 1024,0,2048
dirreq-read-history 2014-11-04 06:23:22 (900 s) 0,0,0
geoip-db-digest 09A0E093100B279AD9CFF47A67B13A21C6E1483F
geoip6-db-digest E983833985E4BCA34CEF611B2DF51942D188E638
dirreq-stats-end 2014-11-04 06:23:22 (86400 s)
dirreq-v3-ips
dirreq-v3-reqs
dirreq-v3-resp ok=16,not-enough-sigs=0,unavailable=0,not-found=0,not-modified=0,busy=0
dirreq-v3-direct-dl complete=0,timeout=0,running=0
dirreq-v3-tunneled-dl complete=12,timeout=0,running=0
transport obfs3 2.215.61.223:4057
transport obfs2 2.215.61.223:4058
transport scramblesuit 2.215.61.223:4059 password=ABCDEFGHIJKLMNOPQRSTUVWXYZ234567
transport obfs4 2.215.61.223:4060 iat-mode=0,node-id=19a448c01aa2e7d55979473b647e282459995b85,public-key=7a61b53701befdae0eeeffaecc73f14e20b537bb0f8b91ad7c2936dc63562b25
bridge-stats-end 2014-11-04 06:23:22 (86400 s)
bridge-ips ca=8
bridge-ip-versions v4=8,v6=0
bridge-ip-transports <OR>=8
router-signature
-----BEGIN SIGNATURE-----
KOXNPCoe+Q+thFA/Lz7RTja2tWp4oC6SvyIooEZibHtEDgiXuU4sELWT4bSOk3np
RVmu7QPMmNybx4LHowq3pOeNLtJzpWg8Pfo+N6tR+K4nqPwBRmpsuDhCD/tIXJlP
U36EY4UoN5ABPowhNZFeyr5A3vKiDr6j0hCOqYOhxPY=
-----END SIGNATURE-----
'''

BRIDGE_EXTRA_INFO_DESCRIPTOR_NEWER_DUPLICATE = '''\
extra-info MiserLandfalls E08B324D20AD0A13E114F027AB9AC3F32CA696A0
published 2014-11-04 08:10:25
write-history 2014-11-04 08:10:25 (900 s) 3188736,2226176,2866176,2226176
read-history 2014-11-04 08:10:25 (900 s) 3891200,2483200,2698240,2483200
dirreq-write-history 2014-11-04 08:10:25 (900 s) 1024,0,2048,3072
dirreq-read-history 2014-11-04 08:10:25 (900 s) 0,0,0,0
geoip-db-digest 09A0E093100B279AD9CFF47A67B13A21C6E1483F
geoip6-db-digest E983833985E4BCA34CEF611B2DF51942D188E638
dirreq-stats-end 2014-11-04 08:10:25 (86400 s)
dirreq-v3-ips
dirreq-v3-reqs
dirreq-v3-resp ok=16,not-enough-sigs=0,unavailable=0,not-found=0,not-modified=0,busy=0
dirreq-v3-direct-dl complete=0,timeout=0,running=0
dirreq-v3-tunneled-dl complete=12,timeout=0,running=0
transport obfs3 2.215.61.223:4057
transport obfs2 2.215.61.223:4058
transport scramblesuit 2.215.61.223:4059 password=ABCDEFGHIJKLMNOPQRSTUVWXYZ234567
transport obfs4 2.215.61.223:4060 iat-mode=0,node-id=19a448c01aa2e7d55979473b647e282459995b85,public-key=7a61b53701befdae0eeeffaecc73f14e20b537bb0f8b91ad7c2936dc63562b25
bridge-stats-end 2014-11-04 08:10:25 (86400 s)
bridge-ips ca=8
bridge-ip-versions v4=8,v6=0
bridge-ip-transports <OR>=8
router-signature
-----BEGIN SIGNATURE-----
KOXNPCoe+Q+thFA/Lz7RTja2tWp4oC6SvyIooEZibHtEDgiXuU4sELWT4bSOk3np
RVmu7QPMmNybx4LHowq3pOeNLtJzpWg8Pfo+N6tR+K4nqPwBRmpsuDhCD/tIXJlP
U36EY4UoN5ABPowhNZFeyr5A3vKiDr6j0hCOqYOhxPY=
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
        self.assertIsInstance(routers, list)

    def test_parse_descriptors_parseBridgeNetworkStatusFile_has_RouterStatusEntryV2(self):
        """The items in the dict returned from
        ``b.p.descriptors.parseNetworkStatusFile`` should be
        ``RouterStatusEntryV2``s.
        """
        # Write the descriptor to a file for testing. This is necessary
        # because the function opens the networkstatus file to read it.
        descFile = self.writeTestDescriptorsToFile('networkstatus-bridges',
                                                   BRIDGE_NETWORKSTATUS_0)
        routers = descriptors.parseNetworkStatusFile(descFile)
        bridge = routers[0]
        self.assertIsInstance(bridge, RouterStatusEntryV3)

    def test_parse_descriptors_parseBridgeNetworkStatusFile_1(self):
        """Test ``b.p.descriptors.parseNetworkStatusFile`` with one bridge
        networkstatus descriptor.
        """
        # Write the descriptor to a file for testing. This is necessary
        # because the function opens the networkstatus file to read it.
        descFile = self.writeTestDescriptorsToFile('networkstatus-bridges',
                                                   BRIDGE_NETWORKSTATUS_0)
        routers = descriptors.parseNetworkStatusFile(descFile)
        bridge = routers[0]
        self.assertEqual(bridge.address, u'152.78.9.20')
        self.assertEqual(bridge.fingerprint,
                         u'6FA9216CF3A06E89A03121ACC31F70F8DFD7DDCC')

    def test_parse_descriptors_parseBridgeNetworkStatusFile_2(self):
        """Test ``b.p.descriptors.parseNetworkStatusFile`` with two bridge
        networkstatus descriptors.
        """
        # Write the descriptor to a file for testing. This is necessary
        # because the function opens the networkstatus file to read it.
        descFile = self.writeTestDescriptorsToFile('networkstatus-bridges',
                                                   BRIDGE_NETWORKSTATUS_0,
                                                   BRIDGE_NETWORKSTATUS_1)
        routers = descriptors.parseNetworkStatusFile(descFile)
        bridge = routers[0]
        self.assertEqual(bridge.address, u'152.78.9.20')
        self.assertEqual(bridge.fingerprint,
                         u'6FA9216CF3A06E89A03121ACC31F70F8DFD7DDCC')

    def test_parse_descriptors_parseBridgeExtraInfoFiles_return_type(self):
        """The return type of ``b.p.descriptors.parseBridgeExtraInfoFiles``
        should be a dictionary (after deduplication).
        """
        descFile = io.BytesIO(BRIDGE_EXTRA_INFO_DESCRIPTOR)
        routers = descriptors.parseBridgeExtraInfoFiles(descFile)
        self.assertIsInstance(routers, dict)

    def test_parse_descriptors_parseBridgeExtraInfoFiles_has_BridgeExtraInfoDescriptor(self):
        """The return of ``b.p.descriptors.parseBridgeExtraInfoFiles`` should
        contain ``BridgeExtraInfoDescriptor``s.
        """
        descFile = io.BytesIO(BRIDGE_EXTRA_INFO_DESCRIPTOR)
        routers = descriptors.parseBridgeExtraInfoFiles(descFile)
        bridge = routers.values()[0]
        self.assertIsInstance(bridge, BridgeExtraInfoDescriptor)

    def test_parse_descriptors_parseBridgeExtraInfoFiles_one_file(self):
        """Test for ``b.p.descriptors.parseBridgeExtraInfoFiles`` with only one
        bridge extrainfo file.
        """
        descFile = io.BytesIO(BRIDGE_EXTRA_INFO_DESCRIPTOR)
        routers = descriptors.parseBridgeExtraInfoFiles(descFile)
        bridge = routers.values()[0]

        # The number of transports we parsed should be equal to the number of
        # 'transport' lines in the descriptor:
        self.assertEqual(len(bridge.transport),
                         BRIDGE_EXTRA_INFO_DESCRIPTOR.count('transport '))

        self.assertEqual(bridge.fingerprint,
                         u'6FA9216CF3A06E89A03121ACC31F70F8DFD7DDCC')

    def test_parse_descriptors_parseBridgeExtraInfoFiles_two_files(self):
        """Test for ``b.p.descriptors.parseBridgeExtraInfoFiles`` with two
        bridge extrainfo files, and check that only the newest extrainfo
        descriptor is used.
        """
        descFileOne = io.BytesIO(BRIDGE_EXTRA_INFO_DESCRIPTOR)
        descFileTwo = io.BytesIO(BRIDGE_EXTRA_INFO_DESCRIPTOR_NEWER_DUPLICATE)
        routers = descriptors.parseBridgeExtraInfoFiles(descFileOne, descFileTwo)
        # We shouldn't have duplicates:
        self.assertEqual(len(routers), 1)

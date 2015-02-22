# -*- coding: utf-8 -*-
#
# This file is part of BridgeDB, a Tor bridge distribution system.
#
# :authors: Isis Lovecruft 0xA3ADB67A2CDB8B35 <isis@torproject.org>
#           please also see AUTHORS file
# :copyright: (c) 2013-2015 Isis Lovecruft
#             (c) 2007-2015, The Tor Project, Inc.
#             (c) 2007-2015, all entities within the AUTHORS file
# :license: see included LICENSE for information

"""Tests for :mod:`bridgedb.Main`."""

from __future__ import print_function

import base64
import logging
import os
import random
import shutil
import sys

from datetime import datetime
from time import sleep

from twisted.internet.threads import deferToThread
from twisted.trial import unittest

from bridgedb import Main
from bridgedb.Bridges import BridgeHolder
from bridgedb.parse.options import parseOptions


logging.getLogger().disabled = True


HERE = os.getcwd()
TOPDIR = HERE.rstrip('_trial_temp')
CI_RUNDIR = os.path.join(TOPDIR, 'run')

# A networkstatus descriptor with two invalid ORAddress (127.0.0.1 and ::1)
# and an invalid port number (70000).
NETWORKSTATUS_MALFORMED = '''\
r OracleLunacy LBXW03FIKvo9aXCEYbDdq1BbNtM E0yN8ofiBpg6JHW0iPX5gJ1gKFI 2014-09-05 21:39:24 127.0.0.1 70000 0
a [::1]:70000
s Fast Guard Running Stable Valid
w Bandwidth=2094050
p reject 1-65535
'''

def mockAddOrUpdateBridgeHistory(bridge, timestamp):
    """A mocked version of :func:`bridgedb.Stability.addOrUpdateBridgeHistory`
    which doesn't access the database (so that we can test functions which
    call it, like :func:`bridgedb.Main.updateBridgeHistory`).
    """
    print("Pretending to update Bridge %s with timestamp %s..." %
          (bridge.fingerprint, timestamp))


class MockBridgeHolder(BridgeHolder):
    def __init__(self):
        self._bridges = {}
    def __len__(self):
        return len(self._bridges.keys())
    def insert(self, bridge):
        self._bridges[bridge.fingerprint] = bridge


class MainTests(unittest.TestCase):
    """Integration tests for :func:`bridgedb.Main.load`."""

    def _appendToFile(self, file, data):
        """Append **data** to **file**."""
        fh = open(file, 'a')
        fh.write(data)
        fh.flush()
        fh.close()

    def _copyDescFilesHere(self, files):
        """Copy all the **files** to the _trial_tmp/ directory.

        :param list files: A list of strings representing the paths to
            descriptor files. This should probably be taken from a
            ``bridgedb.persistent.Conf`` object which has parsed the
            ``bridgedb.conf`` file in the top-level directory of this repo.
        :rtype: list
        :returns: A list of the new paths (in the ``_trial_tmp`` directory) to
            the copied descriptor files. This should be used to update the
            ``bridgedb.persistent.Conf`` object.
        """
        updatedPaths = []

        for f in files:
            base = os.path.basename(f)
            src = os.path.join(CI_RUNDIR, base)
            if os.path.isfile(src):
                dst = os.path.join(HERE, base)
                shutil.copy(src, dst)
                updatedPaths.append(dst)
            else:
                self.skip = True
                raise unittest.SkipTest(
                    "Can't find mock descriptor files in %s directory" %
                    CI_RUNDIR)

        return updatedPaths

    def _cbAssertFingerprints(self, d):
        """Assert that there are some bridges in the splitter."""
        self.assertGreater(len(self.splitter), 0)
        return d

    def _cbCallUpdateBridgeHistory(self, d, splitter):
        """Fake some timestamps for the bridges in the splitter, and then call
        Main.updateBridgeHistory().
        """
        def timestamp():
            return datetime.fromtimestamp(random.randint(1324285117, 1524285117))

        bridges = splitter._bridges
        timestamps = {}

        for fingerprint, _ in bridges.items():
            timestamps[fingerprint] = [timestamp(), timestamp(), timestamp()]

        return Main.updateBridgeHistory(bridges, timestamps)

    def _eb_Failure(self, failure):
        """If something produces a twisted.python.failure.Failure, fail the
        test with it.
        """
        self.fail(failure)

    def _writeConfig(self, config):
        """Write a config into the current working directory.

        :param str config: A big long multiline string that looks like the
            bridgedb.conf file.
        :rtype: str
        :returns: The pathname of the file that the **config** was written to.
        """
        configFile = os.path.join(os.getcwd(), 'bridgedb.conf')
        fh = open(configFile, 'w')
        fh.write(config)
        fh.flush()
        fh.close()
        return configFile

    def setUp(self):
        """Find the bridgedb.conf file in the top-level directory of this repo,
        copy it and the descriptor files it references to the current working
        directory, produce a state object from the loaded bridgedb.conf file,
        and make an HMAC key.
        """
        # Get the bridgedb.conf file in the top-level directory of this repo:
        self.configFile = os.path.join(TOPDIR, 'bridgedb.conf')
        self.config = Main.loadConfig(self.configFile)

        # Copy the referenced descriptor files from bridgedb/run/ to CWD:
        self.config.STATUS_FILE = self._copyDescFilesHere([self.config.STATUS_FILE])[0]
        self.config.BRIDGE_FILES = self._copyDescFilesHere(self.config.BRIDGE_FILES)
        self.config.EXTRA_INFO_FILES = self._copyDescFilesHere(self.config.EXTRA_INFO_FILES)

        # Initialise the state
        self.state = Main.persistent.State(**self.config.__dict__)
        self.key = base64.b64decode('TvPS1y36BFguBmSOvhChgtXB2Lt+BOw0mGfz9SZe12Y=')

        # Create a BridgeSplitter
        self.splitter = MockBridgeHolder()

        # Functions which some tests mock, which we'll need to re-replace
        # later in tearDown():
        self._orig_addOrUpdateBridgeHistory = Main.addOrUpdateBridgeHistory
        self._orig_sys_argv = sys.argv

    def tearDown(self):
        """Replace the mocked mockAddOrUpdateBridgeHistory() function with the
        real function, Stability.addOrUpdateBridgeHistory().
        """
        Main.addOrUpdateBridgeHistory = self._orig_addOrUpdateBridgeHistory
        sys.argv = self._orig_sys_argv

    def test_Main_updateBridgeHistory(self):
        """Main.updateBridgeHistory should update some timestamps for some
        bridges.
        """
        # Mock the addOrUpdateBridgeHistory() function so that we don't try to
        # access the database:
        Main.addOrUpdateBridgeHistory = mockAddOrUpdateBridgeHistory

        # Get the bridges into the mocked splitter
        d = deferToThread(Main.load, self.state, self.splitter)
        d.addCallback(self._cbAssertFingerprints)
        d.addErrback(self._eb_Failure)
        d.addCallback(self._cbCallUpdateBridgeHistory, self.splitter)
        d.addErrback(self._eb_Failure)
        return d

    def test_Main_load(self):
        """Main.load() should run without error."""
        d = deferToThread(Main.load, self.state, self.splitter)
        d.addCallback(self._cbAssertFingerprints)
        d.addErrback(self._eb_Failure)
        return d

    def test_Main_load_no_state(self):
        """Main.load() should raise SystemExit without a state object."""
        self.assertRaises(SystemExit, Main.load, None, self.splitter)

    def test_Main_load_clear(self):
        """When called with clear=True, load() should run and clear the
        hashrings.
        """
        d = deferToThread(Main.load, self.state, self.splitter, clear=True)
        d.addCallback(self._cbAssertFingerprints)
        d.addErrback(self._eb_Failure)
        return d

    def test_Main_load_collect_timestamps(self):
        """When COLLECT_TIMESTAMPS=True, Main.load() should call
        Main.updateBridgeHistory().
        """
        # Mock the addOrUpdateBridgeHistory() function so that we don't try to
        # access the database:
        Main.addOrUpdateBridgeHistory = mockAddOrUpdateBridgeHistory
        state = self.state
        state.COLLECT_TIMESTAMPS = True

        # The reactor is deferring this to a thread, so the test execution
        # here isn't actually covering the Main.updateBridgeHistory()
        # function:
        Main.load(state, self.splitter)

    def test_Main_load_malformed_networkstatus(self):
        """When called with a networkstatus file with an invalid descriptor,
        Main.load() should raise a ValueError.
        """
        self._appendToFile(self.state.STATUS_FILE, NETWORKSTATUS_MALFORMED)
        self.assertRaises(ValueError, Main.load, self.state, self.splitter)

    def test_Main_reloadFn(self):
        """Main._reloadFn() should return True."""
        self.assertTrue(Main._reloadFn())

    def test_Main_handleSIGHUP(self):
        """Main._handleSIGHUP() should return True."""
        raise unittest.SkipTest("_handleSIGHUP touches the reactor.")

        self.assertTrue(Main._handleSIGHUP())

    def test_Main_createBridgeRings(self):
        """Main.createBridgeRings() should add three hashrings to the
        splitter.
        """
        proxyList = None
        (splitter, emailDist, httpsDist) = Main.createBridgeRings(self.config,
                                                                  proxyList,
                                                                  self.key)
        # Should have an IPBasedDistributor ring, an EmailDistributor ring,
        # and an UnallocatedHolder ring:
        self.assertEqual(len(splitter.ringsByName.keys()), 3)

    def test_Main_createBridgeRings_with_proxyList(self):
        """Main.createBridgeRings() should add three hashrings to the
        splitter and add the proxyList to the IPBasedDistibutor.
        """
        exitRelays = ['1.1.1.1', '2.2.2.2', '3.3.3.3']
        proxyList = Main.proxy.ProxySet()
        proxyList.addExitRelays(exitRelays)
        (splitter, emailDist, httpsDist) = Main.createBridgeRings(self.config,
                                                                  proxyList,
                                                                  self.key)
        # Should have an IPBasedDistributor ring, an EmailDistributor ring,
        # and an UnallocatedHolder ring:
        self.assertEqual(len(splitter.ringsByName.keys()), 3)
        self.assertGreater(len(httpsDist.categories), 0)
        self.assertItemsEqual(exitRelays, httpsDist.categories[-1])

    def test_Main_createBridgeRings_no_https_dist(self):
        """When HTTPS_DIST=False, Main.createBridgeRings() should add only
        two hashrings to the splitter.
        """
        proxyList = Main.proxy.ProxySet()
        config = self.config
        config.HTTPS_DIST = False
        (splitter, emailDist, httpsDist) = Main.createBridgeRings(config,
                                                                  proxyList,
                                                                  self.key)
        # Should have an EmailDistributor ring, and an UnallocatedHolder ring:
        self.assertEqual(len(splitter.ringsByName.keys()), 2)
        self.assertNotIn('https', splitter.rings)
        self.assertNotIn(httpsDist, splitter.ringsByName.values())

    def test_Main_createBridgeRings_no_email_dist(self):
        """When EMAIL_DIST=False, Main.createBridgeRings() should add only
        two hashrings to the splitter.
        """
        proxyList = Main.proxy.ProxySet()
        config = self.config
        config.EMAIL_DIST = False
        (splitter, emailDist, httpsDist) = Main.createBridgeRings(config,
                                                               proxyList,
                                                               self.key)
        # Should have an IPBasedDistributor ring, and an UnallocatedHolder ring:
        self.assertEqual(len(splitter.ringsByName.keys()), 2)
        self.assertNotIn('email', splitter.rings)
        self.assertNotIn(emailDist, splitter.ringsByName.values())

    def test_Main_createBridgeRings_no_reserved_share(self):
        """When RESERVED_SHARE=0, Main.createBridgeRings() should add only
        two hashrings to the splitter.
        """
        proxyList = Main.proxy.ProxySet()
        config = self.config
        config.RESERVED_SHARE = 0
        (splitter, emailDist, httpsDist) = Main.createBridgeRings(config,
                                                                  proxyList,
                                                                  self.key)
        # Should have an IPBasedDistributor ring, and an EmailDistributor ring:
        self.assertEqual(len(splitter.ringsByName.keys()), 2)
        self.assertNotIn('unallocated', splitter.rings)

    def test_Main_createBridgeRings_two_file_buckets(self):
        """When FILE_BUCKETS has two filenames in it, Main.createBridgeRings()
        should add three hashrings to the splitter, then add two
        "pseudo-rings".
        """
        proxyList = Main.proxy.ProxySet()
        config = self.config
        config.FILE_BUCKETS = {
            'bridges-for-support-desk': 10,
            'bridges-for-ooni-tests': 10,
        }
        (splitter, emailDist, httpsDist) = Main.createBridgeRings(config,
                                                                  proxyList,
                                                                  self.key)
        # Should have an IPBasedDistributor ring, an EmailDistributor, and an
        # UnallocatedHolder ring:
        self.assertEqual(len(splitter.ringsByName.keys()), 3)

        # Should have two pseudoRings:
        self.assertEqual(len(splitter.pseudoRings), 2)
        self.assertIn('pseudo_bridges-for-support-desk', splitter.pseudoRings)
        self.assertIn('pseudo_bridges-for-ooni-tests', splitter.pseudoRings)

    def test_Main_run(self):
        """Main.run() should run and then finally raise SystemExit."""
        config = """
BRIDGE_FILES = ["../run/bridge-descriptors"]
EXTRA_INFO_FILES = ["../run/cached-extrainfo", "../run/cached-extrainfo.new"]
STATUS_FILE = "../run/networkstatus-bridges"
HTTPS_CERT_FILE="cert"
HTTPS_KEY_FILE="privkey.pem"
LOGFILE = "bridgedb.log"
PIDFILE = "bridgedb.pid"
DB_FILE = "bridgedist.db"
DB_LOG_FILE = "bridgedist.log"
MASTER_KEY_FILE = "secret_key"
ASSIGNMENTS_FILE = "assignments.log"
LOGLEVEL = "DEBUG"
SAFELOGGING = True
LOGFILE_COUNT = 5
LOGFILE_ROTATE_SIZE = 10000000
LOG_THREADS = False
LOG_TRACE = True
LOG_TIME_FORMAT = "%H:%M:%S"
COLLECT_TIMESTAMPS = False
NO_DISTRIBUTION_COUNTRIES = ['IR', 'SY']
PROXY_LIST_FILES = []
N_IP_CLUSTERS = 3
FORCE_PORTS = [(443, 1)]
FORCE_FLAGS = [("Stable", 1)]
BRIDGE_PURPOSE = "bridge"
TASKS = {'GET_TOR_EXIT_LIST': 3 * 60 * 60,}
SERVER_PUBLIC_FQDN = 'bridges.torproject.org'
SERVER_PUBLIC_EXTERNAL_IP = '38.229.72.19'
HTTPS_DIST = True
HTTPS_BIND_IP = None
HTTPS_PORT = None
HTTPS_N_BRIDGES_PER_ANSWER = 3
HTTPS_INCLUDE_FINGERPRINTS = True
HTTPS_USE_IP_FROM_FORWARDED_HEADER = False
HTTP_UNENCRYPTED_BIND_IP = "127.0.0.1"
HTTP_UNENCRYPTED_PORT = 55555
HTTP_USE_IP_FROM_FORWARDED_HEADER = False
RECAPTCHA_ENABLED = False
RECAPTCHA_PUB_KEY = ''
RECAPTCHA_SEC_KEY = ''
RECAPTCHA_REMOTEIP = ''
GIMP_CAPTCHA_ENABLED = False
GIMP_CAPTCHA_DIR = 'captchas'
GIMP_CAPTCHA_HMAC_KEYFILE = 'captcha_hmac_key'
GIMP_CAPTCHA_RSA_KEYFILE = 'captcha_rsa_key'
EMAIL_DIST = True
EMAIL_FROM_ADDR = "bridges@torproject.org"
EMAIL_SMTP_FROM_ADDR = "bridges@torproject.org"
EMAIL_SMTP_HOST = "127.0.0.1"
EMAIL_SMTP_PORT = 55556
EMAIL_USERNAME = "bridges"
EMAIL_DOMAINS = ["somewhere.com", "somewhereelse.net"]
EMAIL_DOMAIN_MAP = {
    "mail.somewhere.com": "somewhere.com",
    "mail.somewhereelse.net": "somewhereelse.net",
}
EMAIL_DOMAIN_RULES = {
    'somewhere.com': ["ignore_dots", "dkim"],
    'somewhereelse.net': ["dkim"],
}
EMAIL_WHITELIST = {}
EMAIL_BLACKLIST = []
EMAIL_FUZZY_MATCH = 4
EMAIL_RESTRICT_IPS = []
EMAIL_BIND_IP = "127.0.0.1"
EMAIL_PORT = 55557
EMAIL_N_BRIDGES_PER_ANSWER = 3
EMAIL_INCLUDE_FINGERPRINTS = True
EMAIL_GPG_SIGNING_ENABLED = False
EMAIL_GPG_HOMEDIR = '../.gnupg'
EMAIL_GPG_PRIMARY_KEY_FINGERPRINT = '0017098C5DF4197E3C884DCFF1B240D43F148C21'
EMAiL_GPG_PASSPHRASE = None
EMAIL_GPG_PASSPHRASE_FILE = None
HTTPS_SHARE = 10
EMAIL_SHARE = 5
RESERVED_SHARE = 2
FILE_BUCKETS = {}"""
        configFile = self._writeConfig(config)
        
        # Fake some options:
        sys.argv = ['bridgedb', '-r', os.getcwd(), '-c', configFile]
        options = parseOptions()

        self.assertRaises(SystemExit, Main.run, options, reactor=None)

# -*- coding: utf-8 -*-
#
# This file is part of BridgeDB, a Tor bridge distribution system.
#
# :authors: Isis Lovecruft 0xA3ADB67A2CDB8B35 <isis@torproject.org>
#           please also see AUTHORS file
# :copyright: (c) 2013-2015 Isis Lovecruft
#             (c) 2007-2015, The Tor Project, Inc.
#             (c) 2007-2015, all entities within the AUTHORS file
# :license: 3-clause BSD, see included LICENSE for information

"""Tests for :mod:`bridgedb.proxy`."""

import sure

from twisted.internet import defer
from twisted.internet import reactor
from twisted.trial import unittest

from bridgedb import proxy


EXIT_LIST_0 = """\
11.11.11.11
22.22.22.22
123.45.67.89"""

EXIT_LIST_1 = """\
33.33.33.33
44.44.44.44
55.55.55.55
66.66.66.66
77.77.77.77"""

EXIT_LIST_BAD = """\
foo
bar
baz"""


class MockExitListProtocol(proxy.ExitListProtocol):
    """A mocked version of :class:`~bridgedb.proxy.ExitListProtocol`."""

    def __init__(self):
        proxy.ExitListProtocol.__init__(self)
        self._data = EXIT_LIST_0
        self.script = '/bin/echo'
        print()

    def _log(self, msg):
        print("%s: %s" % (self.__class__.__name__, msg))

    def childConnectionLost(self, childFD):
        self._log("childConnectionLost() called with childFD=%s" % childFD)
        proxy.ExitListProtocol.childConnectionLost(self, childFD)

    def connectionMade(self):
        self._log("connectionMade() called")
        proxy.ExitListProtocol.connectionMade(self)

    def errReceived(self, data):
        self._log("errReceived() called with %s" % data)
        proxy.ExitListProtocol.errReceived(self, data)

    def outReceivedData(self, data):
        self._log("outReceivedData() called with %s" % data)
        proxy.ExitListProtocol.outReceivedData(self, data)

    def outConnectionLost(self):
        self._log("outConnectionLost() called")
        proxy.ExitListProtocol.outConnectionLost(self)

    def parseData(self):
        data = self._data.split('\n')
        for line in data:
            line = line.strip()
            if not line: continue
            if line.startswith('<'): break
            if line.startswith('#'): continue
            ip = proxy.isIPAddress(line)
            if ip:
                self._log("adding IP %s to exitlist..." % ip)
                self.exitlist.add(ip)

    def processEnded(self, reason):
        self._log("processEnded() called with %s" % reason)
        proxy.ExitListProtocol.processEnded(self, reason)

    def processExited(self, reason):
        self._log("processExited() called with %s" % reason)
        proxy.ExitListProtocol.processExited(self, reason)


class ProxySetImplementationTest(unittest.TestCase):

    def setUp(self):
        # We have to put something in it, otherwise self.ps.should.be.ok won't
        # think it's truthy:
        self.ps = proxy.ProxySet(['1.1.1.1'])

    def test_instantiation(self):
        self.ps.should.be.ok
        self.ps.should.have.property('__contains__').being.callable
        self.ps.should.have.property('__hash__').being.callable
        self.ps.should.have.property('__iter__').being.callable
        self.ps.should.have.property('__len__').being.callable
        self.ps.should.have.property('add').being.callable
        self.ps.should.have.property('copy').being.callable
        self.ps.should.have.property('contains').being.callable
        self.ps.should.have.property('discard').being.callable
        self.ps.should.have.property('remove').being.callable

        self.ps.should.have.property('difference').being.callable
        self.ps.should.have.property('issubset').being.callable
        self.ps.should.have.property('issuperset').being.callable
        self.ps.should.have.property('intersection').being.callable
        self.ps.should.have.property('symmetric_difference').being.callable
        self.ps.should.have.property('union').being.callable

    def test_attributes(self):
        self.ps.should.have.property('proxies').being.a(list)
        self.ps.should.have.property('exitRelays').being.a(set)
        self.ps.should.have.property('_proxies').being.a(set)
        self.ps.should.have.property('_proxydict').being.a(dict)


class LoadProxiesFromFileIntegrationTests(unittest.TestCase):
    """Unittests for :class:`~bridgedb.proxy.loadProxiesFromFile()`."""

    def setUp(self):
        self.fn0 = '%s-0' % self.__class__.__name__
        self.fn1 = '%s-1' % self.__class__.__name__
        self.badfile = '%s-badfile' % self.__class__.__name__
        self.writeFiles()

    def writeFiles(self):
        with open(self.fn0, 'w') as fh:
            fh.write(EXIT_LIST_0)
            fh.flush()
        with open(self.fn1, 'w') as fh:
            fh.write(EXIT_LIST_1)
            fh.flush()
        with open(self.badfile, 'w') as fh:
            fh.write(EXIT_LIST_BAD)
            fh.flush()

    def emptyFile(self, filename):
        """We have to do this is a separate method, otherwise Twisted doesn't
        actually do it.
        """
        fh = open(filename, 'w')
        fh.truncate()
        fh.close()

    def test_proxy_loadProxiesFromFile_1_file(self):
        """Test loading proxies from one file."""
        proxies = proxy.loadProxiesFromFile(self.fn0)
        self.assertEqual(len(proxies), 3)

    def test_proxy_loadProxiesFromFile_1_file_missing(self):
        """Test loading proxies from one file that doesn't exist."""
        proxies = proxy.loadProxiesFromFile('%s-missing' % self.__class__.__name__)
        self.assertEqual(len(proxies), 0)

    def test_proxy_loadProxiesFromFile_1_file_and_proxyset(self):
        """Test loading proxies from one file."""
        proxyList = proxy.ProxySet(['1.1.1.1'])
        proxies = proxy.loadProxiesFromFile(self.fn0, proxySet=proxyList)
        self.assertEqual(len(proxies), 3)
        self.assertEqual(len(proxyList), 4)

    def test_proxy_loadProxiesFromFile_2_files_and_proxyset(self):
        """Test loading proxies from two files."""
        proxyList = proxy.ProxySet(['1.1.1.1'])
        proxy.loadProxiesFromFile(self.fn0, proxySet=proxyList)
        proxies = proxy.loadProxiesFromFile(self.fn1, proxySet=proxyList)
        self.assertEqual(len(proxies), 5)
        self.assertEqual(len(proxyList), 9)

    def test_proxy_loadProxiesFromFile_removeStale(self):
        """Test loading proxies from two files and removing the stale ones."""
        proxyList = proxy.ProxySet(['1.1.1.1'])
        self.assertEqual(len(proxyList), 1)
        proxies = proxy.loadProxiesFromFile(self.fn0, proxySet=proxyList)
        self.assertEqual(len(proxies), 3)
        self.assertEqual(len(proxyList), 4)
        proxies = proxy.loadProxiesFromFile(self.fn1, proxySet=proxyList)
        self.assertEqual(len(proxies), 5)
        self.assertEqual(len(proxyList), 9)

        self.emptyFile(self.fn0)
        proxies = proxy.loadProxiesFromFile(self.fn0, proxySet=proxyList,
                                            removeStale=True)
        self.assertEqual(len(proxies), 0)
        self.assertEqual(len(proxyList), 6)

    def test_proxy_loadProxiesFromFile_duplicates(self):
        """Loading proxies from the same file twice shouldn't store
        duplicates.
        """
        proxyList = proxy.ProxySet(['1.1.1.1'])
        proxy.loadProxiesFromFile(self.fn1, proxySet=proxyList)
        self.assertEqual(len(proxyList), 6)
        proxy.loadProxiesFromFile(self.fn1, proxySet=proxyList)
        self.assertEqual(len(proxyList), 6)

    def test_proxy_loadProxiesFromFile_bad_file(self):
        """Loading proxies from a file with invalid IPs in it should do
        nothing.
        """
        proxyList = proxy.ProxySet()
        proxy.loadProxiesFromFile(self.badfile, proxySet=proxyList)
        self.assertEqual(len(proxyList), 0)


class DownloadTorExitsTests(unittest.TestCase):
    """Tests for `~bridgedb.proxy.downloadTorExits()`."""

    def setUp(self):
        self.protocol = MockExitListProtocol
        self.proxyList = proxy.ProxySet()

    def tearDown(self):
        """Cleanup method after each ``test_*`` method runs; removes all
        selectable readers and writers from the reactor.
        """
        reactor.removeAll()

    def test_proxy_downloadTorExits(self):
        def do_test():
            return proxy.downloadTorExits(self.proxyList,
                                          'OurIPWouldGoHere',
                                          protocol=self.protocol)
        d = do_test()


class ProxySetUnittests(unittest.TestCase):
    """Unittests for :class:`~bridgedb.proxy.ProxySet`."""

    def setUp(self):
        self.proxies = EXIT_LIST_1.split('\n')
        self.moarProxies = EXIT_LIST_0.split('\n')

        self.proxyList = proxy.ProxySet()
        for p in self.proxies:
            self.proxyList.add(p)

    def test_ProxySet_init(self):
        """When initialised (after setUp() has run), the ProxySet should
        contain a number of proxies equal to the number we added in the setUp()
        method.
        """
        self.assertEquals(len(self.proxyList), len(self.proxies))

    def test_ProxySet_proxies_getter(self):
        """ProxySet.proxies should list all proxies."""
        self.assertItemsEqual(self.proxyList.proxies, set(self.proxies))

    def test_ProxySet_proxies_setter(self):
        """``ProxySet.proxies = ['foo']`` should raise an ``AttributeError``."""
        self.assertRaises(AttributeError, self.proxyList.__setattr__, 'proxies', ['foo'])

    def test_ProxySet_proxies_deleter(self):
        """``del(ProxySet.proxies)`` should raise an AttributeError."""
        self.assertRaises(AttributeError, self.proxyList.__delattr__, 'proxies')

    def test_ProxySet_exitRelays_issubset_proxies(self):
        """ProxySet.exitRelays should always be a subset of ProxySet.proxies."""
        self.assertTrue(self.proxyList.exitRelays.issubset(self.proxyList.proxies))
        self.proxyList.addExitRelays(self.moarProxies)
        self.assertTrue(self.proxyList.exitRelays.issubset(self.proxyList.proxies))

    def test_ProxySet_exitRelays_getter(self):
        """ProxySet.exitRelays should list all exit relays."""
        self.proxyList.addExitRelays(self.moarProxies)
        self.assertItemsEqual(self.proxyList.exitRelays, set(self.moarProxies))

    def test_ProxySet_exitRelays_setter(self):
        """``ProxySet.exitRelays = ['foo']`` should raise an ``AttributeError``."""
        self.assertRaises(AttributeError, self.proxyList.__setattr__, 'exitRelays', ['foo'])

    def test_ProxySet_exitRelays_deleter(self):
        """``del(ProxySet.exitRelays)`` should raise an AttributeError."""
        self.assertRaises(AttributeError, self.proxyList.__delattr__, 'exitRelays')

    def test_ProxySet_add_new(self):
        """ProxySet.add() should add a new proxy."""
        self.proxyList.add('110.110.110.110')
        self.assertEquals(len(self.proxyList), len(self.proxies) + 1)
        self.assertIn('110.110.110.110', self.proxyList)

    def test_ProxySet_add_None(self):
        """ProxySet.add() called with None should return False."""
        self.assertFalse(self.proxyList.add(None))
        self.assertEquals(len(self.proxyList), len(self.proxies))

    def test_ProxySet_add_duplicate(self):
        """ProxySet.add() shouldn't add the same proxy twice."""
        self.proxyList.add(self.proxies[0])
        self.assertEquals(len(self.proxyList), len(self.proxies))
        self.assertIn(self.proxies[0], self.proxyList)

    def test_ProxySet_addExitRelays(self):
        """ProxySet.addExitRelays() should add the new proxies."""
        self.proxyList.addExitRelays(self.moarProxies)
        self.assertIn(self.moarProxies[0], self.proxyList)

    def test_ProxySet_radd_new(self):
        """ProxySet.radd() should add a new proxy."""
        self.proxyList.__radd__('110.110.110.110')
        self.assertEquals(len(self.proxyList), len(self.proxies) + 1)
        self.assertIn('110.110.110.110', self.proxyList)

    def test_ProxySet_addExitRelays_tagged(self):
        """ProxySet.addExitRelays() should add the new proxies, and they should
        be tagged as being Tor exit relays.
        """
        self.proxyList.addExitRelays(self.moarProxies)
        self.assertTrue(self.proxyList.isExitRelay(self.moarProxies[0]))
        self.assertEquals(self.proxyList.getTag(self.moarProxies[0]),
                          self.proxyList._exitTag)

    def test_ProxySet_addExitRelays_length(self):
        """ProxySet.addExitRelays() should add the new proxies and then the
        total number should be equal to the previous number of proxies plus the
        new exit relays added.
        """
        self.proxyList.addExitRelays(self.moarProxies)
        self.assertEquals(len(self.proxyList), len(self.proxies) + len(self.moarProxies))

    def test_ProxySet_addExitRelays_previous_proxies_kept(self):
        """ProxySet.addExitRelays() should add the new proxies and keep ones that
        were already in the ProxySet.
        """
        self.proxyList.addExitRelays(self.moarProxies)
        self.assertIn(self.proxies[0], self.proxyList)

    def test_ProxySet_addExitRelays_previous_proxies_not_tagged(self):
        """ProxySet.addExitRelays() should add the new proxies and tag them,
        but any previous non-exit relays in the ProxySet shouldn't be tagged as
        being Tor exit relays.
        """
        self.proxyList.addExitRelays(self.moarProxies)
        self.assertFalse(self.proxyList.isExitRelay(self.proxies[0]))
        self.assertNotEquals(self.proxyList.getTag(self.proxies[0]),
                             self.proxyList._exitTag)

    def test_ProxySet_addProxies_tuple_individual_tags(self):
        """ProxySet.addProxies() should add the new proxies and tag them with
        whatever tags we want.
        """
        tags = ['foo', 'bar', 'baz']
        extraProxies = zip(self.moarProxies, tags)
        self.proxyList.addProxies(extraProxies)
        self.assertEquals(len(self.proxyList), len(self.proxies) + len(extraProxies))
        self.assertIn(extraProxies[0][0], self.proxyList)
        self.assertEquals(self.proxyList._proxydict[extraProxies[0][0]], extraProxies[0][1])
        self.assertEquals(self.proxyList._proxydict[extraProxies[1][0]], extraProxies[1][1])
        self.assertEquals(self.proxyList._proxydict[extraProxies[2][0]], extraProxies[2][1])

    def test_ProxySet_addProxies_tuple_too_many_items(self):
        """``ProxySet.addProxies()`` where the tuples have >2 items should
        raise a ValueError.
        """
        extraProxies = zip(self.moarProxies,
                           ['sometag' for _ in range(len(self.moarProxies))],
                           ['othertag' for _ in range(len(self.moarProxies))])
        self.assertRaises(ValueError, self.proxyList.addProxies, extraProxies)

    def test_ProxySet_addProxies_list(self):
        """``ProxySet.addProxies(..., tag='sometag')`` should add the new
        proxies and tag them all with the same tag.
        """
        self.proxyList.addProxies(self.moarProxies, tag='sometag')
        self.assertEquals(len(self.proxyList), len(self.proxies) + len(self.moarProxies))
        self.assertIn(self.moarProxies[0], self.proxyList)
        for p in self.moarProxies:
            self.assertEquals(self.proxyList.getTag(p), 'sometag')
        for p in self.proxies:
            self.assertNotEqual(self.proxyList.getTag(p), 'sometag')

    def test_ProxySet_addProxies_set(self):
        """``ProxySet.addProxies(..., tag=None)`` should add the new
        proxies and tag them all with timestamps.
        """
        self.proxyList.addProxies(set(self.moarProxies))
        self.assertEquals(len(self.proxyList), len(self.proxies) + len(self.moarProxies))
        self.assertIn(self.moarProxies[0], self.proxyList)
        for p in self.moarProxies:
            self.assertIsInstance(self.proxyList.getTag(p), float)
        for p in self.proxies:
            self.assertNotEqual(self.proxyList.getTag(p), 'sometag')

    def test_ProxySet_addProxies_bad_type(self):
        """``ProxySet.addProxies()`` called with something which is neither an
        iterable, a basestring, or an int should raise a ValueError.
        """
        self.assertRaises(ValueError, self.proxyList.addProxies, object)

    def test_ProxySet_addProxies_list_of_bad_types(self):
        """``ProxySet.addProxies()`` called with something which is neither an
        iterable, a basestring, or an int should raise a ValueError.
        """
        self.assertRaises(ValueError, self.proxyList.addProxies, [object, object, object])

    def test_ProxySet_getTag(self):
        """ProxySet.getTag() should get the tag for a proxy in the set."""
        self.proxyList.add('1.1.1.1', 'bestproxyevar')
        self.assertEquals(self.proxyList.getTag('1.1.1.1'), 'bestproxyevar')

    def test_ProxySet_getTag_nonexistent(self):
        """ProxySet.getTag() should get None for a proxy not in the set."""
        self.assertIsNone(self.proxyList.getTag('1.1.1.1'))

    def test_ProxySet_clear(self):
        """ProxySet.clear() should clear the set of proxies."""
        self.proxyList.clear()
        self.assertEquals(len(self.proxyList), 0)
        self.assertEquals(len(self.proxyList.proxies), 0)
        self.assertEquals(len(self.proxyList._proxies), 0)
        self.assertEquals(len(self.proxyList._proxydict.items()), 0)

    def test_ProxySet_contains_list(self):
        """Calling ``list() is in ProxySet()`` should return False."""
        self.assertFalse(self.proxyList.contains(list(self.proxies[0],)))

    def test_ProxySet_contains_nonexistent(self):
        """``ProxySet().contains()`` with a proxy not in the set should
        return False.
        """
        self.assertFalse(self.proxyList.contains(self.moarProxies[0]))

    def test_ProxySet_contains_nonexistent(self):
        """``ProxySet().contains()`` with a proxy in the set should
        return True.
        """
        self.assertTrue(self.proxyList.contains(self.proxies[0]))

    def test_ProxySet_copy(self):
        """ProxySet.copy() should create an exact copy."""
        newProxyList = self.proxyList.copy()
        self.assertEquals(newProxyList, self.proxyList)

    def test_ProxySet_difference(self):
        """ProxySet.difference() should list the items in ProxySetA which
        aren't in ProxySetB.
        """
        proxySetA = self.proxyList
        proxySetB = proxy.ProxySet(self.moarProxies)
        self.assertItemsEqual(proxySetA.difference(proxySetB),
                              set(self.proxies))
        self.assertItemsEqual(proxySetB.difference(proxySetA),
                              set(self.moarProxies))

    def test_ProxySet_firstSeen_returns_timestamp(self):
        """ProxySet.firstSeen() should return a timestamp for a proxy with a
        timestamp tag.
        """
        self.proxyList.add(self.moarProxies[0])
        self.assertIsNotNone(self.proxyList.firstSeen(self.moarProxies[0]))

    def test_ProxySet_firstSeen_returns_float(self):
        """ProxySet.firstSeen() should return a timestamp for a proxy with a
        timestamp tag.
        """
        self.proxyList.add(self.moarProxies[1])
        self.assertIsInstance(self.proxyList.firstSeen(self.moarProxies[1]), float)

    def test_ProxySet_firstSeen_other_tags(self):
        """ProxySet.firstSeen() should return None when a proxy doesn't have a
        timestamp.
        """
        self.proxyList.add(self.moarProxies[2], 'sometag')
        self.assertIsNone(self.proxyList.firstSeen(self.moarProxies[2]))

    def test_ProxySet_issubset(self):
        """ProxySet.issubset() on a superset should return True."""
        self.assertTrue(self.proxyList.issubset(set(self.proxies + self.moarProxies[:0])))

    def test_ProxySet_issuperset(self):
        """ProxySet.issubset() on a subset should return True."""
        self.assertTrue(self.proxyList.issuperset(set(self.proxies[:1])))

    def test_ProxySet_intersection(self):
        """ProxySet.intersection() should return the combination of two
        disjoint sets.
        """
        raise unittest.SkipTest(
            ("FIXME: bridgedb.proxy.ProxySet.intersection() is broken and "
             "always returns an empty set()."))

        a = self.proxies
        a.extend(self.moarProxies)
        a = set(a)
        b = self.proxyList.intersection(set(self.moarProxies))
        self.assertItemsEqual(a, b)

    def test_ProxySet_remove(self):
        """ProxySet.remove() should subtract proxies which were already added
        to the set.
        """
        self.proxyList.remove(self.proxies[0])
        self.assertEquals(len(self.proxyList), len(self.proxies) - 1)
        self.assertNotIn(self.proxies[0], self.proxyList)

    def test_ProxySet_remove_nonexistent(self):
        """ProxySet.remove() shouldn't subtract proxies which aren't already in
        the set.
        """
        self.proxyList.remove('110.110.110.110')
        self.assertEquals(len(self.proxyList), len(self.proxies))
        self.assertNotIn('110.110.110.110', self.proxyList)

    def test_ProxySet_replaceProxyList(self):
        """ProxySet.replaceProxyList should remove all the current proxies and
        add all the new ones.
        """
        self.proxyList.replaceProxyList(self.moarProxies, 'seven proxies')
        for p in self.moarProxies:
            self.assertIn(p, self.proxyList)
            self.assertEqual(self.proxyList.getTag(p), 'seven proxies')
        for p in self.proxies:
            self.assertNotIn(p, self.proxyList)

    def test_ProxySet_replaceProxyList_bad_type(self):
        """ProxySet.replaceProxyList should remove all the current proxies and
        then since we're giving it a bad type it should do nothing else.
        """
        self.proxyList.replaceProxyList([object, object, object])
        self.assertEqual(len(self.proxyList), 0)

    def test_ProxySet_hash(self):
        """Two equal ProxySets should return the same hash."""
        proxyListA = proxy.ProxySet(self.proxies)
        proxyListB = proxy.ProxySet(self.proxies)
        self.assertEqual(proxyListA, proxyListB)
        self.assertItemsEqual(proxyListA, proxyListB)
        self.assertEqual(hash(proxyListA), hash(proxyListB))


class ExitListProtocolTests(unittest.TestCase):
    """Unittests for :class:`~bridgedb.proxy.ExitListProtocol`."""

    def setUp(self):
        self.proto = proxy.ExitListProtocol()

    def test_ExitListProtocol_parseData_error_page(self):
        """ """
        self.proto.data = """\
<!doctype html>
<html lang="en">
<body>
  <div class="content">
  <img src="/torcheck/img/tor-on.png" class="onion" />
  <h4>Welcome to the Tor Bulk Exit List exporting tool.</h4>
  </div>
</body>
</html>"""
        self.proto.parseData()
        self.assertEqual(len(self.proto.exitlist), 0)

    def test_ExitListProtocol_parseData_page_with_3_ips_with_comments(self):
        """ """
        self.proto.data = """\
# This is a list of all Tor exit nodes from the past 16 hours that can contact 1.1.1.1 on port 443 #
# You can update this list by visiting https://check.torproject.org/cgi-bin/TorBulkExitList.py?ip=1.1.1.1&port=443 #
# This file was generated on Fri Feb  6 02:04:27 UTC 2015 #
101.99.64.150
103.10.197.50
103.240.91.7"""
        self.proto.parseData()
        self.assertEqual(len(self.proto.exitlist), 3)

    def test_ExitListProtocol_parseData_page_with_3_ips(self):
        """ """
        self.proto.data = """
101.99.64.150
103.10.197.50
103.240.91.7"""
        self.proto.parseData()
        self.assertEqual(len(self.proto.exitlist), 3)

    def test_ExitListProtocol_parseData_page_with_bad_ip(self):
        """ """
        self.proto.data = """
192.168.0.1
127.0.0.1
103.240.91.7"""
        self.proto.parseData()
        self.assertEqual(len(self.proto.exitlist), 1)

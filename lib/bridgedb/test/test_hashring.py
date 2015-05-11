# -*- coding: utf-8 -*-

from __future__ import print_function

import math
import random

from twisted.trial import unittest
from zope.interface.verify import verifyObject

from bridgedb import hashring
from bridgedb.bridges import Bridge
from bridgedb.test.util import generateFakeBridges


BRIDGES = generateFakeBridges()


class HashringTests(unittest.TestCase):
    """Unittests for :class:`bridgedb.hashring.Hashring`."""

    def setUp(self):
        self.bridges = BRIDGES

    def test_Hashring_init(self):
        self.assertTrue(verifyObject(hashring.IHashring,
                                     hashring.Hashring('key')))

    def test_Hashring_init_name_attribute(self):
        """New ``Hashring``s should have a ``name`` attribute set to 'Ring'."""
        ring = hashring.Hashring('mimsyweretheborogroves')
        self.assertEquals(ring.name, str())

    def test_Hashring_name(self):
        """Hashring.name should set the name attribute."""
        ring = hashring.Hashring('mimsyweretheborogroves')
        ring.name = 'borogroves'
        self.assertEquals(ring.name, "borogroves")

    def test_Hashring_name_two_subrings(self):
        """Hashring.name should set the name attribute for subrings."""
        key = 'andmomedidrathsoutgrabe'
        ring = hashring.Hashring(key)
        ring.name = 'raths'

        subring0 = hashring.Hashring(key)
        subring1 = hashring.Hashring(key)
        ring.addSubring(subring0, 'outgrabe')
        ring.addSubring(subring1, 'mome')
     
        self.assertEquals(ring.name, 'raths')
        self.assertEquals(ring.subrings[0].name, 'raths (outgrabe)')
        self.assertEquals(ring.subrings[1].name, 'raths (mome)')

    def test_Hashring_addSubring(self):
        """Calling addSubring() should add the subring to subrings."""
        ring = hashring.Hashring('key')
        self.assertEqual(len(ring.subrings), 0)
        ring.addSubring(hashring.Hashring('key'))
        self.assertEqual(len(ring.subrings), 1)

    def test_Hashring_addSubring_with_name(self):
        """Calling addSubring() should add the subring to subrings and give the
        subring a name.
        """
        ring = hashring.Hashring('key')
        self.assertEqual(len(ring.subrings), 0)
        ring.addSubring(hashring.Hashring('key'), 'awesome')
        self.assertEqual(len(ring.subrings), 1)
        self.assertEqual(ring.subrings[0].name, '(awesome)')

    def test_Hashring_addSubring_not_IHashring(self):
        """Adding the wrong type of object as a subring should raise a
        TypeError.
        """
        class NotHashring(object): pass

        ring = hashring.Hashring('key')
        self.assertRaises(TypeError, ring.addSubring, NotHashring())

    def test_Hashring_insert_without_subrings(self):
        """Inserting bridges into a hashring should put the bridges in _keys
        and _ring.
        """
        ring = hashring.Hashring('key')
        ring.insert(*self.bridges)
        self.assertEqual(len(ring), len(self.bridges))
        self.assertEqual(len(ring._keys), len(self.bridges))

    def test_Hashring_contains(self):
        """A hashring with a specific bridge in it should report that the
        bridge is in that hashring.
        """
        ring = hashring.Hashring('key')
        ring.insert(*self.bridges)
        bridge = self.bridges[random.randint(0, len(self.bridges)-1)]
        self.assertTrue(bridge in ring)

    def test_Hashring_contains_false(self):
        """A hashring without a specific bridge in it should not report that
        the bridge is in that hashring.
        """
        ring = hashring.Hashring('key')
        ring.insert(*self.bridges[:100])
        bridge = self.bridges[random.randint(100, len(self.bridges)-1)]
        self.assertFalse(bridge in ring)

    def test_Hashring_contains_with_subring(self):
        """A hashring without a specific bridge in it should not report that
        the bridge is in that hashring.
        """
        ring = hashring.Hashring('key')
        ring.addSubring(hashring.Hashring('bar'), 'bar')
        ring.insert(*self.bridges)
        bridge = self.bridges[random.randint(0, len(self.bridges)-1)]
        self.assertTrue(bridge in ring)

    def test_Hashring_iter(self):
        ring = hashring.Hashring('key')
        ring.insert(*self.bridges)
        for bridge in ring:
            self.assertIsInstance(bridge, Bridge)

    def test_Hashring_insert_with_two_subrings(self):
        """Inserting a bridge into a hashring should put the bridges the
        subrings.
        """
        ring = hashring.Hashring('foo')
        ring.addSubring(hashring.Hashring('bar'), 'bar')
        ring.addSubring(hashring.Hashring('baz'), 'baz')
        ring.insert(*self.bridges)
        self.assertEqual(len(ring), len(self.bridges))
        self.assertApproximates(len(ring.subrings[0]), len(ring.subrings[1]), 75)
        self.assertEqual(len(ring._keys), 0)

    def test_Hashring_insert_intervals(self):
        """The intervals between inserted items should be approximately equal."""
        ring = hashring.Hashring('key')
        ring.insert(*self.bridges)
        
        # The distance between one key and the next key (to the right) of it:
        intervals = []

        print()
        for index, key in zip(range(len(ring._keys)), ring._keys):
            key = int(key, 16)
            try:
                interval = int(ring._keys[index+1], 16) - key
            except IndexError:
                # The total size of the hash space is 2**32 since we truncate
                # HMACs to 32-bit ints.
                #interval = ((2**32) - key) + int(ring._keys[0], 16)
                # XXX We stopped truncating, it's 64 bits now.
                interval = ((2**64) - key) + int(ring._keys[0], 16)
            print("  key = %s    interval = %r" %
                  (int(ring._keys[index], 16), interval))
            intervals.append(interval)

        mean = sum(intervals) / len(intervals)
        stddev = int(math.sqrt(
            sum([((x - mean)**2) for x in intervals]) / len(intervals)))

        print("  ----------------------------------------")
        print("  Minimum interval = %r" % min(intervals))
        print("  Maximum interval = %r" % max(intervals))
        print("  Mean = %r" % mean)
        print("  Standard deviation (σ) = %r" % stddev)
        print("  σ/mean %% = %d%% " % float((stddev/mean) * 100))
        print()
        print("This looks bad, and it is. This is why we use consistent "
              "hashrings instead.")

    def test_Hashring_clear_without_subrings(self):
        """Clearing a hashring should get rid of all the items in _keys
        and _ring.
        """
        ring = hashring.Hashring('key')
        ring.insert(*self.bridges)
        self.assertEqual(len(ring), len(self.bridges))
        self.assertEqual(len(ring._keys), len(self.bridges))

        ring.clear()
        self.assertEqual(len(ring), 0)
        self.assertEqual(len(ring._keys), 0)
        self.assertEqual(len(ring._ring), 0)

    def test_Hashring_clear_with_two_subrings(self):
        """Clearing a hashring with subrings should clear the subrings."""
        ring = hashring.Hashring('foo')
        ring.addSubring(hashring.Hashring('bar'), 'bar')
        ring.addSubring(hashring.Hashring('baz'), 'baz')
        ring.insert(*self.bridges)
        self.assertEqual(len(ring), len(self.bridges))
        self.assertApproximates(len(ring.subrings[0]), len(ring.subrings[1]), 100)
        self.assertEqual(len(ring._keys), 0)

        ring.clear()
        self.assertEqual(len(ring), 0)
        self.assertEqual(len(ring._ring), 0)
        self.assertEqual(len(ring._keys), 0)

        for subring in ring.subrings:
            self.assertEqual(len(subring), 0)

    def test_Hashring_clear_with_two_subrings_and_two_bridge_sets(self):
        """Hashring.clear() should also clear subrings."""
        key = 'clearsubringstoo'
        ring = hashring.Hashring(key)
        ring.addSubring(hashring.Hashring(key))
        self.assertEqual(len(ring.subrings), 1)

        ring.insert(*self.bridges[:250])
        self.assertEqual(len(ring), 250)
        self.assertEqual(len(ring._keys), 0)
        self.assertEqual(len(ring.subrings[0]), 250)

        ring.addSubring(hashring.Hashring(key))
        self.assertEqual(len(ring.subrings), 2)

        ring.insert(*self.bridges[250:])
        self.assertEqual(len(ring), 500)
        self.assertEqual(len(ring._keys), 0)
        self.assertApproximates(len(ring.subrings[0]), 375, 25)
        self.assertApproximates(len(ring.subrings[1]), 125, 25)

        ring.clear()
        self.assertEqual(len(ring), 0)
        self.assertEqual(len(ring.subrings), 2)
        self.assertEqual(len(ring.subrings[0]), 0)
        self.assertEqual(len(ring.subrings[1]), 0)

    def test_Hashring_exportToFile(self):
        """hashring.exportToFile() should write certain data about the items to
        the specified file.
        """
        filename = "%s.assignments.log" % self.id()
        ring = hashring.Hashring('foo')
        ring.insert(*self.bridges)
        ring.exportToFile(filename, description="Non-xyzzy distributor")

        with open(filename) as fh:
            print(fh.read())

    def test_Hashring_exportToFile_with_subrings(self):
        """hashring.exportToFile() should write certain data about the items to
        the specified file.
        """
        filename = "%s.assignments.log" % self.id()
        ring = hashring.Hashring('foo')
        ring.addSubring(hashring.Hashring('bar'), 'bar')
        ring.addSubring(hashring.Hashring('baz'), 'baz')
        ring.insert(*self.bridges)
        ring.exportToFile(filename, description="Non-xyzzy distributor")

        with open(filename) as fh:
            print(fh.read())

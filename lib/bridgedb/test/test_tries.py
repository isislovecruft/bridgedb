# -*- coding: utf-8  -*-
# ____________________________________________________________________________
#
# This file is part of BridgeDB, a Tor bridge distribution system.
#
# :authors: Isis Lovecruft 0xA3ADB67A2CDB8B35 <isis@torproject.org>
#           please also see AUTHORS file
# :copyright: (c) 2013-2015, Isis Lovecruft
#             (c) 2007-2015, The Tor Project, Inc.
# :license: see LICENSE for licensing information
# ____________________________________________________________________________

"""Unittests for :mod:`bridgedb.trie`."""

from __future__ import print_function

import logging

from twisted.trial import unittest

from bridgedb import tries
from bridgedb.hashring import Hashring
from bridgedb.test.util import Benchmarker


def buildComplexTree(tree):
    """Build a rather complex tree with the following structure::

                               +---+
                               |   |
                               +-+-+
                                 |
                     +--------+--+--+-----+
                     |        |     |     |
                   +-+-+    +-+-+ +-+-+ +-+-+
                   | 1 |    | 2 | | 3 | | 4 |
                   +-+-+    +-+-+ +---+ +-+-+
                     |        |           |
               +-----+        |           +-----+-----+
               |     |        |           |     |     |
             +-+-+ +-+-+    +-+-+       +-+-+ +-+-+ +-+-+
             | 5 | | 6 |    | 7 |       | 8 | | 9 | | 10|
             +-+-+ +---+    +-+-+       +-+-+ +---+ +---+
               |     |        |           |
               |     |     +--+--+     +--+--+-----+-----+
               |     |     |     |     |     |     |     |
             +-+-+ +-+-+ +-+-+ +-+-+ +-+-+ +-+-+ +-+-+ +-+-+
             | 11| | 12| | 13| | 14| | 15| | 16| | 17| | 18|
             +---+ +---+ +---+ +---+ +---+ +---+ +---+ +---+
    """
    tree.insert([1,     ], "1")
    tree.insert([2,     ], "2")
    tree.insert([3,     ], "3")
    tree.insert([4,     ], "4")

    tree.insert([1, 1,  ], "5")
    tree.insert([1, 2,  ], "6")
    tree.insert([2, 1,  ], "7")
    tree.insert([4, 1,  ], "8")
    tree.insert([4, 2,  ], "9")
    tree.insert([4, 3,  ], "10")

    tree.insert([1, 1, 1], "11")
    tree.insert([1, 2, 1], "12")
    tree.insert([2, 1, 1], "13")
    tree.insert([2, 1, 2], "14")

    tree.insert([4, 1, 1], "15")
    tree.insert([4, 1, 2], "16")
    tree.insert([4, 1, 3], "17")
    tree.insert([4, 1, 4], "18")

def buildMoreComplexTree(tree):
    """Build a rather complex tree with the following structure::

                               +---+
                               |   |
                               +-+-+
                                 |
                     +--------+--+--+-----+-------------------+
                     |        |     |     |                   |
                   +-+-+    +-+-+ +-+-+ +-+-+               +-+-+
                   | 1 |    | 2 | | 3 | | 4 |               | 19|
                   +-+-+    +-+-+ +---+ +-+-+               +-+-+
                     |        |           |                   |
               +-----+        |           +-----+-----+       +-----+
               |     |        |           |     |     |       |     |
             +-+-+ +-+-+    +-+-+       +-+-+ +-+-+ +-+-+   +-+-+ +-+-+
             | 5 | | 6 |    | 7 |       | 8 | | 9 | | 10|   | 20| | 21|
             +-+-+ +---+    +-+-+       +-+-+ +---+ +---+   +-+-+ +-+-+
               |     |        |           |
               |     |     +--+--+     +--+--+-----+-----+
               |     |     |     |     |     |     |     |
             +-+-+ +-+-+ +-+-+ +-+-+ +-+-+ +-+-+ +-+-+ +-+-+
             | 11| | 12| | 13| | 14| | 15| | 16| | 17| | 18|
             +---+ +---+ +---+ +---+ +---+ +---+ +---+ +---+

    where nodes ``19``, ``20``, and ``21`` are added in reverse order,
    and have the following key-values:

      - ``"(524 13)"``:    ``"19"``
      - ``"(524 13 41)"``: ``"20"``
      - ``"(524 13 42)"``: ``"21"``
    """
    buildComplexTree(tree)
    tree.insert([524, 13, 42], "21")
    tree.insert([524, 13, 41], "20")
    tree.insert([524, 13,   ], "19")

def buildDeepComplexTree(tree):
    """Build a very deep, rather complex tree with the following
    structure::

                               +---+
                               |   |
                               +-+-+
                                 |
                     +--------+--+--+-----+
                     |        |     |     |
                   +-+-+    +-+-+ +-+-+ +-+-+
                   | 1 |    | 2 | | 3 | | 4 |
                   +-+-+    +-+-+ +---+ +-+-+
                     |        |           |
               +-----+        |           +-----+-----+
               |     |        |           |     |     |
             +-+-+ +-+-+    +-+-+       +-+-+ +-+-+ +-+-+
             | 5 | | 6 |    | 7 |       | 8 | | 9 | | 10|
             +-+-+ +---+    +-+-+       +-+-+ +---+ +---+
               |     |        |           |
               |     |     +--+--+     +--+--+-----+-----+
               |     |     |     |     |     |     |     |
             +-+-+ +-+-+ +-+-+ +-+-+ +-+-+ +-+-+ +-+-+ +-+-+
             | 11| | 12| | 13| | 14| | 15| | 16| | 17| | 18|
             +---+ +-+-+ +---+ +---+ +---+ +---+ +---+ +---+
                     |
                     |
                     |
                   +-+-+
                   | 19|
                   +-+-+
                     ⋮
                     ⋮
                     ⋮
                   +-+-+
                   | 29|
                   +-+-+

    with a total of 30 nodes, nested 15 levels deep.
    """
    print("\nBuilding base complex tree structure...")
    buildComplexTree(tree)
    print("Deepening the tree...")
    print("Reticulating splines...")

    key = [1, 2, 1]
    for i in range(19, 30):
        key.append(1)
        tree.insert(key, str(i))


class AdaptiveMetricTreeNodeTests(unittest.TestCase):
    def setUp(self):
        self.node = tries.AdaptiveMetricTreeNode()

    def buildBranches(self):
        for i in range(1, 5):
            node = tries.AdaptiveMetricTreeNode([i], str(i))
            self.node.branches.append(node)

    def test_AdaptiveMetricTreeNode_countMatching_all_matching(self):
        """AdaptiveMetricTreeNode.countMatching([1,2,3]) when the node's key is
        [1, 2, 3] should return 3.
        """
        self.node.key = [1, 2, 3]
        self.assertEqual(self.node.countMatching([1, 2, 3]), 3)

    def test_AdaptiveMetricTreeNode_countMatching_some_matching(self):
        """AdaptiveMetricTreeNode.countMatching([1,1,3]) when the node's key is
        [1, 2, 3] should return 1.
        """
        self.node.key = [1, 2, 3]
        self.assertEqual(self.node.countMatching([1, 1, 3]), 1)

    def test_AdaptiveMetricTreeNode_countMatching_none_matching(self):
        """AdaptiveMetricTreeNode.countMatching([6,6,6]) when the node's key is
        [1, 2, 3] should return 0.
        """
        self.node.key = [1, 2, 3]
        self.assertEqual(self.node.countMatching([6, 6, 6]), 0)

    def test_AdaptiveMetricTreeNode_items(self):
        """AdaptiveMetricTreeNode.items() should return a list (key, item)s,
        for all nodes in the node's branches.
        """
        self.buildBranches()
        self.assertEqual(self.node.items(),
                         [([1], "1"), ([2], "2"), ([3], "3"), ([4], "4")])

    def test_AdaptiveMetricTreeNode_values(self):
        """AdaptiveMetricTreeNode.values() should return a list of
        ``node.item``s, for all nodes in the node's branches.
        """
        self.buildBranches()
        self.assertEqual(self.node.values(), ["1", "2", "3", "4"])

    def test_AdaptiveMetricTreeNode_sort_with_duplicates(self):
        """Calling AdaptiveMetricTreeNode.sort() with duplicates within it's
        branches should still correctly sort the nodes (but retain the
        duplicates).
        """
        self.buildBranches()
        self.node.branches.extend(self.node.branches)
        self.assertEqual(self.node.keys(),
                         [[1], [2], [3], [4], [1], [2], [3], [4]])
        self.node.sort()
        self.assertEqual(self.node.keys(),
                         [[1], [1], [2], [2], [3], [3], [4], [4]])

    def test_AdaptiveMetricTreeNode_sort_reversed(self):
        """Calling AdaptiveMetricTreeNode.sort() with the nodes in reverse
        order should correctly sort the nodes.
        """
        for i in reversed(range(1, 5)):
            node = tries.AdaptiveMetricTreeNode([i], str(i))
            self.node.branches.append(node)

        self.assertEqual(self.node.keys(),
                         [[4], [3], [2], [1]])
        self.node.sort()
        self.assertEqual(self.node.keys(),
                         [[1], [2], [3], [4]])


class AdaptiveMetricTreeTests(unittest.TestCase):
    def setUp(self):
        self.tree = tries.AdaptiveMetricTree()

    def buildComplexTree(self):
        buildComplexTree(self.tree)

    def buildMoreComplexTree(self):
        buildMoreComplexTree(self.tree)

    def buildDeepComplexTree(self):
        buildDeepComplexTree(self.tree)

    def buildSimpleTree(self):
        """Build a very simple tree with the following structure::

                               +---+
                               |   |
                               +-+-+
                                 |
                                 |
                                 |
                               +-+-+
                               |one|
                               +-+-+
                                 |
                                 |
                                 |
                             +---+----+
                             |one,one |
                             +--------+

        """
        self.tree.insert([1   ], "one")
        self.tree.insert([1, 1], "one,one")

    def checkComplexTreeItems(self):
        """Check that the items within the tree (as constructed by calling
        :meth:`buildComplexTree`) are correct.
        """
        self.assertEqual(self.tree.trunk.item, None)
        self.assertEqual(self.tree.trunk.branches[0].item, "1")  # (1)
        self.assertEqual(self.tree.trunk.branches[1].item, "2")  # (2)
        self.assertEqual(self.tree.trunk.branches[2].item, "3")  # (3)
        self.assertEqual(self.tree.trunk.branches[3].item, "4")  # (4)

        self.assertEqual(self.tree.trunk.branches[0].branches[0].item, "5")   # (1 1)
        self.assertEqual(self.tree.trunk.branches[0].branches[1].item, "6")   # (1 2)
        self.assertEqual(self.tree.trunk.branches[1].branches[0].item, "7")   # (2 1)
        self.assertEqual(self.tree.trunk.branches[3].branches[0].item, "8")   # (4 1)
        self.assertEqual(self.tree.trunk.branches[3].branches[1].item, "9")   # (4 2)
        self.assertEqual(self.tree.trunk.branches[3].branches[2].item, "10")  # (4 3)

        self.assertEqual(self.tree.trunk.branches[0].branches[0].branches[0].item, "11")   # (1 1 1)
        self.assertEqual(self.tree.trunk.branches[0].branches[1].branches[0].item, "12")   # (1 2 1)
        self.assertEqual(self.tree.trunk.branches[1].branches[0].branches[0].item, "13")   # (2 1 1)
        self.assertEqual(self.tree.trunk.branches[1].branches[0].branches[1].item, "14")   # (2 1 2)
        self.assertEqual(self.tree.trunk.branches[3].branches[0].branches[0].item, "15")   # (4 1 1)
        self.assertEqual(self.tree.trunk.branches[3].branches[0].branches[1].item, "16")   # (4 1 2)
        self.assertEqual(self.tree.trunk.branches[3].branches[0].branches[2].item, "17")   # (4 1 3)
        self.assertEqual(self.tree.trunk.branches[3].branches[0].branches[3].item, "18")   # (4 1 4)

    def checkComplexTreeKeys(self):
        """Check that the keys within the tree (as constructed by calling
        :meth:`buildComplexTree`) are correct.
        """
        self.assertEqual(self.tree.trunk.key, [])
        self.assertEqual(self.tree.trunk.branches[0].key, [1])  # (1)
        self.assertEqual(self.tree.trunk.branches[1].key, [2])  # (2)
        self.assertEqual(self.tree.trunk.branches[2].key, [3])  # (3)
        self.assertEqual(self.tree.trunk.branches[3].key, [4])  # (4)

        self.assertEqual(self.tree.trunk.branches[0].branches[0].key, [1, 1])   # (1 1)
        self.assertEqual(self.tree.trunk.branches[0].branches[1].key, [1, 2])   # (1 2)
        self.assertEqual(self.tree.trunk.branches[1].branches[0].key, [2, 1])   # (2 1)
        self.assertEqual(self.tree.trunk.branches[3].branches[0].key, [4, 1])   # (4 1)
        self.assertEqual(self.tree.trunk.branches[3].branches[1].key, [4, 2])   # (4 2)
        self.assertEqual(self.tree.trunk.branches[3].branches[2].key, [4, 3])   # (4 3)

        self.assertEqual(self.tree.trunk.branches[0].branches[0].branches[0].key, [1, 1, 1])   # (1 1 1)
        self.assertEqual(self.tree.trunk.branches[0].branches[1].branches[0].key, [1, 2, 1])   # (1 2 1)
        self.assertEqual(self.tree.trunk.branches[1].branches[0].branches[0].key, [2, 1, 1])   # (2 1 1)
        self.assertEqual(self.tree.trunk.branches[1].branches[0].branches[1].key, [2, 1, 2])   # (2 1 2)
        self.assertEqual(self.tree.trunk.branches[3].branches[0].branches[0].key, [4, 1, 1])   # (4 1 1)
        self.assertEqual(self.tree.trunk.branches[3].branches[0].branches[1].key, [4, 1, 2])   # (4 1 2)
        self.assertEqual(self.tree.trunk.branches[3].branches[0].branches[2].key, [4, 1, 3])   # (4 1 3)
        self.assertEqual(self.tree.trunk.branches[3].branches[0].branches[3].key, [4, 1, 4])   # (4 1 4)

    def checkMoreComplexTreeKeys(self):
        """Check that the keys within the tree (as constructed by calling
        :meth:`buildMoreComplexTree`) are correct.
        """
        self.assertIn([524, 13, 42], self.tree)
        self.assertIn([524, 13, 41], self.tree)
        self.assertIn([524, 13,   ], self.tree)

        # Check that the keys are correctly ordered:
        self.assertEqual(self.tree.get("(524 13)").keys(),
                         [[524, 13, 41], [524, 13, 42]])

    def test_AdaptiveMetricTree_init(self):
        """We should be able to initialise an AdaptiveMetricTree."""
        self.assertIsInstance(self.tree, tries.AdaptiveMetricTree)

    def test_AdaptiveMetricTree_contains_list(self):
        """The statement::

            [1] in tree

        when there IS a node in the tree whose key is equal to the
        s-expression ``"(1)"``, should return True.
        """
        self.buildSimpleTree()
        self.assertIn([1], self.tree)
        self.assertIn([1, 1], self.tree)
        self.assertTrue([1] in self.tree)
        self.assertTrue([1, 1] in self.tree)

    def test_AdaptiveMetricTree_contains_list_missing(self):
        """The statement::

            [1, 2] in tree

        when there IS NOT a node in the tree whose key is equal to the
        s-expression ``"(1 2)"``, should return False.
        """
        self.buildSimpleTree()
        self.assertNotIn([1, 2], self.tree)
        self.assertFalse([1, 2] in self.tree)

    def test_AdaptiveMetricTree_contains_list_trunk(self):
        """The statement::

            [] in tree

        should always return True (because the trunk should always be present).
        """
        self.assertIn([], self.tree)
        self.tree.insert([1, 2], "one,two")
        self.assertIn([], self.tree)
        self.tree.insert([1   ], "one")
        self.assertIn([], self.tree)
        self.tree.insert([1, 1], "one,one")
        self.assertIn([], self.tree)

    def test_AdaptiveMetricTree_contains_sexp(self):
        """The statement::

            "(1 2)" in tree

        when there IS a node in the tree whose key is equal to the
        s-expression ``"(1 2)"``, should return True.
        """
        self.tree.insert([1, 2], "one,two")
        self.assertIn('(1 2)', self.tree)
        self.assertTrue('(1 2)' in self.tree)

    def test_AdaptiveMetricTree_contains_sexp_missing(self):
        """The statement::

            "(1 1)" in tree

        when there IS NOT a node in the tree whose key is equal to the
        s-expression ``"(1 1)"``, should return False.
        """
        self.tree.insert([1, 2], "one,two")
        # But not parents of any other subtrees:
        self.assertNotIn('(2)', self.tree)
        # Nor any additional siblings:
        self.assertNotIn('(1 1)', self.tree)

    def test_AdaptiveMetricTree_contains_sexp_trunk(self):
        """The statement::

            "()" in tree

        should always return True (because the trunk should always be present).
        """
        self.assertIn('()', self.tree)
        self.tree.insert([1, 2], "one,two")
        self.assertIn('()', self.tree)
        self.tree.insert([1   ], "one")
        self.assertIn('()', self.tree)
        self.tree.insert([1, 1], "one,one")
        self.assertIn('()', self.tree)

    def test_AdaptiveMetricTree_contains_benchmark_complex(self):
        """A benchmark test for AdaptiveMetricTree.__contains__()."""
        self.buildComplexTree()

        keys = self.tree.keys()
        keys = keys[:5] + keys[-5:] # Sample the first and last five

        print()
        for key in keys:
            with Benchmarker():
                self.assertTrue(key in self.tree)

    def test_AdaptiveMetricTree_contains_benchmark_more_complex(self):
        """A benchmark test for AdaptiveMetricTree.__contains__()."""
        self.buildMoreComplexTree()

        keys = self.tree.keys()
        keys = keys[:5] + keys[-5:] # Sample the first and last five

        print()
        for key in keys:
            with Benchmarker():
                self.assertTrue(key in self.tree)

    def test_AdaptiveMetricTree_contains_benchmark_deep(self):
        """A benchmark test for AdaptiveMetricTree.__contains__()."""
        self.buildDeepComplexTree()

        keys = self.tree.keys()
        keys = keys[:5] + keys[-5:] # Sample the first and last five

        for key in keys:
            with Benchmarker():
                self.assertTrue(key in self.tree)

    def test_AdaptiveMetricTree_iter(self):
        """Iterating over a tree should return all the nodes in the tree, in
        breadth-first (i.e. level-) order.
        """
        self.buildComplexTree()

        nodes = list(self.tree.traverse().queue)
        for i, node in enumerate(iter(self.tree)):
            self.assertEqual(nodes[i], node)

    def test_AdaptiveMetricTree_len(self):
        """The length of an empty tree should be 0."""
        self.assertEqual(len(self.tree), 0)

    def test_AdaptiveMetricTree_len_simple(self):
        """The length of a tree should be equal to the number of the elements
        in ``tree.trunk.branches`` (and should not include subbranches of those
        branches).
        """
        self.buildSimpleTree()
        self.assertEqual(len(self.tree), 1)

    def test_AdaptiveMetricTree_len_complex(self):
        """The length of a tree should be equal to the number of the elements
        in ``tree.trunk.branches``.
        """
        self.buildComplexTree()
        self.assertEqual(len(self.tree), 4)

    def test_AdaptiveMetricTree_str_empty(self):
        """Check that the graph of an empty tree is as boring as it sounds."""
        graph = str(self.tree)

        # There should be a TRUNK and some LEAFs:
        self.assertIn("TRUNK", graph)
        self.assertIn("LEAF", graph)

        # And… the graph of an empty tree turns out to be pretty boring:
        self.assertEqual(graph, " TRUNK  LEAF []: None")

    def test_AdaptiveMetricTree_str_complex(self):
        """Check that the string representation of the tree includes all the
        nodes, plus some other useful information.
        """
        self.buildComplexTree()
        graph = str(self.tree)

        # There should be a TRUNK and some LEAFs:
        self.assertIn("TRUNK", graph)
        self.assertIn("LEAF", graph)

        # Check that all the nodes and their items made it into the graph:
        for key, item in self.tree.items():
            self.assertIn(str(key), graph)
            self.assertIn(str(item), graph)

    def test_AdaptiveMetricTree_insert(self):
        """Calling ``tree.insert([1])`` should add the branch to
        ``tree.trunk.branches``.
        """
        self.tree.insert([1], "first")

        self.assertEqual(len(self.tree.trunk.branches), 1)
        self.assertEqual(self.tree.trunk.branches[0].key, [1])
        self.assertEqual(self.tree.trunk.branches[0].item, "first")
        self.assertEqual(len(self.tree.trunk.branches[0].branches), 0)

    def test_AdaptiveMetricTree_insert_length_increases(self):
        """Each time a branch is added to the ``tree.trunk``, the length of the
        tree should increase by 1.
        """
        self.assertEqual(len(self.tree), 0)

        self.tree.insert([1], "apple")

        self.assertEqual(len(self.tree), 1)
        self.assertEqual(self.tree.trunk.branches[0].key, [1])
        self.assertEqual(self.tree.trunk.branches[0].item, "apple")

        self.tree.insert([2], "banana")

        self.assertEqual(len(self.tree), 2)
        self.assertEqual(self.tree.trunk.branches[1].key, [2])
        self.assertEqual(self.tree.trunk.branches[1].item, "banana")

        self.tree.insert([3], "carrot")

        self.assertEqual(len(self.tree), 3)
        self.assertEqual(self.tree.trunk.branches[2].key, [3])
        self.assertEqual(self.tree.trunk.branches[2].item, "carrot")

    def test_AdaptiveMetricTree_insert_automatic_parents(self):
        """Adding a branch with depth-3, i.e. "(1 1 1)" to a bare tree should
        automatically add both the parent "(1 1)" and the grandparent "(1)" to
        the tree.  Both the parent and the grandparent's items should be set
        to None.
        """
        self.tree.insert([1, 1, 1], "abc")

        # The grandparent should have been automatically added:
        self.assertIn('(1)', self.tree)
        # The parent also should have been automatically added:
        self.assertIn('(1 1)', self.tree)

    def test_AdaptiveMetricTree_insert_duplicate(self):
        """Adding an item with a key that is already in the tree should replace
        the item for that key.
        """
        self.assertEqual(len(self.tree), 0)

        self.tree.insert([1], "elm")

        self.assertEqual(len(self.tree), 1)
        self.assertEqual(self.tree.trunk.branches[0].key, [1])
        self.assertEqual(self.tree.trunk.branches[0].item, "elm")

        self.tree.insert([1], "douglas fir")

        self.assertEqual(len(self.tree), 1)
        self.assertEqual(self.tree.trunk.branches[0].key, [1])
        self.assertEqual(self.tree.trunk.branches[0].item, "douglas fir")

        self.tree.insert([1], "linden")

        self.assertEqual(len(self.tree), 1)
        self.assertEqual(self.tree.trunk.branches[0].key, [1])
        self.assertEqual(self.tree.trunk.branches[0].item, "linden")

    def test_AdaptiveMetricTree_insert_split(self):
        """When branches are added from the leaves inward (towards the trunk),
        the parent branches should always be present.  When the parent branch
        is actually added, its item should cease to be None and instead be
        whatever the added item was.
        """
        self.tree.insert([1, 1, 1], "baz")

        self.assertEqual(len(self.tree), 1)

        self.assertEqual(self.tree.trunk.branches[0].depth, 1)
        self.assertEqual(self.tree.trunk.branches[0].branches[0].depth, 2)
        self.assertEqual(self.tree.trunk.branches[0].branches[0].branches[0].depth, 3)

        self.assertEqual(self.tree.trunk.branches[0].item, None)
        self.assertEqual(self.tree.trunk.branches[0].branches[0].item, None)
        self.assertEqual(self.tree.trunk.branches[0].branches[0].branches[0].item, "baz")

        self.tree.insert([1, 1,  ], "bar")

        self.assertEqual(len(self.tree), 1)

        self.assertEqual(self.tree.trunk.branches[0].depth, 1)
        self.assertEqual(self.tree.trunk.branches[0].branches[0].depth, 2)
        self.assertEqual(self.tree.trunk.branches[0].branches[0].branches[0].depth, 3)

        self.assertEqual(self.tree.trunk.branches[0].item, None)
        self.assertEqual(self.tree.trunk.branches[0].branches[0].item, "bar")
        self.assertEqual(self.tree.trunk.branches[0].branches[0].branches[0].item, "baz")

        self.tree.insert([1,     ], "foo")

        self.assertEqual(len(self.tree), 1)

        self.assertEqual(self.tree.trunk.branches[0].depth, 1)
        self.assertEqual(self.tree.trunk.branches[0].branches[0].depth, 2)
        self.assertEqual(self.tree.trunk.branches[0].branches[0].branches[0].depth, 3)

        self.assertEqual(self.tree.trunk.branches[0].item, "foo")
        self.assertEqual(self.tree.trunk.branches[0].branches[0].item, "bar")
        self.assertEqual(self.tree.trunk.branches[0].branches[0].branches[0].item, "baz")

        self.assertEqual(self.tree.trunk.branches[0].key, [1])
        self.assertEqual(self.tree.trunk.branches[0].branches[0].key, [1, 1])
        self.assertEqual(self.tree.trunk.branches[0].branches[0].branches[0].key, [1, 1, 1])

    def test_AdaptiveMetricTree_insert_complex_tree(self):
        """Build a (rather) complex tree and run some base tests on it."""
        self.buildComplexTree()
        self.checkComplexTreeItems()
        self.checkComplexTreeKeys()

    def test_AdaptiveMetricTree_insert_more_complex_tree(self):
        """Build a more complex tree and check that all the branches were added
        and that they are correctly ordered (even when added in reverse, from
        the leaves towards the trunk).
        """
        self.buildMoreComplexTree()
        self.checkMoreComplexTreeKeys()
        print("\n" + str(self.tree))

    def test_AdaptiveMetricTree_insert_really_complex_tree(self):
        """Build a really complex tree and check that all the branches were
        added and that they are correctly ordered (even when added in reverse,
        from the leaves towards the trunk).
        """
        self.buildMoreComplexTree()
        self.checkMoreComplexTreeKeys()

        self.tree.insert([4, 3, 4   ], "22")
        self.assertIn([  4,  3,  4], self.tree)

        self.tree.insert([4, 3, 2   ], "23")
        self.assertIn([  4,  3,  4], self.tree)
        self.assertIn([  4,  3,  2], self.tree)

        self.tree.insert([4, 3, 2, 2], "24")
        self.assertIn([  4,  3,  4], self.tree)
        self.assertIn([  4,  3,  2], self.tree)
        self.assertIn([  4,  3,  2, 2], self.tree)

        self.tree.insert([4, 3, 3   ], "25")
        self.assertIn([  4,  3,  4], self.tree)
        self.assertIn([  4,  3,  2], self.tree)
        self.assertIn([  4,  3,  2, 2], self.tree)
        self.assertIn([  4,  3,  3], self.tree)

        print("\n" + str(self.tree))

        # Check that the original complex tree is still okay:
        self.checkComplexTreeItems()
        self.checkComplexTreeKeys()

        # Check that the third layer of rings that we added, underneath (4 3),
        # is in the correct order:
        self.assertEqual(self.tree.trunk.branches[3].branches[2].branches[0].key, [4, 3, 2])
        self.assertEqual(self.tree.trunk.branches[3].branches[2].branches[1].key, [4, 3, 3])
        self.assertEqual(self.tree.trunk.branches[3].branches[2].branches[2].key, [4, 3, 4])

    def test_AdaptiveMetricTree_get_sexp(self):
        """Doing tree.get('(4 1 3)'), when a node with the s-expression key
        '(4 1 3)' exists in the tree, should return that node.
        """
        self.buildComplexTree()

        node = self.tree.get("(4 1 3)")
        self.assertIsInstance(node, tries.AdaptiveMetricTreeNode)
        self.assertEqual(node.key, [4, 1, 3])
        self.assertEqual(str(node), "(4 1 3)")

    def test_AdaptiveMetricTree_get_list(self):
        """Doing tree.get([4, 1, 3]), when a node with the key
        [4, 1, 4] exists in the tree, should return that node.
        """
        self.buildComplexTree()

        node = self.tree.get([4, 1, 3])
        self.assertIsInstance(node, tries.AdaptiveMetricTreeNode)
        self.assertEqual(node.key, [4, 1, 3])
        self.assertEqual(str(node), "(4 1 3)")

    def test_AdaptiveMetricTree_get_sexp_missing(self):
        """Doing tree.get('(5 5 5)'), when no node with that key exists in the
        tree, should return None.
        """
        self.buildComplexTree()

        node = self.tree.get("(5 5 5)")
        self.assertIsNone(node)

    def test_AdaptiveMetricTree_get_list_missing(self):
        """Doing tree.get([5, 5, 5]), when no node with that key exists in the
        tree, should return None.
        """
        self.buildComplexTree()

        node = self.tree.get([5, 5, 5])
        self.assertIsNone(node)

    def test_AdaptiveMetricTree_prune_list(self):
        """Pruning a branch from the tree should cause that node and all of its
        branches to be removed from the tree.
        """
        self.buildComplexTree()

        self.assertEqual(len(self.tree), 4)
        self.assertEqual(len(self.tree.trunk.branches[3].branches), 3)
        self.assertIsNotNone(self.tree.get([4, 1]))
        self.assertIsNotNone(self.tree.get([4, 2]))

        self.tree.prune([4, 1])

        self.assertEqual(len(self.tree), 4)
        self.assertEqual(len(self.tree.trunk.branches[3].branches), 2)
        self.assertIsNone(self.tree.get([4, 1]))
        self.assertIsNotNone(self.tree.get([4, 2]))

    def test_AdaptiveMetricTree_prune_trunk(self):
        """Pruning the trunk node of the tree should erase the entire tree."""
        self.buildComplexTree()

        self.assertEqual(len(self.tree), 4)
        self.tree.prune("()")
        self.assertEqual(len(self.tree), 0)

    def test_AdaptiveMetricTree_prune_sexp(self):
        """Pruning a level-1 node should remove that entire section of the
        tree.
        """
        self.buildComplexTree()

        self.assertEqual(len(self.tree), 4)
        self.tree.prune("(4)")
        self.assertEqual(len(self.tree), 3)

    def test_AdaptiveMetricTree_prune_level_two(self):
        """Pruning a level-2 node should remove that entire section of the
        tree.
        """
        self.buildComplexTree()

        self.assertEqual(len(self.tree), 4)
        self.tree.prune("(2 1)")
        self.assertEqual(len(self.tree.trunk.branches[1].branches), 0)

    def test_AdaptiveMetricTree_prune_sexp_missing(self):
        """Pruning a non-existent section of the tree shouldn't do anything."""
        self.buildComplexTree()

        self.assertEqual(len(self.tree), 4)
        self.tree.prune("(42)")
        self.assertEqual(len(self.tree), 4)

    def test_AdaptiveMetricTree_subtree_missing(self):
        """Calling tree.subtree("(6 6 6)"), when no node with the key (6 6 6)
        exists in the ree, should return an empty list.
        """
        self.buildSimpleTree()
        self.assertEqual(self.tree.subtree("(6 6 6)"), [])

    def test_AdaptiveMetricTree_subtree_with_trunk(self):
        """Calling tree.subtree("(2 1)") should return the tree underneath
        node (2 1), including node (2 1).
        """
        self.buildComplexTree()

        subtreeKeys = [node.key for node in self.tree.subtree("(2 1)")]
        self.assertIn([2, 1, 1], subtreeKeys)
        self.assertIn([2, 1, 2], subtreeKeys)

        # It should include node (2 1)
        self.assertEqual(len(subtreeKeys), 3)

    def test_AdaptiveMetricTree_nodes(self):
        """Doing tree.nodes() should return all the nodes."""
        self.buildSimpleTree()
        self.assertEqual(len(self.tree.nodes()), 3)
        self.assertIsInstance(self.tree.nodes(), list)
        self.assertEqual(self.tree.nodes()[0], self.tree.trunk)
        self.assertEqual(self.tree.nodes()[1], self.tree.trunk.branches[0])
        self.assertEqual(self.tree.nodes()[2], self.tree.trunk.branches[0].branches[0])

    def test_AdaptiveMetricTree_values(self):
        """Doing tree.values() should return the items of all the nodes."""
        self.buildSimpleTree()
        self.assertEqual(len(self.tree.values()), 3)
        self.assertIsInstance(self.tree.values(), list)
        self.assertEqual(self.tree.values()[0], None)
        self.assertEqual(self.tree.values()[1], "one")
        self.assertEqual(self.tree.values()[2], "one,one")

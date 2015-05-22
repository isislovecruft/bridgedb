# -*- coding: utf-8 ; test-case-name: bridgedb.test.test_tries ; -*-
#_____________________________________________________________________________
#
# This file is part of BridgeDB, a Tor bridge distribution system.
#
# :authors: Isis Lovecruft 0xA3ADB67A2CDB8B35 <isis@torproject.org>
#           please also see AUTHORS file
# :copyright: (c) 2013-2015, Isis Lovecruft
#             (c) 2007-2015, The Tor Project, Inc.
# :license: see LICENSE for licensing information
#_____________________________________________________________________________

from __future__ import print_function
from __future__ import unicode_literals

import logging

from functools import wraps
from Queue import Queue

import sexpdata as sexp


class SexpressionError(TypeError):
    """Something couldn't be serialized or deserialized as an s-expression."""


def isSexp(exp):
    """Determine if **exp** is a valid s-expression.

    :param str exp: An s-expression.
    :rtype: bool
    :returns: ``True`` if **exp** is a valid s-expression; ``False``
        otherwise.
    """
    try:
        sexp.loads(exp)
    except (TypeError, AssertionError):
        pass
    else:
        return True
    return False

def fromSexp(exp):
    """Deserialize a potential s-expression into a list.

    :type exp: str or list or tuple
    :param exp: A potential s-expression.
    :raises SexpressionError: if **exp** is not a type that can be
        deserialized.
    :rtype: list
    :returns: A Python list representation of the original **sexp**.
    """
    if isinstance(exp, (list, tuple)):
        exp = toSexp(exp)
    if isinstance(exp, basestring):
        try:
            return sexp.loads(exp)
        except (TypeError, AssertionError):
            raise SexpressionError(
                ("Cannot deserialize %r as an s-expression: "
                 "Expected str; got %s.") % (exp, type(exp)))
    else:
        raise SexpressionError(
            ("Cannot deserialize %r as an s-expression: "
             "Expected str; got %s.") % (exp, type(exp)))

def toSexp(exp):
    """Serialize **exp** into a s-expression.

    >>> from bridgedb.tries import toSexp
    >>> toSexp([1, 2, 3])
    '(1 2 3)'
    >>> toSexp('(1 2 3)')
    '(1 2 3)'

    :type exp: str or list or tuple
    :param exp: The expression to convert to an s-expression.
    :raises SexpressionError: if **exp** cannot be parsed into an
        s-expression.
    :rtype: str
    :returns: The **exp**, as an s-expression.
    """
    if isSexp(exp):
        return exp
    elif isinstance(exp, (list, tuple)):
        return sexp.dumps(exp)
    else:
        raise SexpressionError(
            ("Cannot serialize %r as an s-expression: "
             "Expected list or tuple; got %s.") % (exp, type(exp)))

def tooCloseToTrunk(key, node):
    """If the number of matching elements in the **key** is
    greater-than-or-equal-to the **node** key, then we need to move to a
    branch farther from the trunk of the tree (to accomodate for all the
    matches and thereby base our new branch from the outermost branch
    possible).

    :rtype: bool
    :returns: ``True`` if the **key** belongs in a more outward branch than
        **node**.  ``False`` otherwise.
    """
    return bool(len(node.key) <= node.countMatching(key) < len(key))


class AdaptiveMetricTreeNode(object):
    """A node in an :class:`AdaptiveMetricTree`.

    :type branches: list
    :ivar branches: A list of all other
        :class:`nodes <bridgdb.tries.AdaptiveMetricTreeNode` which stem from
        this node.
    """

    def __init__(self, key=[], item=None):
        """Create a new node for an :class:`AdaptiveMetricTree`.

        :param key: See :meth:`key` for documentation regarding acceptable
            types and formats for the **key**.
        :param item: The object to store at this
            :class:`node <bridgedb.tries.AdaptiveMetricTreeNode` in the
            :class:`tree <bridgedb.tries.AdaptiveMetricTree`.
        """
        self.branches = []
        self.key = key
        self.item = item

    def __cmp__(self, other):
        """node.__cmp__(other) ←→ cmp(node, other)"""
        return self._sortByKeys(self, other)

    def __str__(self):
        """Get this :class:`node's <bridgedb.tries.AdaptiveMetricTreeNode>`
        :meth:`key`, as a s-expression.
        """
        return self._key

    @staticmethod
    def _sortByKeys(node, other):
        """Comparison function for :class:`AdaptiveMetricTreeNode` that orders
        nodes lexographically by their :meth:`key`s.

        :rtype: int
        :returns: Negative if node<other, zero if node node==other, positive if
            node>other.
        """
        x = toSexp(node.key)
        y = toSexp(other.key)

        if x < y:
            return -1
        elif x == y:
            return 0
        elif x > y:
            return 1
        
    @property
    def depth(self):
        """Determine the depth of this
        :class:`node <bridgedb.tries.AdaptiveMetricTreeNode>` in its
        :class:`tree <bridgedb.tries.AdaptiveMetricTree>`.
        """
        return len(self.key)

    @property
    def isLeaf(self):
        """Determine if this
        :class:`node <bridgedb.tries.AdaptiveMetricTreeNode>` is a leaf node
        (meaning that the tree has no further branches stemming out from this
        node).

        :rtype: bool
        :returns: ``True`` if this node is a leaf node; ``False`` otherwise.
        """
        return not bool(len(self.branches))

    @property
    def isTrunk(self):
        """Determine if this
        :class:`node <bridgedb.tries.AdaptiveMetricTreeNode>` is at the trunk of
        the tree (meaning that all other nodes in the tree branch out from this
        one).

        :rtype: bool
        :returns: ``True`` if this node is the trunk node; ``False`` otherwise.
        """
        return not bool(fromSexp(self.key))

    @property
    def key(self):
        """The unique key for this node.

        The :class:`node <bridgedb.tries.AdaptiveMetricTreeNode`'s key is
        internally stored as an s-expression representing the level-order
        indices required to find this ``node`` within its
        :class:`tree <bridgedb.tries.AdaptiveMetricTree>`.  For example, given
        the following tree structure::

                           +---+
                           | 1 |
                           +-+-+
                             |
                    +-----+--+--+-----+
                    |     |     |     |
                  +-+-+ +-+-+ +-+-+ +-+-+
                  | 2 | | 3 | | 4 | | 5 |
                  +-+-+ +-+-+ +---+ +-+-+
                    |     |           |
              +-----+     |           +-----+-----+
              |     |     |           |     |     |
            +-+-+ +-+-+ +-+-+       +-+-+ +-+-+ +-+-+
            | 6 | | 7 | | 8 |       | 9 | | 10| | 11|
            +-+-+ +---+ +-+-+       +-+-+ +---+ +---+
              |           |           |
              |        +--+--+     +--+--+-----+-----+
              |        |     |     |     |     |     |
            +-+-+    +-+-+ +-+-+ +-+-+ +-+-+ +-+-+ +-+-+
            | 12|    | 13| | 14| | 15| | 16| | 17| | 18|
            +---+    +---+ +---+ +---+ +---+ +---+ +---+

        The key for the node labelled ``17`` would be stored internally as the
        s-expression ``"(4 1 3)"``, meaning that, starting from ``1`` (the
        root of the tree), one should take the fourth branch at the first
        level, the first branch at second level, and then, finally, the third
        branch at the third level to arrive at node ``17``.  However, that
        s-expression representation is only used internally, in order to
        guarantee both the marshalling and the uniqueness of node keys.

        .. warn: When we say "indices" here, specifically, we mean using
            1-index notation (that is, start counting from ``1``, and *not*
            from ``0``).  Beware of miscounting the fence posts.

        Because Python programmer can't reasonably be expected to have
        familiarity with Lisp s-expressions, the keys returned from this
        method are instead deserialised from their internal s-expression
        format to flat Python lists.  For example, if this
        :class:`node <bridgedb.tries.AdaptiveMetricTreeNode>` were node ``17``
        from the above tree structure, then calling this method would return::

            [4, 1, 3]

        :rtype: list
        :returns: A list representation of the s-expression which represents
            the level-order branch indices required to locate this node from
            the :data:`~bridgedb.tries.AdaptiveMetricTree.trunk` of the tree.
        """
        return fromSexp(self._key)

    @key.setter
    def key(self, key):
        """Set this node's key.

        :type key: str or list or tuple
        :param key: The level-order branch indices required to locate this
            node from the :data:`~bridgedb.tries.AdaptiveMetricTree.trunk` of
            the tree.  If given as a list, it should be in the form::

                [4, 1, 3]

            And also a tuple, it is quite straightforward::

                (4, 1, 3)

            However, if given as a string, it must be a valid, flat
            s-expression, like so::

                "(4 1 3)"
        """
        self._key = toSexp(key)

    def countMatching(self, other):
        """Count how many elements in the s-expressions for our :data:`key` and
        the **other** key are matching.

        :type other: str or list
        :param list other: Either a flat list — which should be serialisable as
            an s-expression::

                [1, 2, 1, 1]

            or its equivalent valid s-expression string::

                "(1 2 1 1)"

        >>> from bridgedb.tries import AdaptiveMetricTreeNode
        >>> n1 = AdaptiveMetricTreeNode()
        >>> n1.key = [1, 2, 1, 1]
        >>> # With the other keys given as Python lists:
        >>> assert n1.countMatching([1, 2, 1, 1]) == 4
        >>> assert n1.countMatching([1, 2, 3, 1]) == 2
        >>> assert n1.countMatching([1, 2, 1, 4]) == 3
        >>> assert n1.countMatching([5, 4, 3, 2, 1]) == 0
        >>> assert n1.countMatching([2, 2]) == 0
        >>> # With the other keys given as s-expressions:
        >>> assert n1.countMatching("(1 2 1 1)") == 4
        >>> assert n1.countMatching("(1 2 3 1)") == 2
        >>> assert n1.countMatching("(1 2 1 4)") == 3
        >>> assert n1.countMatching("(5 4 3 2 1)") == 0
        >>> assert n1.countMatching("(2 2)") == 0

        :rtype: int
        :returns: The number of matching elements in our :data:`key` and the
            **other** key.
        """
        key = fromSexp(self.key)
        other = fromSexp(other)
        matching = 0

        while matching < len(key) and matching < len(other):
            if key[matching] != other[matching]:
                break
            matching += 1
    
        return matching

    def items(self):
        """Get a mapping of ``node.key`` to ``node.item``, for all nodes in
        this node's :data:`branches`.

        :rtype: list
        :returns: A list of 2-tuples in the form ``(node.key, node.item)``.
        """
        return [(node.key, node.item) for node in self.branches]

    def keys(self):
        """Get the ``node.key`` for each node in this node's :data:`branches`.

        :rtype: list
        """
        return [node.key for node in self.branches]

    def sort(self):
        """:meth:`Sort <bridgedb.tries.AdaptiveMetricTrie._sortByKeys>` this
        node's branches (in place).
        """
        self.branches.sort(cmp=self._sortByKeys)

    def values(self):
        """Get the ``node.item`` for each node in this node's :data:`branches`.

        :rtype: list
        """
        return [node.item for node in self.branches]


class AdaptiveMetricTree(object):
    """An :class:`Adaptive Metric Tree <bridgedb.tries.AdaptiveMetricTree>` is
    a novelle type of non-complete, non-perfect, non-balanced `K-ary Tree`_
    with some vector/metric properties.  Of the more well-known tree data
    structures, those with closest similarity are the `Metric Tree`_ and the
    `Adaptive Radix Tree`_.

    An Adaptive Metric Tree has the following properties:

    .. glossary::
       :sorted:

       Adaptive
          There may be any number of
          :class:`nodes <bridgedb.tries.AdaptiveMetricTreeNode>` at any given
          position in the tree.  Thus, from the trunk of the tree, there might
          be five branches (a.k.a. nodes) stemming outwards, and from one of
          those there might be zero, or one, or two, or *k*, branches.  A
          *trunk* node is any node that has no parent nodes, and *leaf* nodes
          are those which have no children.

       Non-balanced
          The tree does not attempt to move nodes in order to minimize tree
          depth, satisfy proportions or legarithmic constraints, or ensure
          that nodes always reside within the left-most or right-most
          available slot.

       Non-binary
          It is not required that non-leaf nodes have two children.  Non-leaf
          nodes can have as many — or as few — child nodes as you like.

       Non-compact
          Nodes may a single child node.  With some other types of trees, in
          particular, with `Radix Trees`_, a parent with an only child is
          merged with its only child; this is not the case here.  While this
          might seem space-inefficient (and it is), it is necessary property
          for storing :class:`hashrings <bridgedb.hashring.Hashring>` and
          their sub-hashrings within an Adaptive Metric Tree structure.

    One particular optimization which has been made to the
    :class:`Adaptive Metric Tree <bridgedb.tries.AdaptiveMetricTree>` is that
    its :class:`nodes <bridgedb.tries.AdaptiveMetricTreeNode>` have rather
    peculiar :meth:`keys <bridgedb.tries.AdaptiveMetricTreeNode.key>`: each
    key is stored as an `s-expression`_ representing the level-order indices
    required to locate the node.  (See the documentation for node
    :meth:`keys <bridgedb.tries.AdaptiveMetricTreeNode.key>` for a full
    description.)  This feature allows for efficient breadth-first search and
    other forms of tree traversal on a `possibly‑infinite tree`_ structure.


    Time Complexity in Big-O Notation
    ``````````````````````````````````
    In the following table, *w* is taken to be the width of the tree, *n* is
    the number of nodes in the tree, *d* is the depth of an element in the
    tree (which, in our case, happens to equal the length of the
    :meth:`keys <bridgedb.tries.AdaptiveMetricTreeNode.key>`):

    =================== ==================== ====================
    Operation           Average              Worst Case
    =================== ==================== ====================
    Space Requirements  O(n)                 O(n)
    :meth:`get`         O(d)                 O(d)
    :meth:`insert`      O(d²)                O(d³) ???
    :meth:`prune`       O(d)                 O(d)
    =================== ==================== ====================

    .. _k-ary tree: https://en.wikipedia.org/wiki/K-ary_tree
    .. _Metric Tree: https://en.wikipedia.org/wiki/Metric_tree
    .. _Adaptive Radix Tree: http://www-db.in.tum.de/~leis/papers/ART.pdf
        https://github.com/armon/libart
    .. _Radix Trees: https://en.wikipedia.org/wiki/Radix_tree
    .. _s-expression: https://en.wikipedia.org/wiki/S-expression
    .. _possibly‑infinite tree:
        https://en.wikipedia.org/wiki/Tree_traversal#Infinite_trees
    """

    def __init__(self):
        """Create a new :class:`AdaptiveMetricTree` with only a trunk node."""
        self.trunk = AdaptiveMetricTreeNode()

    def __contains__(self, key):
        """tree.__contains__(key) ←→ key in tree"""
        return fromSexp(key) in [n.key for n in self._breadthFirst().queue]

    def __iter__(self):
        """tree.__iter__() ←→ iter(tree)"""
        return iter(self._breadthFirst().queue)

    def __len__(self):
        """tree.__len__() ←→ len(tree)"""
        return len(self.trunk.branches)

    def __str__(self):
        """Returns a string representation of the radix tree.

        .. warn: Do not use on large trees!
        """
        def graph(lst, level, node):
            """Recursively generates a graph of this tree."""
            temp = " "

            if node.isTrunk:
                temp += "TRUNK "
            if node.isLeaf:
                temp += " LEAF "
            if not node.isLeaf and not node.isTrunk:
                temp += "      "

            for i in range(level):
                for _ in range(i):
                    temp += " " * 2
                temp += "|"

            temp += "-" * (level * 2)
            temp += "%s" % node.key
            temp += ": %s" % node.item

            lst.append(temp)

            for branch in node.branches:
                graph(lst, level + 1, branch)

        lst = []
        graph(lst, 0, self.trunk)
        return "\n".join(lst)

    def _breadthFirst(self, trunk=None):
        """Traverse the (possibly infinitely-branching) tree comprising all of
        this :class:`Hashring`'s subrings by conducting a
        `breadth-first search`_.

        .. info:: The algorithm used for the level-order traversal is
            non-recursive by using two :api:`Queue`s.

        :type trunk: :class:`AdaptiveMetricTreeNode`
        :param trunk: The node to begin traversal from.  If given, only the
             subtree from **trunk** downwards will be traversed.
        :rtype: :api:`Queue.Queue`
        :returns: A queue of all sub-hashrings in level-order.
        """
        if not trunk:
            trunk = self.trunk

        def expand(queue, node):
            for branch in node.branches:
                queue.put(branch)

        final = Queue()
        queue = Queue()
        final.put(trunk)
        expand(queue, trunk)

        while not queue.empty():
            node = queue.get()
            final.put(node)
            expand(queue, node)

        return final

    def get(self, key, node=None, default=None):
        """Get a class:`node <bridgedb.tries.AdaptiveMetricTreeNode>` by its
        **key**.

        :type key: str or list or tuple
        :param key: A :class:`AdaptiveMetricTreeNode`
            :meth:`key <bridgedb.tries.AdaptiveMetricTreeNode.key>`.
        :param default: The return value if the **key** can't be found.
        :rtype: :class:`AdaptiveMetricTreeNode`
        :returns: The node whose :data:`key` matches the requested **key**, if
            such a node exists.  Otherwise, returns the **default**.
        """
        if not node:
            node = self.trunk

        key = fromSexp(key)
        matches = node.countMatching(key)
        nonMatching = key[matches:]

        # If the key matches the node key, then we found an exact match.
        if key == node.key:
            return node
        # Otherwise, if it needs to be a branch, then recurse until we've
        # found a match:
        elif len(node.key) <= matches < len(key):
            for branch in node.branches:
                if branch.key[matches] == nonMatching[0]:
                    return self.get(key, branch)

    def insert(self, key, item, node=None):
        """Recursively insert a
        :class:`node <bridgedb.tries.AdaptiveMetricTreeNode` containing the
        **key** and the **item** into this
        :class:`tree <bridgedb.tries.AdaptiveMetricTree`.
        """
        if not node:
            node = self.trunk

        key = fromSexp(key)
        matches = node.countMatching(key)
        nonMatching = key[matches:]
        matching = key[:matches]

        logging.debug("Adding branch %s to %s with item %s" %
                      (toSexp(key), node, item))

        # Add placeholder parent nodes, all the way up the tree to the trunk,
        # but only if they don't already exist:
        if not matches:
            for i in range(len(key)):
                if not key[:i] in self:
                    self.insert(key[:i], None, self.trunk)

        # Next, if we're at the trunk of the tree, or otherwise no branches
        # seem to match, then we need to recursively find the correct node to
        # branch off of:
        if node.isTrunk or tooCloseToTrunk(key, node):
            # Try to add it to one of our branches first:
            for branch in node.branches:
                if branch.key[matches] == nonMatching[0]:
                    logging.debug("Recursing to possible parent %s" % node)
                    self.insert(key, item, branch)
                    break
            # Otherwise, if we couldn't add it to any of our branches, bisect
            # the node into the branches from the current position.
            else:
                n = AdaptiveMetricTreeNode()
                n.key = key
                n.item = item
                logging.debug("Branching from %s to add new node %s with item %r"
                              % (node, n, item))
                node.branches.append(n)
                node.sort()
        # If there is already an exact match, replace the item of that node:
        elif key == node.key:
            logging.debug(("Duplicate key %r for item %r... replacing with "
                           "new item %r.") % (key, node.item, item))
            node.item = item

    def items(self):
        """Get a mapping of ``node.key`` to ``node.item``, for all nodes in
        this tree.

        :rtype: list
        :returns: A list of 2-tuples in the form ``(node.key, node.item)``.
        """
        return [(node.key, node.item) for node in self.traverse().queue]

    def keys(self):
        """Get the ``node.key`` for each node in this tree.

        :rtype: list
        """
        return [node.key for node in self.traverse().queue]

    def nodes(self):
        """Get all nodes in this tree.

        :rtype: list
        """
        return [node for node in self.traverse().queue]

    def prune(self, key, parent=None):
        """Remove a :class:`node <bridgedb.tries.AdaptiveMetricTreeNode` (and
        all nodes branching from it) by **key** from this tree.

        :type key: str or list or tuple
        :param key: A :class:`AdaptiveMetricTreeNode`
            :meth:`key <bridgedb.tries.AdaptiveMetricTreeNode.key>`.
        :param parent: The suspected parent of the node we're trying to remove.
        :rtype: bool
        :returns: ``True`` if the pruning operation was successful; ``False``
            otherwise.
        """
        key = fromSexp(key)
        node = self.get(key)

        if not node:
            return False

        if not node.isTrunk:
            parent = self.get(key[:-1])
            for branch in parent.branches:
                if branch.key == node.key:
                    parent.branches.remove(branch)
                    break
        else:
            self.trunk.branches = []

        return True

    def subtree(self, key):
        """Get all :class:`nodes <bridgedb.tries.AdaptiveMetricTreeNode` whose
        :meth:`key <bridgedb.tries.AdaptiveMetricTreeNode.key>` equals, or
        is prefixed with, the the given **key**.

        :type key: str or list or tuple
        :param key: A :class:`AdaptiveMetricTreeNode`
            :meth:`key <bridgedb.tries.AdaptiveMetricTreeNode.key>`.
        :rtype: list
        :returns: A level-order list of all
            :class:`nodes <bridgedb.tries.AdaptiveMetricTreeNode` which stem
            from the node whose
            :meth:`key <bridgedb.tries.AdaptiveMetricTreeNode.key>` matches
            the given **key**.
        """
        key = fromSexp(key)
        node = self.get(key)
        subtree = []

        if node:
            subtree = list(self.traverse(node).queue)

        return subtree

    def traverse(self, trunk=None):
        """Traverse the (possibly infinitely-branching) tree comprising all of
        this :class:`Hashring`'s subrings by conducting a
        `breadth-first search`_.

        .. info:: The algorithm used for the level-order traversal is
            non-recursive by using two :api:`Queue`s.

        For example, given the following non-binary tree structure for this
        hashring's sub-hashrings, the returned list is ordered in the following
        manner::
                                    +---+                        
                                    | 1 |                        
                                    +-+-+                        
                                      |                          
                             ------+--+--+-----+                 
                             |     |     |     |                 
                           +-+-+ +-+-+ +-+-+ +-+-+               
                           | 2 | | 3 | | 4 | | 5 |               
                           +-+-+ +-+-+ +---+ +-+-+               
                             |     |           |                 
                       +-----+     |           +-----+-----+     
                       |     |     |           |     |     |     
                     +-+-+ +-+-+ +-+-+       +-+-+ +-+-+ +-+-+   
                     | 6 | | 7 | | 8 |       | 9 | | 10| | 11|   
                     +-+-+ +---+ +-+-+       +-+-+ +---+ +---+   
                       |           |           |                 
                       |        +--+--+     +--+--+-----+-----+  
                       |        |     |     |     |     |     |  
                     +-+-+    +-+-+ +-+-+ +-+-+ +-+-+ +-+-+ +-+-+
                     | 12|    | 13| | 14| | 15| | 16| | 17| | 18|
                     +---+    +---+ +---+ +---+ +---+ +---+ +---+

        .. breadth-first search: https://en.wikipedia.org/wiki/Breadth-first_search

        :type trunk: :class:`AdaptiveMetricTreeNode`
        :param trunk: The node to begin traversal from.  If given, only the
             subtree from **trunk** downwards will be traversed.
        :rtype: :api:`Queue.Queue`
        :returns: A queue of all sub-hashrings in level-order.
        """
        return self._breadthFirst(trunk)

    def values(self):
        """Get the ``node.item`` for each node in this tree.

        :rtype: list
        """
        return [node.item for node in self.traverse().queue]

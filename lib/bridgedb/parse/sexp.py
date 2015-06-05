# -*- coding: utf-8 ; test-case-name: bridgedb.test.test_parse_sexp ; -*-
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

"""`S-expression`_ parsers.

.. _S-expression: https://en.wikipedia.org/wiki/S-expression
"""

from __future__ import print_function
from __future__ import unicode_literals

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

    >>> from bridgedb.tries import fromSexp
    >>> fromSexp([1, 2, 3])
    [1, 2, 3]
    >>> fromSexp('(1 2 3)')
    [1, 2, 3]
    >>> fromSexp([3, [1, [4, [1]]]])
    [3, [1, [4, [1]]]]
    >>> fromSexp(["a", "b", "c"])
    [u"a", u"b", u"c"]

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
    u'(1 2 3)'
    >>> toSexp('(1 2 3)')
    u'(1 2 3)'
    >>> toSexp([3, [1, [4, [1]]]])
    u'(3 (1 (4 (1))))'
    >>> toSexp(["a", "b", "c"])
    u'("a" "b" "c")'

    :type exp: str or list or tuple
    :param exp: The expression to convert to an s-expression.
    :raises SexpressionError: if **exp** cannot be parsed into an
        s-expression.
    :rtype: str
    :returns: The **exp**, as an s-expression.
    """
    if isSexp(exp):
        return type('')(exp)
    elif isinstance(exp, (list, tuple)):
        return sexp.dumps(exp)
    else:
        raise SexpressionError(
            ("Cannot serialize %r as an s-expression: "
             "Expected list or tuple; got %s.") % (exp, type(exp)))

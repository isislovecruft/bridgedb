# -*- coding: utf-8 ; test-case-name: bridgedb.test.test_interfaces ; -*-
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


"""All available `Zope`_ interfaces in BridgeDB.

.. _Zope: http://docs.zope.org/zope.interface/index.html
"""

from zope.interface import Interface
from zope.interface import Attribute
from zope.interface import implementer


class IName(Interface):
    """An interface specification for a named object."""

    name = Attribute("A string which identifies this object.")


@implementer(IName)
class Named(object):
    """A named object."""

    #: The character(s) used to join child :class:`Named` object's names with
    #: our name.
    separator = ' '

    def __init__(self):
        self._name = str()

    @property
    def name(self):
        """Get the name of this object.

        :rtype: str
        :returns: A string which identifies this object.
        """
        return self._name

    @name.setter
    def name(self, name):
        """Set a **name** for identifying this object.

        This is used to identify the object in log messages; the **name**
        doesn't necessarily need to be unique. Other :class:`Named` objects
        which are properties of a :class:`Named` object may inherit their
        parents' **name**s.

        >>> from bridgedb.distribute import Named
        >>> named = Named()
        >>> named.name = 'Excellent Super-Awesome Thing'
        >>> named.name
        'Excellent Super-Awesome Thing'

        :param str name: A name for this object.
        """
        self._name = name

        for attr in self.__dict__.values():
            if IName.providedBy(attr):
                attr.name = self.separator.join([name, attr.name])

# -*- coding: utf-8 ; test-case-name: bridgedb.test.test_distribute ; -*-
#_____________________________________________________________________________
#
# This file is part of BridgeDB, a Tor bridge distribution system.
#
# :authors: Isis Lovecruft 0xA3ADB67A2CDB8B35 <isis@torproject.org>
#           please also see AUTHORS file
# :copyright: (c) 2007-2014, The Tor Project, Inc.
#             (c) 2014, Isis Lovecruft
# :license: see LICENSE for licensing information
#_____________________________________________________________________________


"""Classes for creating bridge distribution systems."""

from zope import interface
from zope.interface import Attribute
from zope.interface import implements


class IDistribute(interface.Interface):
    """An interface specification for a system which distributes bridges."""

    name = Attribute(
        ("The name of this distributor. Used mostly for logging purposes, "
         "but in some cases it may also be used to created new HMAC keys "
         "for specific hashrings which this distributor possesses."))

    hashring = Attribute(
        ("An implementer of ``bridgedb.hashring.IHashring`` which stores all "
         "bridges that this Distributor is capable of distributing to its "
         "clients."))

    def __len__():
        """Get the number of bridges in this Distributor's ``hashring``."""

    def __str__():
        """Get a string representation of this Distributor's ``name``."""

    def __unicode__():
        """Get a unicode representation of this Distributor's ``name``."""

    def setDistributorName(name):
        """Set this Distributor's ``name`` attribute."""


class Distributor(object):
    """Distributes bridges to clients."""

    implements(IDistribute)

    def __init__(self):
        super(Distributor, self).__init__()
        self.name = None
        self.hashring = None

    def __len__(self):
        """Get the number of bridges in this ``Distributor``'s ``hashring``.

        :rtype: int
        :returns: The number of bridges currently stored in this
            ``Distributor``'s ``hashring`` (including all bridges stored in
            any of the ``hashring``'s subhashrings).
        """
        return int(len(self.hashring))

    def __str__(self):
        """Get a string representation of this ``Distributor``'s ``name``.

        :rtype: str
        :returns: This ``Distributor``'s ``name`` attribute.
        """
        if self.name:
            return str(self.name)
        return str()

    def __unicode__():
        """Get a unicode representation of this Distributor's ``name``.

        :rtype: unicode
        :returns: This ``Distributor``'s ``name`` attribute.
        """
        if self.name:
            return unicode(self.name)
        return unicode()

    def setDistributorName(self, name):
        """Set a **name** for identifying this distributor.

        This is used to identify the distributor in the logs; the **name**
        doesn't necessarily need to be unique. The hashrings created for this
        distributor will be named after this distributor's name in
        :meth:`propopulateRings`, and any sub hashrings of each of those
        hashrings will also carry that name.

        >>> from bridgedb.distribute import Distributor
        >>> dist = Distributor(Dist.uniformMap, 5, 'fake-hmac-key')
        >>> dist.setDistributorName('HTTPS Distributor')
        >>> dist.prepopulateRings()
        >>> hashrings = ipDist.splitter.filterRings
        >>> firstSubring = hashrings.items()[0][1][1]
        >>> assert firstSubring.name

        :param str name: A name for this distributor.
        """
        self.name = name

        try:
            self.hashring.setName(name)
        except AttributeError:
            logging.debug("Couldn't setName() for %s Distributor's hashring.")

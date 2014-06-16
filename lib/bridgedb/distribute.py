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

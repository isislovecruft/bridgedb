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

import logging

from zope import interface
from zope.interface import Attribute
from zope.interface import implements

from bridgedb import bridgerequest


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

    _answerParameters = Attribute(
        ("An instance of ``bridgedb.bridgerequest.AnswerParameters`` which "
         "describes necessary bridge attributes for responding to a client's "
         "request. For example, we might wish to guarantee that every answer "
         "to a request contains at least one bridge on port 443."))

    def __len__():
        """Get the number of bridges in this Distributor's ``hashring``."""

    def __str__():
        """Get a string representation of this Distributor's ``name``."""

    def __unicode__():
        """Get a unicode representation of this Distributor's ``name``."""

    def answerParameters():
        """A ``@property`` which allows this Distributor's
        ``answerParameters`` attribute to be have ``__get__``, ``__set__``,
        and ``__del__`` called on it.
        """

    def setDistributorName(name):
        """Set this Distributor's ``name`` attribute."""



class Distributor(object):
    """Distributes bridges to clients."""

    implements(IDistribute)

    #: An instance of :class:`bridgedb.bridgerequest.AnswerParameters` which
    #: describes necessary bridge attributes for responding to a client's
    #: request. For example, we might wish to guarantee that every answer to a
    #: request contains at least one bridge on port 443. This should be
    #: accessed through the :property:`answerParameters` property.
    _answerParameters = None

    def __init__(self, key=None, answerParameters=None):
        """Create a system for distributing bridges to clients.

        :type answerParameters: :class:`~bridgerequest.AnswerParameters`
        :param answerParameters: An instance of
            ``bridgedb.bridgerequest.AnswerParameters`` which describes
            necessary bridge attributes for responding to a client's
            request. For example, we might wish to guarantee that every answer
            to a request contains at least one bridge on port 443.
        """
        super(Distributor, self).__init__()
        self.name = None
        self.hashring = None
        self.key = key

        if not answerParameters:
            answerParameters = bridgerequest.AnswerParameters()
        self.answerParameters = answerParameters

    @property
    def answerParameters(self):
        """Get this Distributor's ``answerParameters``.

        .. info:: An ``AnswerParameters`` instance should describe some
            necessary conditions which must be met by all answers to client's
            bridge requests which are handed out. For example, we might wish
            to guarantee that an answer from this Distributor contains at
            least one bridge on port 443, or at least one bridge which has
            been marked with the ``Stable`` flag.

        :rtype: :class:`~bridgerequest.AnswerParameters`
        """
        return self._answerParameters

    @answerParameters.setter
    def answerParameters(self, answerParameters=None):
        """Set this Distributor's ``answerParameters`` attribute.

        :type answerParameters: :class:`~bridgerequest.AnswerParameters`
        :param answerParameters: An instance of
            ``bridgedb.bridgerequest.AnswerParameters`` which describes
            necessary bridge attributes for responding to a client's
            request. For example, we might wish to guarantee that every answer
            to a request contains at least one bridge on port 443.
        """
        if isinstance(answerParameters, bridgerequest.AnswerParameters):
            self._answerParameters = answerParameters

    @answerParameters.deleter
    def answerParameters(self):
        """Clear this Distributor's ``answerParameters`` attribute."""
        self._answerParameters = None

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

        :param str name: A name for this distributor.
        """
        self.name = name

        try:
            self.hashring.setName(name)
        except AttributeError:
            logging.debug("Couldn't setName() for %s Distributor's hashring.")

# -*- coding: utf-8 ; test-case-name: bridgedb.test.test_persistent -*-
#
# This file is part of BridgeDB, a Tor bridge distribution system.
#
# :authors: Isis Lovecruft 0xA3ADB67A2CDB8B35 <isis@torproject.org>
#           please also see AUTHORS file
# :copyright: (c) 2013 Isis Lovecruft
#             (c) 2007-2013, The Tor Project, Inc.
#             (c) 2007-2013, all entities within the AUTHORS file
# :license: 3-clause BSD, see included LICENSE for information

"""Module for functionality to persistently store state."""

import copy
import logging
import os.path

try:
    import cPickle as pickle
except (ImportError, NameError):  # pragma: no cover
    import pickle

from twisted.python.reflect import safe_repr
from twisted.spread import jelly

from bridgedb import Filters, Bridges, Dist
from bridgedb.configure import Conf
#from bridgedb.proxy import ProxySet

_state = None

#: Types and classes which are allowed to be jellied:
_security = jelly.SecurityOptions()
#_security.allowInstancesOf(ProxySet)
_security.allowModules(Filters, Bridges, Dist)


class MissingState(Exception):
    """Raised when the file or class storing global state is missing."""


def _getState():
    """Retrieve the global state instance.

    :rtype: :class:`~bridgedb.persistent.State`
    :returns: An unpickled de-sexp'ed state object, which may contain just
        about anything, but should contain things like options, loaded config
        settings, etc.
    """
    return _state

def _setState(state):
    """Set the global state.

    :type state: :class:`~bridgedb.persistent.State`
    :param state: The state instance to save.
    """
    global _state
    _state = state

def load(stateCls=None):
    """Given a :class:`State`, try to unpickle it's ``statefile``.

    :param string stateCls: An instance of :class:`~bridgedb.persistent.State`. If
        not given, try loading from ``_statefile`` if that file exists.
    :rtype: None or :class:`State`
    """
    statefile = None
    if stateCls and isinstance(stateCls, State):
        cls = stateCls
    else:
        cls = _getState()

    if not cls:
        raise MissingState("Could not find a state instance to load.")
    else:
        loaded = cls.load()
        return loaded


class State(jelly.Jellyable):
    """Pickled, jellied storage container for persistent state."""

    def __init__(self, config=None, **kwargs):
        """Create a persistent state storage mechanism.

        Serialisation of certain classes in BridgeDB doesn't work. Classes and
        modules which are known to be unjelliable/unpicklable so far are:

          - bridgedb.Dist
          - bridgedb.Bridges.BridgeHolder and all other ``splitter`` classes

        :property statefile: The filename to retrieve a pickled, jellied
            :class:`~bridgedb.persistent.State` instance from. (default:
            :attr:`bridgedb.persistent.State._statefile`)
        """
        self._statefile = os.path.abspath(str(__package__) + '.state')
        self.proxyList = None
        self.config = None
        self.key = None

        if 'STATEFILE' in kwargs:
            self.statefile = kwargs['STATEFILE']

        for key, value in kwargs.items():
            self.__dict__[key] = value

        if config is not None:
            for key, value in config.__dict__.items():
                self.__dict__[key] = value

        _setState(self)

    def _get_statefile(self):
        """Retrieve the filename of the global statefile.

        :rtype: string
        :returns: The filename of the statefile.
        """
        return self._statefile

    def _set_statefile(self, filename):
        """Set the global statefile.

        :param string statefile: The filename of the statefile.
        """
        filename = os.path.abspath(os.path.expanduser(filename))
        logging.debug("Setting statefile to '%s'" % filename)
        self._statefile = filename

        # Create the parent directory if it doesn't exist:
        dirname = os.path.dirname(filename)
        if not os.path.isdir(dirname):
            os.makedirs(dirname)

        # Create the statefile if it doesn't exist:
        if not os.path.exists(filename):
            open(filename, 'w').close()

    def _del_statefile(self):
        """Delete the file containing previously saved state."""
        try:
            with open(self._statefile, 'w') as fh:
                fh.close()
            os.unlink(self._statefile)
            self._statefile = None
        except (IOError, OSError) as error:  # pragma: no cover
            logging.error("There was an error deleting the statefile: '%s'"
                          % self._statefile)

    statefile = property(_get_statefile, _set_statefile, _del_statefile,
                         """Filename property of a persisent.State.""")

    def load(self, statefile=None):
        """Load a previously saved statefile.

        :raises MissingState: If there was any error loading the **statefile**.
        :rtype: :class:`State` or None
        :returns: The state, loaded from :attr:`State.STATEFILE`, or None if
            an error occurred.
        """
        if not statefile:
            if not self.statefile:
                raise MissingState("Could not find a state file to load.")
            statefile = self.statefile
        logging.debug("Retrieving state from: \t'%s'" % statefile)

        quo= fh = None
        err = ''

        try:
            if isinstance(statefile, basestring):
                fh = open(statefile, 'r')
            elif not statefile.closed:
                fh = statefile
        except (IOError, OSError) as error:  # pragma: no cover
            err += "There was an error reading statefile "
            err += "'{0}':\n{1}".format(statefile, error)
        except (AttributeError, TypeError) as error:
            err += "Failed statefile.open() and statefile.closed:"
            err += "\n\t{0}\nstatefile type = '{1}'".format(
                error.message, type(statefile))
        else:
            try:
                status = pickle.load(fh)
            except EOFError:
                err += "The statefile %s was empty." % fh.name
            else:
                quo = jelly.unjelly(status)
                if fh is not None:
                    fh.close()
                if quo:
                    return quo

        if err:
            raise MissingState(err)

    def save(self, statefile=None):
        """Save state as a pickled jelly to a file on disk."""
        if not statefile:
            if not self._statefile:
                raise MissingState("Could not find a state file to load.")
            statefile = self._statefile
        logging.debug("Saving state to: \t'%s'" % statefile)

        fh = None
        try:
            fh = open(statefile, 'w')
        except (IOError, OSError) as error:  # pragma: no cover
            logging.warn("Error writing state file to '%s': %s"
                         % (statefile, error))
        else:
            try:
                pickle.dump(jelly.jelly(self), fh)
            except AttributeError as error:
                logging.debug("Tried jellying an unjelliable object: %s"
                              % error.message)

        if fh is not None:
            fh.flush()
            fh.close()

    def useChangedSettings(self, config):
        """Take a new config, compare it to the last one, and update settings.

        Given a ``config`` object created from the configuration file, compare
        it to the last :class:`~bridgedb.configure.Conf` that was stored, and apply
        any settings which were changed to be attributes of the :class:`State`
        instance.
        """
        updated = []
        new = []

        for key, value in config.__dict__.items():
            try:
                # If state.config doesn't have the same value as the new
                # config, then update the state setting.
                #
                # Be sure, when updating settings while parsing the config
                # file, to assign the new settings as attributes of the
                # :class:`bridgedb.configure.Conf` instance.
                if value != self.config.__dict__[key]:
                    setattr(self, key, value)
                    updated.append(key)
                    logging.debug("Updated %s setting: %r → %r" %
                                  (safe_repr(key),
                                   self.config.__dict__[key],
                                   safe_repr(value)))
            except (KeyError, AttributeError):
                setattr(self, key, value)
                new.append(key)
                logging.debug("New setting: %s = %r" %
                              (safe_repr(key),
                               safe_repr(value)))

        logging.info("Updated setting(s): %s" % ' '.join([x for x in updated]))
        logging.info("New setting(s): %s" % ' '.join([x for x in new]))
        logging.debug(
            "Saving newer config as `state.config` for later comparison")
        self.config = config

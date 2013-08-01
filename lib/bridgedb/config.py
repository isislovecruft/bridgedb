# -*- coding: utf-8 -*-
#
# :authors: see AUTHORS file
# :copyright: (c) 2007-2013, The Tor Project, Inc.
# :license: see LICENSE for licensing information

"""config.py - configuration utilities for BridgeDB"""

from types import ModuleType

import doctest
import imp
import sys
import os

try:
    from bridgedb import log as logging
## remove this after feature/9199-improved-logging* is merged:
except ImportError:
    import logging


#: Testing-specific configuration settings, used for debugging. To apply these
#: on top of the default settings in bridgedb.conf, run with:
#: ``$ python ./lib/TorBridgeDB.py -t``.
TESTING_CONFIG = { 'RUN_IN_DIR': "./run",
                   'LOGFILE': "test.log",
                   'LOGDIR': "log",
                   'LOGLEVEL': "DEBUG",
                   'HTTP_UNENCRYPTED_BIND_IP': "127.0.0.1",
                   'HTTP_UNENCRYPTED_PORT': 6788,
                   'EXTRA_INFO_FILE': None,
                 }

class Conf(dict):
    """A configuration object. Holds unvalidated attributes."""

    def __init__(self, *args, **kwargs):
        """Intialize a configuration object.

        Essentially, this is a slightly modified Python dict, which can take
        keyword arguments for setting names and value, or variables read from
        a .py file.

        >>> config_settings = {'quasar': 'past', 'pulsar': 'present'}
        >>> config = Conf(**config_settings)

        Or, to read a config file, do:

        >>> config_file = './bridgedb.conf'
        >>> config = Conf(file=config_file)

        Also, nothing's stopping you from doing *both*:

        >>> config_settings = {'quasar': 'past',
        ...                    'pulsar': 'present',
        ...                    'file': './bridgedb.conf'}
        >>> config = Conf(**config_settings)

        which would apply all the key=value pairs to ``Conf.__dict__``, and
        then apply all the setting from ``Conf.__dict__['file']`` (which
        obviously would override any overlapping settings, keeping the ones
        from the file).

        After being loaded into the Conf object, attributes may be access via
        the usual dict methods, or as an attribute of the :class:`Conf`
        object (they are functionally equivalent):

        >>> settings = {'eris': 'apple', 'morningstar': 'skull'}
        >>> conf = config.Conf(**settings)
        >>> conf.morningstar
        'skull'
        >>> conf['morningstar']
        'skull'
        >>> conf.get('morningstar')
        'skull'
        >>> assert conf.eris == conf['eris']

        The most recently loaded configuration file is stored as
        :attr:`Conf.file` and can be reloaded with :meth:`Conf.reload`.
        """
        ## If called with ``file='./somefile'`` then load global variables
        ## from that file if it exists and is readable
        if kwargs and 'file' in kwargs:
            self.load(kwargs['file'])
        self.update(*args, **kwargs)

    def __getattr__(self, item):
        """Retrieve a setting called by attribute name.

        Conf.__getattribute__('item') <==> Conf.item

        :param str item: The variable name of the setting to retrieve.
        :returns: The value of the configuration setting if it exists, else
            None.
        """
        try: return self[item]
        except KeyError: return None

    def __setattr__(self, item, setting=None):
        """Set a configuration item by attribute name.

        Conf.__setattr__('item', setting)  <==>  Conf.item = setting

        >>> settings = {'file': '../bridgedb.conf',
        ...             'ASSIGNMENTS_FILE': 'buckets.log'}
        >>> conf = config.Conf(**settings)
        >>> conf.ASSIGNMENTS_FILE
        'buckets.log'
        >>> conf.ASSIGNMENTS_FILE = 'bridge-buckets.log'
        >>> conf.ASSIGNMENTS_FILE
        'bridge-buckets.log'

        :param item: The key/attribute from ``Conf.__dict__`` to modify.
        :param setting: The value to set ``Conf.item`` to.
        """
        self[item] = setting

    def __delattr__(self, item):
        """Remove a configuration setting, by attribute name."""
        try: del self[item]
        except KeyError as err: raise AttributeError(err)

    def __getstate__(self):
        """Get the current configuration state. Used for pickling."""
        return dict(self)

    def __setstate__(self, state):
        """Restore config state after unpickling a Conf object."""
        for item, default in state.items():
            self[item] = default

    def load(self, config_file):
        """Load config settings from a file or from an instance of :class:`Conf`.

        :param str config_file: The filename of the config file to
            read. Tildes will be expanded, and if the file's path isn't
            absolute, it is assumed to be in the current working directory.
        """
        if isinstance(config_file, str):
            if config_file.find('~'):
                self.file = os.path.expanduser(config_file)
            else:
                self.file = os.path.abspath(config_file)
        elif isinstance(config_file, (ModuleType, self.__class__)):
            ## Because the config file is not technically a "flat file", but
            ## instead is a file containing Python global variables, when it
            ## is loaded it is treated as a Python source file. This means it
            ## gets compiled, and Python's idiot interpreter adds a 'c' to the
            ## extension of any compiled Python binary. We don't want to load
            ## binary files.
            if ((hasattr(config_file, 'file') is not None) and
                not config_file.file.endswith('c')):
                    self.file = config_file.file

        logging.info("Loading config file: %s" % config_file)
        try:
            if isinstance(config_file, ModuleType):
                new = config_file.__dict__
            if hasattr(self, 'file') is not None:
                new = imp.load_source('config', self.file).__dict__
        except (OSError, IOError) as err:
            logging.err(err, "Loading config file '%s' failed!" % config_file)
        else: self.update(**new)

    def reload(self):
        """Reload settings from the most recently used configuration file.

        NOTE: This method calls :meth:`bridgedb.config.Conf.clear` before
        reapplying the configuration settings from the file. This means that
        any extra settings specified via ``*args`` and ``**kwargs`` to either
        :meth:`bridgedb.config.Conf.update` or
        :meth:`bridgedb.config.Conf.__init__` are erased, and *only* the
        settings as stored in the most recently used configuration file,
        ``Conf.file``, are reloaded.
        """
        try:
            logging.info("Reloading previous config file %s" % self.file)
            self.clear()
            self.load(self.file)
        except AttributeError: logging.warn("No previously loaded config file!")

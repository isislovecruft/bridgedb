# -*- coding: utf-8 ; test-case-name: bridgedb.test.test_util -*-
#
# This file is part of BridgeDB, a Tor bridge distribution system.
#
# :authors: Isis Lovecruft 0xA3ADB67A2CDB8B35 <isis@torproject.org>
#           Matthew Finkel 0x017DD169EA793BE2 <sysrqb@torproject.org>
# :copyright: (c) 2013-2015, Isis Lovecruft
#             (c) 2013-2015, Matthew Finkel
#             (c) 2007-2015, The Tor Project, Inc.
# :license: 3-Clause BSD, see LICENSE for licensing information

"""Common utilities for BridgeDB."""

from functools import partial

import abc
import logging
import logging.config
import logging.handlers
import os

from twisted.python import components


class CacheError(Exception):
    """Raised when there is an error inserting or removing an item from a
    :class:`Cache`.
    """


def _getLogHandlers(logToFile=True, logToStderr=True):
    """Get the appropriate list of log handlers.

    :param bool logToFile: If ``True``, add a logfile handler.
    :param bool logToStderr: If ``True``, add a stream handler to stderr.
    :rtype: list
    :returns: A list containing the appropriate log handler names from the
        :class:`logging.config.dictConfigClass`.
    """
    logHandlers = []
    if logToFile:
        logHandlers.append('rotating')
    if logToStderr:
        logHandlers.append('console')
    return logHandlers

def _getRotatingFileHandler(filename, mode='a', maxBytes=1000000, backupCount=0,
                            encoding='utf-8', uid=None, gid=None):
    """Get a :class:`logging.RotatingFileHandler` with a logfile which is
    readable+writable only by the given **uid** and **gid**.

    :param str filename: The full path to the log file.
    :param str mode: The mode to open **filename** with. (default: ``'a'``)
    :param int maxBytes: Rotate logfiles after they have grown to this size in
        bytes.
    :param int backupCount: The number of logfiles to keep in rotation.
    :param str encoding: The encoding for the logfile.
    :param int uid: The owner UID to set on the logfile.
    :param int gid: The GID to set on the logfile.
    :rtype: :class:`logging.handlers.RotatingFileHandler`
    :returns: A logfile handler which will rotate files and chown/chmod newly
        created files.
    """
    # Default to the current process owner's uid and gid:
    uid = os.getuid() if not uid else uid
    gid = os.getgid() if not gid else gid

    if not os.path.exists(filename):
        open(filename, 'a').close()
    os.chown(filename, uid, gid)
    try:
        os.chmod(filename, os.ST_WRITE | os.ST_APPEND)
    except AttributeError:  # pragma: no cover
        logging.error("""
    XXX FIXME: Travis chokes on `os.ST_WRITE` saying that the module doesn't
               have that attribute, for some reason:
    https://travis-ci.org/isislovecruft/bridgedb/builds/24145963#L1601""")
        os.chmod(filename, 384)

    fileHandler = partial(logging.handlers.RotatingFileHandler,
                          filename,
                          mode,
                          maxBytes=maxBytes,
                          backupCount=backupCount,
                          encoding=encoding)
    return fileHandler

def configureLogging(cfg):
    """Set up Python's logging subsystem based on the configuration.

    :type cfg: :class:`~bridgedb.persistent.Conf`
    :param cfg: The current configuration, including any in-memory settings.
    """
    from bridgedb import safelog

    # Turn on safe logging by default:
    safelogging = getattr(cfg, 'SAFELOGGING', True)
    safelog.setSafeLogging(safelogging)

    level = getattr(cfg, 'LOGLEVEL', 'WARNING')
    logLevel = getattr(logging, level, 0)
    logStderr = getattr(cfg, 'LOG_TO_STDERR', False)
    logfileName = getattr(cfg, 'LOGFILE', "bridgedb.log")
    logfileCount = getattr(cfg, 'LOGFILE_COUNT', 3) - 1
    logfileRotateSize = getattr(cfg, 'LOGFILE_ROTATE_SIZE', 10000000)
    logThreads = getattr(cfg, 'LOG_THREADS', False)
    logTrace = getattr(cfg, 'LOG_TRACE', False)
    logTimeFormat = getattr(cfg, 'LOG_TIME_FORMAT', "%H:%M:%S")

    logFilters = []
    if safelogging:
        logFilters = ['safelogEmail', 'safelogIPv4', 'safelogIPv6']

    logConfig = {
        'version': 1,
        'filters': {
            'safelogEmail': {'()': safelog.SafelogEmailFilter},
            'safelogIPv4': {'()': safelog.SafelogIPv4Filter},
            'safelogIPv6': {'()': safelog.SafelogIPv6Filter},
        },
        'formatters': {
            'default': {'()': JustifiedLogFormatter,
                        # These values below are kwargs passed to
                        # :class:`JustifiedFormatter`:
                        'logThreads': logThreads,
                        'logTrace': logTrace,
                        'datefmt': logTimeFormat},
        },
        'handlers': {
            'console': {'class': 'logging.StreamHandler',
                        'level': logLevel,
                        'formatter': 'default',
                        'filters': logFilters},
            'rotating': {'()': _getRotatingFileHandler(logfileName, 'a',
                                                       logfileRotateSize,
                                                       logfileCount),
                         'level': logLevel,
                         'formatter': 'default',
                         'filters': logFilters},
        },
        'root': {
            'handlers': _getLogHandlers(logfileName, logStderr),
            'level': logLevel,
        },
    }

    logging.config.dictConfig(logConfig)

    logging.info("Logger Started.")
    logging.info("Level: %s", logLevel)
    logging.info("Safe Logging: %sabled" % ("En" if safelogging else "Dis"))

def levenshteinDistance(s1, s2, len1=None, len2=None,
                        offset1=0, offset2=0, memo=None):
    """Compute the Levenstein Distance between two strings.

    The `Levenshtein String Distance Algorithm
    <https://en.wikipedia.org/wiki/Levenshtein_distance>` efficiently computes
    the number of characters which must be changed in **s1** to make it
    identical to **s2**.

    >>> levenshteinDistance('cat', 'cat')
    0
    >>> levenshteinDistance('cat', 'hat')
    1
    >>> levenshteinDistance('arma', 'armadillo')
    5

    :param str s1: The string which should be changed.
    :param str s2: The string which **stringOne** should be compared to.
    """
    len1 = len(s1) if len1 is None else len1
    len2 = len(s2) if len2 is None else len2
    memo = {} if memo is None else memo

    key = ','.join([str(offset1), str(len1), str(offset2), str(len2)])
    if memo.get(key) is not None: return memo[key]

    if len1 == 0: return len2
    elif len2 == 0: return len1

    cost = 0 if (s1[offset1] == s2[offset2]) else 1
    distance = min(
        levenshteinDistance(s1, s2, len1-1, len2,   offset1+1, offset2,   memo) + 1,
        levenshteinDistance(s1, s2, len1,   len2-1, offset1,   offset2+1, memo) + 1,
        levenshteinDistance(s1, s2, len1-1, len2-1, offset1+1, offset2+1, memo) + cost,
    )
    memo[key] = distance
    return distance

def registerAdapter(adapter, adapted, interface):
    """Register a Zope interface adapter for global use.

    See :api:`twisted.python.components.registerAdapter` and the Twisted
    Matrix Labs `howto documentation for components`_.

    .. howto documentation for components:
        https://twistedmatrix.com/documents/current/core/howto/components.html
    """
    try:
        components.registerAdapter(adapter, adapted, interface)
    except ValueError:  # An adapter class was already registered
        pass


class JustifiedLogFormatter(logging.Formatter):
    """A logging formatter which pretty prints thread and calling function
    information, in addition to the normal timestamp, log level, and log
    message.

    :ivar int width: The width of the column for the calling function
        information, if the latter is to be included.
    """
    width = 30

    def __init__(self, logThreads=False, logTrace=False,
                 datefmt="%H:%M:%s"):
        """If **logTrace** is ``True``, the line number, module name, and
        function name where the logger was called will be included in the
        message, and the width of this information will always equal ``width``.

        :param bool logThreads: If ``True``, include the current thread name
            and ID in formatted log messages.
        :param bool logTrace: If ``True``, include information on the calling
            function in formatted log messages.
        """
        super(JustifiedLogFormatter, self).__init__(datefmt=datefmt)
        self.logThreads = logThreads
        self.logTrace = logTrace

        _fmt = ["%(asctime)s %(levelname)-7.7s"]
        if self.logThreads:
            _fmt.append("[%(threadName)s id:%(thread)d]")
        _fmt.append("%(callingFunc)s")
        _fmt.append("%(message)s")

        self._fmt = " ".join(_fmt)

    def _formatCallingFuncName(self, record):
        """Format the combined module name and function name of the place where
        the log message/record was recorded, so that the formatted string is
        left-justified and not longer than the :cvar:`width`.

        :type record: :class:`logging.LogRecord`
        :param record: A record of an event created by calling a logger.
        :returns: The :class:`logging.LogRecord` with its ``message``
            attribute rewritten to contain the module and function name,
            truncated to ``width``, or padded on the right with spaces as is
            necessary.
        """
        callingFunc = ""
        if self.logTrace:
            # The '.' character between the module name and function name
            # would otherwise be interpreted as a format string specifier, so
            # we must specify ``chr(46)``:
            lineno = "L%s:" % record.lineno
            caller = "%s%-s%s" % (lineno.rjust(6), record.module, chr(46))
            maxFuncNameWidth = self.width - 2 - len(caller)
            funcName = record.funcName
            if len(funcName) > maxFuncNameWidth:
                funcName = record.funcName[:maxFuncNameWidth]
            caller += "%s()" % (funcName)
            callingFunc = caller.ljust(self.width)

        record.callingFunc = callingFunc
        return record

    def format(self, record):
        """Reformat this log **record** to neatly print thread and function
        traces, if configured to do so.

        :type record: :class:`logging.LogRecord`
        :param record: A record of an event created by calling a logger.
        """
        record = self._formatCallingFuncName(record)
        return super(JustifiedLogFormatter, self).format(record)


class DoublyLinked(object):
    """An item in a doubly-linked list."""

    def __init__(self):
        self.next = None
        self.prev = None

        self.key = None
        self.value = None

    @property
    def empty(self):
        """Determine if there is an item in this slot."""
        return not (bool(self.key) or bool(self.value))

    def clear(self):
        """Clear this item's :data:`key` and :data:`value`."""
        self.key = None
        self.value = None


class Cache(object):
    """A cache for objects which automatically trims itself to the specified
    cache size.
    """
    def __init__(self, size, callback=None):
        """Create a new :class:`Cache`

        :param int size: The number of sub-hashrings (usually particular to a
            certain :class:`Constraint` or set of ``Constraint``s) to keep
            cached. Later, if a constrained sub-hashring is needed, and it is
            found within the cache, the cached sub-hashring will be used
            rather than generating a new one.
        :type callback: callable
        :param callback: If set, this will be called with a 2-tuple of
            (item.key, item.value), whenever an item is added or removed from
            this cache.
        """
        self._cache = {}
        self.callback = callback

        self._mru = DoublyLinked()
        self._mru.next = self._mru
        self._mru.prev = self._mru

        self._size = 1
        self.size = size

    @property
    def lru(self):
        """Get the least recently used (LRU) item in this cache."""
        return self._mru.prev

    @property
    def mru(self):
        """Get the most recently used (MRU) item in this cache."""
        return self._mru

    @property
    def size(self):
        """Get the current size of this :class:`Cache`.

        The ``Cache`` will store up to this many items before :property:`lru`
        items are deleted.

        :rtype: int
        :returns: The current size of this cache.
        """
        return self._size

    @size.setter
    def size(self, size):
        """Set the size of this :class:`Cache`.

        :param int size: The maximum number of items to keep in this ``Cache``.
        :raises CacheError: If resizing the ``Cache`` failed.
        :raises TypeError: If **size** is anything other than an ``int``.
        """
        if isinstance(size, int) and size >= 0:
            if size > self._size:
                self.grow(size - self._size)
            elif size < self._size:
                self.shrink(self._size - size)
            if not self._size == size:  # pragma: no cover
                raise CacheError(("Failure to update cache size to %d! "
                                  "Current size: %d") % (size, self._size))
        else:
            raise TypeError("Cache size must be an int (got %s)" % type(size))

    def __contains__(self, key):
        """Cache.__contains__(key) ←→ key in Cache"""
        return key in self._cache.keys()

    def __delitem__(self, key):
        """Cache.__delitem__(key) ←→ del Cache[key]

        .. warn:: This method updates the :class:`Cache` order.
        """
        item = self._cache[key]

        # Update this item so that it is now the :data:`head` of the internal
        # doubly-linked list, then shift the head to the item following it.
        self.mtf(item)
        self._mru = item.next

        item.next = None
        item.prev = None
        item.clear()

        del self._cache[key]

    def __getitem__(self, key):
        """Cache.__getitem__(key) ←→ Cache[key]

        .. warn:: This method updates the :class:`Cache` order.
        """
        item = self._cache[key]

        # Update this item so that it is now the :data:`head` of the internal
        # doubly-linked list (since it is the most recently used).
        self.mtf(item)
        self._mru = item

        return item.value

    def __iter__(self):
        """Cache.__iter__() ←→ iter(Cache)"""
        return iter([item.key for item in self.all()])

    def __len__(self):
        """Cache.__len__() ←→ len(Cache)"""
        return len(self._cache)

    def __setitem__(self, key, value):
        """Cache.__setitem__(key, value) ←→ Cache[key] = value

        If any value is stored under **key** in the cache already, then it
        will be updated with the new value.  Otherwise, a slot for the new
        item will be chosen.  There are two cases:

          * If the cache is full, the least recently used (LRU) item will be
            pushed out of the cache.

          * If the cache is not full, we want to choose a slot that is empty.
            Because of the way the internal doubly-linked list is managed, the
            empty slots are always grouped together at the tail end of the
            list.  Since the list is circular, the LRU item always directly
            preceeds the :data:`head` item.

        Thus, regardless of whether the cache is full or not, our conditions
        are satisfied by choosing the slot directly preceeding the
        :data:`head` item.
        """
        if key in self._cache:
            item = self._cache[key]
            item.value = value

            self.mtf(item)
            self._mru = item
            return

        item = self._mru.prev

        # If the slot already contains something, then remove the old item
        # from the cache.
        if not item.empty:
            if self.callback:
                self.callback(item.key, item.value)
            del self._cache[item.key]

        item.key = key
        item.value = value
        self._cache[key] = item

        # We need to move the item to the head of the list. The item is at
        # the tail, so it directly preceeds the :data:`_head`.  Therefore,
        # the ordering is already correct, we just need to point the
        # :data:`_head` to the new item.
        self._mru = item

    def all(self):
        """All items stored in this :class:`Cache`.

        :rtype: iterator
        :returns: An iterator over the
            :class:`items <bridgedb.hashring.DoublyLinked>` stored in this
            ``Cache``, in order from the most recently used item to the least
            recently used item.
        """
        item = self._mru
        for _ in range(len(self)):
            yield item
            item = item.next

    def clear(self):
        """Remove all items stored in this :class:`Cache`."""
        [item.clear() for item in self.all()]
        self._cache.clear()

    def get(self, key, default=None):
        """Get an item from this :class:`Cache` by its **key**, and return
        the **default** value if we could not find the item.
        """
        try:
            return self[key]
        except KeyError:
            return default

    def grow(self, count):
        """Increase the size of this cache by insert **count** empty item slots
        at the tail of the internal doubly-linked list.
        """
        logging.debug("Growing cache size by %d..." % count)
        for _ in range(count):
            item = DoublyLinked()
            item.next = self._mru
            item.prev = self._mru.prev

            self._mru.prev.next = item
            self._mru.prev = item
            self._size += 1

    def items(self):
        """The keys and values of all items stored in this :class:`Cache`.

        :rtype: iterator
        :returns: An iterator over the (key, value) tuples for all items
            stored in this ``Cache``, in order from the most recently used
            item to the least recently used item.
        """
        return [(item.key, item.value) for item in self.all()]

    def keys(self):
        """The keys of all items stored in this :class:`Cache`.

        :rtype: iterator
        :returns: An iterator over the keys of the items stored in this
            ``Cache``, in order from the most recently used item to the least
            recently used item.
        """
        return [item.key for item in self.all()]

    def mtf(self, item):
        """Move the **item** to the front.

        Update the ordering of the internal doubly-linked list such that the
        **item** directly precedes the :data:`head` item.

        .. info:: Because of the order of operations, if **item** already
            directly precedes the :data:`head`, or if **item** is the
            :data:`head`, then the order of the internal doubly-linked list
            will be unchanged.

        .. warn:: This method updates the :class:`Cache` order.
        """
        item.prev.next = item.next
        item.next.prev = item.prev

        item.prev = self._mru.prev
        item.next = self._mru.prev.next

        item.next.prev = item
        item.prev.next = item

    def peek(self, key):
        """Retrieve an item in the cache without effecting the cache order."""
        return self._cache[key].value

    def shrink(self, count):
        """Decrease this cache's size by removing **count** items from the tail.

        .. warn:: This method updates the :class:`Cache` order.

        :param int count: The number of items to shrink this cache by.
        """
        logging.debug("Shrinking cache size by %d..." % count)
        for _ in range(count):
            item = self._mru.prev
            if not item.empty:
                if self.callback:
                    self.callback(item.key, item.value)
                del self._cache[item.key]

            self._mru.prev = item.prev
            item.prev.next = self._mru
            self._size -= 1

    def values(self):
        """The values of all items stored in this :class:`Cache`.

        :rtype: iterator
        :returns: An iterator over the values of the items stored in this
            ``Cache``, in order from the most recently used item to the least
            recently used item.
        """
        return [item.value for item in self.all()]


class mixin:
    """Subclasses of me can be used as a mixin class by registering another
    class, ``ClassA``, which should be mixed with the ``mixin`` subclass, in
    order to provide simple, less error-prone, multiple inheritance models::

    >>> from __future__ import print_function
    >>> from bridgedb.util import mixin
    >>>
    >>> class ClassA(object):
    >>>     def sayWhich(self):
    >>>         print("ClassA.sayWhich() called.")
    >>>     def doSuperThing(self):
    >>>         super(ClassA, self).__repr__()
    >>>     def doThing(self):
    >>>         print("ClassA is doing a thing.")
    >>>
    >>> class ClassB(ClassA):
    >>>     def sayWhich(self):
    >>>         print("ClassB.sayWhich() called.")
    >>>     def doSuperThing(self):
    >>>         super(ClassB, self).__repr__()
    >>>     def doOtherThing(self):
    >>>         print("ClassB is doing something else.")
    >>>
    >>> class ClassM(mixin):
    >>>     def sayWhich(self):
    >>>         print("ClassM.sayWhich() called.")
    >>>
    >>> ClassM.register(ClassA)
    >>>
    >>> class ClassC(ClassM, ClassB):
    >>>     def sayWhich(self):
    >>>         super(ClassC, self).sayWhich()
    >>>
    >>> c = ClassC()
    >>> c.sayWhich()
    ClassM.saywhich() called.
    >>> c.doSuperThing()
    <super: <class 'ClassA'>, NULL>
    >>> c.doThing()
    ClassA is doing a thing.
    >>> c.doOtherThing()
    ClassB is doing something else.

    .. info:: This class' name is lowercased because pylint is hardcoded to
        expect mixin classes to end in ``'mixin'``.
    """
    __metaclass__ = abc.ABCMeta

# -*- coding: utf-8 -*-
#
# This file is part of BridgeDB, a Tor bridge distribution system.
#
# :authors: Isis Lovecruft 0xA3ADB67A2CDB8B35 <isis@torproject.org>
#           please also see AUTHORS file
# :copyright: (c) 2007-2013, The Tor Project, Inc.
#             (c) 2007-2013, all entities within the AUTHORS file
# :license: 3-clause BSD, see included LICENSE for information

"""BridgeDB logging facilities, including filters, observers, and publishers.

** Module Overview: **
::

   LevelledPublisher - Default :interface:`ILogPublisher` for an
    |                  :interface:`ILogObserver`. Ensures that writes to the
    |                  logger go to all enabled log mechanisms.
    |
    |- XXX DOCDOC see stem's documentation for module docstrings.

** Logging System Structure: **

There should only ever be one instance of :class:`LevelledPublisher`. The
publisher takes care of various lower-level things like gathering tracebacks
and log context settings in the ``eventDict`` like the ``logLevel`` for each
message, and then sending the processed log message to the appropriate
:interface:`ILogObserver`s (e.g. :meth:`LevelledObserver.emit`).

The publisher can have multiple observers. Log observers watch the messages
passing though the system, and decide via their :meth:`LevelledObserver.emit`
method whether or not to record the message.

Similarly, an observer can also have multiple loggers and handlers underneath
it. A logger is responsible for gathering messages from a certain domain,
perhaps a certain component of an application, and sending them to any/all
appropriate log handlers.

Lastly, a log handler is what actually does something with the logged
messages. It simply takes everything it recieves and writes it to a file or a
stream, writes it to a socket, whatever.

An example layout of this structure when configured might look something like
this:

::
    publisher
       |_ observer (name='bridgedb')
       |    |_ logger (name='bridgedb')
       |         | |_ filehandler (bridgedb.log)
       |         | |_ filehandler (debug.log)
       |         | |_ streamhandler (sys.stdout)
       |         |
       |         |_ logger (name='bridgedb.storage') ← getChild('storage')
       |               |_ filehandler (sqlite.log)
       |
       |_ observer (name='assignments')
       |      |_ filehandler (assignments.log)
       |
       |_ observer (name='buckets')
              |_ filehandler (buckets1.log)
              |_ filehandler (buckets2.log)

** Module Settings: **
Logging settings can be easily set by using the :func:`configureLogging`
function, which takes optionally a filename to use as the default application
log file, a folder to store log file in, the level of the lowest level
messages to record, whether or not to enable filtering of sensitive
information (IP addresses, email addresses, and relay fingerprints) from logs,
and the verbosity level, as arguments. A stream can optionally be given
instead of a filename; in that case the default will be to direct all log
messages to that stream (i.e. stdout) rather than to a file. The simplest way
to begin logging to both stdout and a file, both at level WARN or higher,
would be to use :func:`startLogging` which automatically calls
:func:`configureLogging` with the extra kwargs and starts the log observer:

>>> from bridgedb import log as logging
>>> my_logfile = 'doctest.log'
>>> observer = logging.startLogging(filename=my_logfile,
...                                 name="bridgedb",
...                                 folder='./log',
...                                 level=logging.LEVELS['WARN'])
>>> observer.startLoggingToStdout()

Now that logging is configured and started, to log messages simply do:

>>> log = observer.logger
>>> log.warn("Logging to both stdout and file %s" % my_logfile)
UserWarning: Logging to both stdout and file test.log

Any messages below the configured level will be ignored:

>>> log.debug("That technical thing is doing *all of the technical things*.")

and the level of the observer and its underlying loggers/handlers can be
changed with :meth:`LevelledObserver.setLevel`.

** Log Filters: **
Filters for modifying or withholding log messages from records can be created
by subclassing :class:`twisted.python.log.LoggerAdapter`, see
:class:`SafeLoggerAdapter` for an example of such a class which, when given a
logger, creates an adapted logger that scrubs IP and email addresses from
logs.

** How levels are handled: **
The context dictionary :interface:`twisted.python.log.ILogContext` is
essentially a dictionary of settings, whose default values are changed for
each logged message which goes though the ``defaultPublisher``. This context
controls the functionality for the logging eventDict subsystem. These settings
are internal to the :class:`LevelledPublisher` log emission methods
(i.e. :meth:`~LevelledPublisher.msg`, :meth:`~LevelledPublisher.debug`,
:meth:`~LevelledPublisher.err`, etc.), and they are handled automatically, so
you probably shouldn't ever touch them.

 .. data: Publisher Settings (enum)

    =========== =============================================================
    Setting     Description
    =========== =============================================================
    logLevel    Set internally by the :meth:`LevelledPublisher.msg()` methods
    system      See logging.Logger.name and t.p.log.Logger.logPrefix()
    isError     Tells :meth:`LevelledObserver.emit()` to extract a traceback

For example, when calling :meth:`LevelledPublisher.err`, the message's
``eventDict['logLevel']`` is changed to ``LEVELS['ERROR']``,
``eventDict['isError']`` is set to True (telling the system that when
:meth:`~LevelledObserver.emit` is called, a traceback should be extracted from
the frame at which the message was created). ``eventDict['system']`` is merely
the named domain of the logger, which is printed in the output and is
stackable (i.e. if logger with ``name='bridgedb'`` is created, and then a
second logger with ``name='bridgedb.dist'`` then the latter will record all
messages logged to it, and the former will record messages sent to both -- as
well as the ``'bridgedb.foo'`` logger, etc.).

** Note: **
Even though though this file isn't fully PEP8 conformant, please, do *not*
reorder the classes and functions within this file. Various things, like the
block:

    try:
        defaultPublisher
    except NameError:
        defaultPublisher = LevelledPublisher()
    [...]

mean that the class LevelledPublisher must come beforehand, and that any
functions or classes which require the use of ``defaultPublisher`` or
:meth:`addObserver` *must* come afterwards, even though the normal Python
convention is to declare functions before classes in a module.

** TODO **
The logger should *perhaps* be made better/easier to work with at some
point. Unfortunately, there is a lot of (in my opinion) poorly written code in
the stdlib logging module, and twisted's :mod:`~twisted.python.log` is
essentially a confused and half-assed attempt to make stdlib's :mod:`logging`
behave nicely in an async framework. Unfortunately, the redefining of basic,
but essentially the same structures (for example, that a
:class:`twisted.python.log.LogPublisher` is essentially the same as a
:class:`logging.Manager`, and that a :class:`~twisted.python.log.Observer` is
essentially the same a :class:`~logging.Logger`...), between both modules
causes a bit of chaos and confusing in the code, plus we're faced with the
choice of adding more hacks in to get the two things to play nicely, or else
inheriting the downsides of both.

I would propose that, at some point, when a more structured/parseable, more
*actually* threadsafe_, faster, logger is needed for BridgeDB that we use
something else. I have considered using Foolscap_ for ooni, and now
BridgeDB. Foolscap is used by Tahoe-LAFS, and I've spoken with them about
their opinion on it. The response was, "Well, I can't think of any
frustrations I've ever had with it...other than maybe the steep learning
curve, on top of learning Twisted." Which doesn't sound all too bad to me.

Other alternatives might be:
  - Twiggy_: not sure how nicely it plays with Twisted, plus it seems a tiny
    bit too beta for me to feel comfortable using it in production code.
  - Structlog_: I haven't really looked at it. It's also super new.

.. _threadsafe:
 http://emptysqua.re/blog/another-thing-about-pythons-threadlocals/
.. _Foolscap: http://foolscap.lothar.com/docs/logging.html
.. _Twiggy: http://i.wearpants.org/blog/meet-twiggy/
            https://twiggy.readthedocs.org/en/latest/
.. _Structlog:
 https://twistedmatrix.com/pipermail/twisted-python/2013-September/027427.html

Design Requirements:
    [x] way to log different part of application to different loggers
        [x] some should go to files
        [x] some should go to stdout/stderr
        [ ] way to use contexts or other mechanism to gather
            (metrics/statistical) information
        [x] each should have its own level
            [x] level should be changeable
    [x] way to filter log messages
    [x] must be threadsafe
"""

from __future__ import print_function

__docformat__ = 'reStructuredText'

from itertools import dropwhile

import functools
import hashlib
import ipaddr
import os
import sys
import time
import traceback
import weakref

from twisted.python import context
from twisted.python import log as txlog
from twisted.python import failure
from twisted.python import util as txutil
from twisted.internet.interfaces import ILoggingContext
# TODO when/if isis/feature/9317-metrics-contexts is merged,
# bridgedb.contexts.logAssignment() can be used to log bridge assignments for
# a specific distributor, similarly to how t.p.log.callWithContext() can be
# used in the general case.
from twisted.python.log import ILogContext
from twisted.python.log import ILogObserver
# We need both deferr() and err() (even though they are the same function)
# because later on err() will get overriden by LevelledPublisher.err()
from twisted.python.log import deferr
from twisted.python.log import err
from twisted.python.filepath import FilePath
from twisted.python.filepath import InsecurePath
from twisted.python.threadable import synchronize
from zope.interface import implements

from bridgedb.utils import parsers

txlog.logging.captureWarnings(True)
txlog.logging.logThreads = True


class LogFileExistsException(Exception):
    """Raised when configured log file is an existing directory, not file."""

class LogFolderExistsException(Exception):
    """Raised when configured log file is an existing directory, not file."""


#: A dictionary containing logging level names and priority values.
#:
#: .. data: Log Levels (enum)
#: ================== =====
#: Level name         Value
#: ================== =====
#: 'NOTSET'               0
#: 'DEBUG'               10
#: 'INFO'                20
#: 'WARN'/'WARNING'      30
#: 'ERROR'               40
#: 'FATAL'/'CRITICAL'    50
#:
LEVELS = { 'NOTSET'  :  0, 0  : 'NOTSET',
           'DEBUG'   : 10, 10 : 'DEBUG',
           'INFO'    : 20, 20 : 'INFO',
           'WARN'    : 30, 30 : 'WARN',
           'WARNING' : 30,
           'ERROR'   : 40, 40 : 'ERROR',
           'CRITICAL': 50,
           'FATAL'   : 50, 50 : 'FATAL', }

# ----------------
# Context Settings
# ----------------
#: See the module docstring for descriptions of context settings.
context.setDefault(ILogContext, {'system':   str(__package__),
                                 'logLevel': LEVELS['DEBUG'],
                                 'isError':  False})

def updateDefaultContext(oldDefault, newContext):
    """Update the default context for this module.

    :param class oldDefault: The context class to clone and update.
    :param dictionary newContext: Settings to update ``defaultContext`` with.
    """
    updatedContext = context.get(oldDefault).copy()
    updatedContext.update(**newContext)
    context.setDefault(oldDefault, updatedContext)
    return updatedContext

# -----------------
# Observer Settings
# -----------------

#: A mapping from log observer names to instances.
_observerMapping = weakref.WeakValueDictionary()
_safeLogging = True
_logDirectory = os.path.join(os.getcwdu(), u'log')
_level = LEVELS['DEBUG']
_encoding = sys.getfilesystemencoding()
#: Algorithm to hash bridge fingerprints with, for sanitised logging.
_fingerprintHashAlgo = 'sha1'
#: A strftime(3) format string for log timestamps.
_timeFormat = '[%Y-%m-%d %H:%M:%S]'
_formatPrefix = '%(asctime)-4s'
_formatSuffix = '[%(levelname)s] %(message)s'
_verboseFormat = ' '.join((_formatPrefix,
                           'L%(lineno)-.4d:%(module)s.%(funcName)-.30s',
                           _formatSuffix))
_format = ' '.join((_formatPrefix, _formatSuffix))

def setVerboseFormat(verbose=bool):
    """Set the format for log statements.

    :param boolean verbose: If True, include line numbers and module names in
        log statements.
    """
    global _format
    if verbose:
        _format = _verboseFormat
    else:
        _format = ' '.join((_formatPrefix, _formatSuffix))

def getVerboseFormat():
    """Get the format string for a :class:`LevelledPythonObserver.logger`.

    :rtype: string
    :returns: A format string.
    """
    return _format

def setSafeLogging(enable=bool):
    """Enable or disable scrubbing of client IP and email addresses, and bridge
    relay fingerprints.

    :param boolean enable: If True, enable scrubbing of logs.
    """
    global _safeLogging
    _safeLogging = enable

def getSafeLogging():
    """Get the current setting for whether safe logging is enabled or disabled.

    :rtype: boolean
    :returns: True if safe logging is enabled.
    """
    return _safeLogging

def setLevel(level=LEVELS['DEBUG']):
    """Set the level to log messages at.

    This sets the 'level' key inside :interface:`ILogContext`, which is used
    as the default setting for new observers. To set the level for a specific
    observer or handler, do:

    >>> observer = startLogging(name='bridgedb.doctest')
    >>> observer.setLevel(LEVELS['DEBUG'])
    >>> assert observer.level == 10

    :type level: str or int
    :param level: The level, from ``log.LEVELS``, to log at.
    """
    try:
        newlevel = level.upper()
    except AttributeError:
        if level in LEVELS:
            newlevel = level
    else:
        newlevel = LEVELS.get(level)
    if not newlevel:
        return
    global _level
    _level = newlevel
    updateDefaultContext(ILogContext, {'logLevel': newlevel})

def getLevel():
    """Get the current global log level setting.

    Note that Observer classes in this module, when instantiated, set their
    default level to the current level *at the time of their instantiation*.
    """
    return _level

def setDirectory(path=None):
    """Set the folder to store log files in.

    :param string path: The directory. Tildes and non-absolute paths will be
         expanded.
    """
    if path:
        if path.find('~') > 0:
            path = os.path.expanduser(path)
        if not os.path.isabs(path):
            path = os.path.abspath(path)

        global _logDirectory
        _logDirectory = path

def getDirectory():
    """Get the current setting for which directory log files are stored in.

    :rtype: string
    :returns: The absolute path of the directory to store log files in.
    """
    return _logDirectory

def _setPaths(folder=None, filename=None):
    """Ensure that paths are valid and exist.

    :param string folder: If given, use :func:`setDirectory` to sent the log
         folder to this directory. Otherwise, if not given, this value is
         obtained from :func:`getDirectory`.
    :param string filename: The filename to create, relative to ``folder``.
    :returns: Two strings, the first is the fullpath of the directory to store
        log files in, the second is the base filename of the log file
        specified by ``filename``. The second will be None if ``filename is
        not specified.
    """
    if folder:    # Set the folder first if we need to
        setDirectory(folder)
    folder = FilePath(getDirectory())

    if folder.exists():
        msg("Log folder '%s' already exists." % folder.path)
        if not folder.isdir():
            raise LogFolderExistsException(
                "Log folder exists and isn't a directory: %s" % folder.path)
    if not folder.exists():
        msg("Creating log folder '%s'..." % folder.path)
        folder.createDirectory()
    assert folder.exists()

    if not filename:
        return folder.path, ''

    try:
        lf = folder.child(filename)
    except InsecurePath as iperr:
        deferr(iperr)
        raise iperr
    else:
        if lf.exists() and not lf.isfile():
            raise LogFileExistsException(
                "Log file exists and isn't a file: %s" % lf.path)
        filename = lf.basename()
        dirname = lf.dirname()
        return dirname, filename

def configureLogging(filename=None, folder=None,  stream=None, level=None,
                     safe=True, verbose=True):
    """Configure log settings for all :class:`LevelledPythonObserver`s created.

    This function will create default settings so that all call to
    :class:`LevelledPythonObserver` will use these set defaults, unless kwargs
    given to ``LevelledPythonObserver`` direct it to do otherwise.

    Note that ``stream`` and ``file`` cannot be used simultaneously. To log to
    both, do:

    >>> configureLogging(filename='doctest.log')
    >>> logger = startLogging()
    >>> logger.startLoggingToStdout()

    Logging of spawned threads is turned on by default, and warnings are
    configured to be captured.

    :param string filename: A file to write logs to. It will be joined
         relative to the returned value of :func:`getDirectory`.
    :param string folder: If given, use :func:`setDirectory` to sent the log
         folder to this directory. Otherwise, if not given, this value is
         obtained from :func:`getDirectory`.
    :type stream: A stream-like object.
    :param stream: A stream to write logs to, i.e. ``sys.stdout``.
    :type level: integer or string
    :param level: The default level for all ``LevelledPythonObserver``s. This
        may be any of the keys in ``LEVELS``.
    :param boolean verbose: If False, log statements will be formatted to give
        the timestamp, log level, and message for the call to the logger. If
        True, log statements will also include the module name, and the
        calling function plus its line number.
    :param boolean safe: If True, scrub IP and email addresses from logs, and
        cause all fingerprints given to :meth:`redigested` to return a
        rehashed version.
    :ivar string enc: This is set to the default file system encoding, in
        order to set the encoding for streams and files, otherwise it would
        get set to ``ascii``, an encoding which is to be avoided like the
        plague (unless used for the creation of an art).
    """
    if level is not None:
        setLevel(level)
    setVerboseFormat(verbose)
    setSafeLogging(safe)

    lvl = getLevel()
    log_conf = functools.partial(txlog.logging.basicConfig, level=lvl,
                                 format=_format, datefmt=_timeFormat,
                                  encoding=_encoding, filemode='a')
    if filename or folder:
        # We only actually need the filename relative to the log directory
        _, filename = _setPaths(folder, filename)
        if filename:
            log_conf(filename=filename)
    elif stream:
        log_conf(stream=stream)
    else:
        # log to stdout if nothing was specified
        log_conf(stream=sys.stdout)

# ----------------------
# Log Filters & Adapters
# ----------------------

def redigested(fingerprint):
    """Returns a hexidecimal string representing the SHA-1 digest of ``val``.

    This is useful for safely logging bridge fingerprints, using the same
    method used by the tools for metrics.torproject.org.

    :param string fingerprint: The value to digest.
    :rtype: str
    :returns: A 40-byte hexidecimal representation of the SHA-1 digest.
    """
    if _safeLogging:
        return hashlib.new(_fingerprintHashAlgo, fingerprint).hexdigest()
    return fingerprint

def scrubEmailAddress(token):
    """Replace ``token`` if it is an email address.

    Parsing and validating the actual email address is quite slow, so avoid
    putting non-email addresses though ``valid_email_address()``.  The more we
    can turn parsers into generators, and the more we avoid using the
    :mod:`re` module, the faster the parsing will go.

    :param string token: A chunk of text to parse. It MUST be split on
        whitespace, i.e. 'fu' is a token, while 'fu bar' is not. It should be
        ``strip()``ed, but it isn't strictly necessary.
    :returns: The string '[scrubbed]' if the ``token`` was an email address,
        otherwise it returns the unmodified ``token``.
    """
    if token.find('@'):
        if parsers.isEmailAddress(token):
            return '[scrubbed]'
    return token

def scrubIPAddress(token):
    """Replace any IPv4 or IPv6 addresses found with '[scrubbed]'.

    :param string token: A chunk of text to parse. It MUST be split on
        whitespace, i.e. 'fu' is a token, while 'fu bar' is not. It should be
        ``strip()``ed, but it isn't strictly necessary.
    :returns: The string '[scrubbed]' if the ``token`` was an email address,
        otherwise it returns the unmodified ``token``.
    """
    try:
        ipaddr.IPAddress(token)
    except ValueError:
        return token
    else:
        return '[scrubbed]'

def filterEmailAddress(message):
    """Replace any email addresses in the ``message`` with '[scrubbed]'.

    A generator with string.join() is supposed to be the fastest way to do
    this: http://www.skymind.com/~ocrow/python_string/

    :param string message: The log message to filter email addressses out of.
    :rtype: string
    :returns: The ``message`` with any email addresses scrubbed away.
    """
    return ' '.join([scrubEmailAddress(w) for w in message.split()])

def filterIPAddress(message):
    """Replace any IP addresses in ``message`` with '[scrubbed]'.

    :param string message: The log message to filter IP addressses out of.
    :rtype: string
    :returns: The ``message`` with any IP addresses scrubbed away.
    """
    return ' '.join([scrubIPAddress(w) for w in message.split()])

class SafeLoggerAdapter(txlog.logging.LoggerAdapter):
    """Logger adapter for scrubbing IP and email addresses."""

    # TODO the adapter should possibly be compartmentalised so that filtering
    # of IPs, email addresses, and fingerprints are each configurable.

    def process(self, message, kwargs):
        """Process a log message and scrub sensitive information if necessary.

        :param message: A message string.
        :returns: The scrubbed message and the kwargs.
        """
        if message.find('@') > 0:
            message = filterEmailAddress(message)
        # Try to avoid doing intense parsing for IP addresses if there aren't
        # any numbers in the message (XXX what are the odds of an IPv6 address
        # coming up without any digits?):
        for number in xrange(0, 10):
            if message.find(str(number)):
                message = filterIPAddress(message)
                break
        return message, kwargs

# --------------
# Log Publishers
# --------------

class LevelledPublisher(txlog.LogPublisher):
    """Publishes logged events to all registered log observers.

    :ivar list synchronized: If running inside a thread, every call to these
        methods will be wrapped with a lock. See
        :func:`twisted.python.threadable.synchronize`.
    :ivar list observers: Any log observers which have been added with
        :meth:`addObserver`, and to which logged events should be published.
    :ivar string verboseErrors: A string indicating how much information to
         include in the tracebacks gathered from :meth:`exception`. Must be
         one of ``'brief'``, ``'default'``, or ``'verbose'``.
    """
    synchronized = ['_msg']

    def __init__(self):
        """Create a log publisher."""
        txlog.LogPublisher.__init__(self)
        self.observers = []
        self.verboseErrors = 'default'

    def stopLogging(self):
        """Shutdown the logger.

        Calling this will cause all logging, to files or otherwise, to stop.
        """
        self._msg("Stopping %s logging at %s" % (__package__, time.time()))
        [observer.stop() for observer in self.observers]
        self.observers = []

    def exception(self, error=None, message=None, **kwargs):
        """Log an exception or failure with its traceback.

        This function works regardless of whether or not there is currently an
        :class:`Exception`, and, if there is an ``Exception``, it doesn't
        matter if it is wrapped in a :class:`twisted.python.failure.Failure`.

        If ``error`` is a :class:`twisted.python.failure.Failure`, and
        :attr:`error.captureVars` is True, then a detailed traceback will be
        logged, which will include global and local variables. Note that this
        significantly slows down the logging facilities.

        If ``error`` is None, then nothing will happen.

        When wrapping an Exception in a
        :class:`~twisted.python.failure.Failure`, we can set the
        ``Failure.captureVars`` attribute to get an extremely detailed
        traceback which includes global and local variables at the time of the
        exception. To get these, set :attr:`defaultPublisher.debug` to
        'verbose' or 'brief', like this:

        >>> import exceptions
        >>> defaultPublisher.debug = 'verbose'
        >>> def getfail():
        ...     numberFlyingSaucers = 13
        ...     try:
        ...         raise FutureWarning("Alien alert!!", numberFlyingSaucers)
        ...     except Exception as error:
        ...         fail = failure.Failure(error, captureVars=True)
        ...         return fail
        >>> try: getfail()
        ... except: _log.exception(fail)
        *--- Failure #1 ---
        Failure: exceptions.FutureWarning: ('Alien alert!!', 13)
        *--- End of Failure #1 ---

        which obviously gives you the 'numberFlyingSaucers' variable as well.

        :type error: A :class:`twisted.python.failure.Failure`, or an
            :exc:`Exception`, or None.
        :param error: An exception, or a failure, to capture a traceback
            for. If None, then an attempt will be made to extract the most
            recent exception from the stack.
        :param string message: Some sort of explanation or context explaining why
            the ``error`` occured.
        :keyword: All other kwargs are passed to :meth:`msg`, and are used
            there to update the ``eventDict`` context dict.
        """
        kwargs.update({'logLevel': LEVELS['FATAL'],
                       'isError': True,
                       'exc_info': False})

        # We do not want to store the actual Failure instance in the
        # eventDict, because then _emitWithLevel() would grab a duplicate
        # traceback from the Failure when it calls txlog.textFromEventDict
        if isinstance(error, failure.Failure):
            detail = 'verbose' if error.captureVars else self.verboseErrors
            text = '\n'.join(((error.getErrorMessage() or 'Unhandled Error'),
                              error.getTraceback(detail=detail)))
        else:
            exctype, excval, exctb = sys.exc_info()
            text = '\n'.join(
                (message, traceback.print_exception(exctype, excval, exctb)))
        self._msg(text, **kwargs)

    # We need to override t.p.log.LogPublisher._err() because it is called in
    # t.p.log.LogPublisher.msg without passing kwargs (and we would need to be
    # able to pass it a logLevel kwarg).
    def _err(self, error=None, why=None, **kwargs):
        """Log a message at the ERROR level.

        :type error: A :class:`twisted.python.failure.Failure`, or an
            :exc:Exception, or None.
        :param error: A failure to log. If ``error`` is a :exc:`Exception`, it
            will get wrapped in a :class:`~twisted.python.failure.Failure`. If
            it is None, then a :class:`t.p.failure.Failure` will be created
            from the current exception state.
        :param str why: A message which should describe the context in which
            ``error`` occurred.
        :keyword: Other kwargs are passed to :meth:`LevelledPublisher.msg`,
            and are used there to update the ``eventDict`` context dict.
        """
        kwargs.update({'logLevel': LEVELS['ERROR'],
                       'isError': True,
                       'exc_info': True})
        if error is None:
            error = failure.Failure()
        if isinstance(error, failure.Failure):
            self._msg(failure=error, why=why, **kwargs)
        elif isinstance(error, Exception):
            self._msg(failure=failure.Failure(error), why=why, **kwargs)
        else:
            self._msg(repr(error), why=why, **kwargs)

    def warn(self, *message, **kwargs):
        """Log a message at the WARN level.

        It is not necessary to use a :class:`warnings.WarningMessage`, though
        if ``kwargs`` contains the keys ``category``, ``filename``, and
        ``lineno``, then a :class:`warnings.WarningMessage` will be created
        automatically.

        :param str message: The warning message to log.
        :param class category: The class which generated the message, its full
            import path will be automatically devised though
            :func:`reflect.qual`.
        :param str filename: The name of the current file where the warning
            occurred.
        :param str lineno: The line number where the warning occurred.
        :keyword: All other kwargs are passed to :meth:`msg`, and are used
            there to update the ``eventDict`` context dict.
        """
        kwargs.update({'logLevel': LEVELS['WARN']})
        #txlog.warnings.warn(*message)
        self._msg(*message, **kwargs)

    def _msg(self, *message, **kwargs):
        """Log a message. If no logLevel in kwargs, the level is INFO.

        :keyword: These update the ``eventDict`` context dictionary.
        """
        if not 'logLevel' in kwargs.keys():
            kwargs.update({'logLevel': LEVELS['INFO']})
        txlog.LogPublisher.msg(self, *message, **kwargs)

    def debug(self, message, *arg, **kwargs):
        """Log a message at the DEBUG level.

        :keyword: All other kwargs are passed to :meth:`msg`, and are used
            there to update the ``eventDict`` context dict.
        """
        self._msg(message, *arg, logLevel=LEVELS['DEBUG'], **kwargs)
# Make sure the locks get created for I/O handling methods
synchronize(LevelledPublisher)

# This ensures that the instance of :class:`LevelledPublisher` isn't
# reinstantiated if the module is reloaded:
try:
    defaultPublisher
except NameError:
    defaultPublisher = LevelledPublisher()
    addObserver = defaultPublisher.addObserver
    removeObserver = defaultPublisher.addObserver
    stopLogging = defaultPublisher.stopLogging

    msg = info = defaultPublisher._msg
    debug = defaultPublisher.debug
    exception = fatal = critical = defaultPublisher.exception
    error = err = defaultPublisher._err
    warn = warning = defaultPublisher.warn

# -------------
# Log Observers
# -------------

def _emitWithLevel(observerCls, eventDict):
    """General-use function for overriding an observer's ``emit()`` method.

    This function is meant as a generalised method override for the ``emit``
    method of classes which implement
    :interface:`twisted.python.log.ILogObserver`. It understands log levels,
    similar to the Python stdlib logging module, and will refuse to emit
    messages whose ``eventDict['logLevel']`` is lower than the
    ``observerCls.level``.

    It also prepends the log level of the message, as well as basic ISO-8601
    timestamps, to log messages. By default, the timestamp separator used is a
    single space (instead of a 'T'), and timestamp precision is taken to the
    seconds.

    If ``observerCls`` is a :class:`LevelledPythonObserver` it returns the
    message level and the extracted text/traceback/errormessage.

    For other observer classes:
      - If the extracted message is at a level that ``observerCls`` is
        ignoring, it returns without doing anything.
      - Otherwise, it calls :meth:`observerCls.write(message)` where
        ``message`` is a formatted string contained the full message,
        including timestamp, level, and the ``name`` attribute of the
        observer.

    :param observerCls: An instance of a log observer class that implements
        then :interface:`twisted.python.log.ILogObserver` interface.
    :param dict eventDict: see :func:`twisted.python.log.textFromEventDict`.
    """
    # Get the original message
    text = txlog.textFromEventDict(eventDict)

    # Get the level that the message was logged at:
    if 'logLevel' in eventDict:
        msg_lvl = eventDict['logLevel']
    elif eventDict['isError']:
        msg_lvl = LEVELS['ERROR']
        if isinstance(observerCls, LevelledObserver):
            if observerCls.level in range(40, 60, 10):
                # This lets txlog.logging know that we expect a traceback:
                eventDict['exc_info'] = True
        # If we used the LevelledPublisher.exception() method, then the
        # traceback should already be in eventDict['message'], and
        # eventDict['failure'] will still be None.
        #
        # :meth:`txlog.textFromEventDict` will extract into the above ``text``
        # variable the tracebacks from failures/exceptions which are logged
        # with LevelledPublisher.err() (these have an eventDict['failure'])
        if 'failure' in eventDict:
            msg_lvl = LEVELS['FATAL']
    else:
        # If the log message somehow doesn't have a level, pretend it has
        # whatever level we're logging at.
        msg_lvl = observerCls.level

    if not text and 'message' in eventDict:
        text = eventDict['message']
        # join them if we got a list of lines
        if isinstance(text, (list, tuple, set)):
            text = ' '.join([str(m) for m in eventDict['message']])+'\n'
    if not text:
        return
    else:
        obsName = getattr(observerCls, 'name', None)
        lvlName = LEVELS.get(msg_lvl) + ':'
        fmtDict = {'system': obsName or eventDict['system'],
                   'text': text.replace("\n", "\n\t"),
                   'level': lvlName,
                   'time': observerCls.formatTime(eventDict['time'])}
        message = txlog._safeFormat("%(time)s %(level)s %(text)s\n", fmtDict)

        if isinstance(observerCls, LevelledObserver):
            return message, msg_lvl, eventDict
        elif msg_lvl >= observerCls.level:
            txutil.untilConcludes(observerCls.write, message)
            txutil.untilConcludes(observerCls.flush)

# Declare the observer interface implementation
ILogObserver.implementedBy(_emitWithLevel)

class LevelledObserver(txlog.FileLogObserver, object):
    """Base class for the other observers; should not be used directly.

    This class is also used to monkeypatch :class:`t.p.log.FileLogObserver`,
    which is unfortunately an old-style class and breaks inheritance and the
    new MRO model added in Python 2.7.4ish.

    :ivar string timeFormat: The stftime(3) format for printing timestamps.
    """
    implements(ILoggingContext)

    timeFormat = _timeFormat

    def __init__(self, log_file=None, name=None):
        """Create an observer which emit()s logLevels.

        This class is a suitable visitor pattern to both the standard library
        :mod:`logging` module as well as Twisted logging infrastructure.

        :param file log_file: A sufficiently file-like object. (In Python this
            is inadequately and variably defined, but is often taken to mean
            that the "file-like object" has a write() method.)
        :param string name: The name of this observer. This is passed to
            :meth:`logging.getLogger <twisted.python.log.logging.getLogger>`.
        :ivar integer level: The level which this observer should log at. It
            gets set to the current ``level`` within the
            ``context.defaultContext``.
        """
        self.verboseFormat = getVerboseFormat()
        self.level = getLevel()
        self.name = self.logPrefix(name)

        if not log_file:
            log_file = txlog.NullFile()

        super(LevelledObserver, self).__init__(log_file)

    def _mapObserver(self):
        """Add a mapping between an observer's name and it's instance.

        The mapping, :attr:`_observerMapping`, is weakly referenced to save
        memory, and it stores a table of observer names (keys) to instances
        (values). This method is wrapped in binary semaphore locks.
        """
        _observerMapping[self.name] = self

    def _unmapObserver(self):
        """Delete the mapping between observer and its name, if it exists."""
        del _observerMapping[self.name]

    def emit(self, eventDict):
        """Emit a log message if it's at (or above) our level.

        See :func:`_emitWithLevel`.

        :param dictionary eventDict: see
            :func:`twisted.python.log.textFromEventDict` for an explanation of
            the default ``eventDict`` keys and their uses.
        """
        _, message = _emitWithLevel(self, eventDict)
        if message:
            txutil.untilConcludes(self.write, message)
            txutil.untilConcludes(self.flush)

    def logPrefix(self, name=None):
        """Get the name of a logger instance.

        It may seem silly, but this method is necessary for using functions
        such as :func:`twisted.python.log.callWithLogger` in a way that is
        compatible with stdlib logging module's :func:`logging.getLogger`. See
        also the stub :class:`twisted.python.log.Logger`.

        :rtype: str
        :returns: The name of this logger.
        """
        def first(*args):
            """Returns the first arg which is not None."""
            return dropwhile(lambda x: x is None, args).next()
        return first(name, __package__, self.__module__, __name__, "root")

    def start(self):
        """Start observing log events."""
        if self.emit in defaultPublisher.observers:
            msg("Observer %r already started!" % repr(self))
        else:
            addObserver(self.emit)
            self._mapObserver()

    def stop(self):
        """Stop observing log events."""
        removeObserver(self.emit)
        self._unmapObserver()
        msg("Removed observer: %r" % repr(self))

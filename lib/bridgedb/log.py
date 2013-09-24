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

import hashlib
import ipaddr
import os
import sys
import time
import traceback

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




#: A dictionary of logging level names and their corresponding priority values
LOG_LEVEL = { 'NOTSET':    0,
              'DEBUG':    10,
              'INFO':     20,
              'WARN':     30,
              'WARNING':  30,
              'ERROR':    40,
              'CRITICAL': 50,
              'FATAL':    50, }

#: The current level to log at:
level = LOG_LEVEL['WARN']
#: The directory to store logfiles in:
folder = os.getcwd()
#: The instantiated :class:`log.BridgeDBLogPublisher` which should be used for
#: publishing all incoming log events to log observers. This is automatically
#: instantiated at the end of :file:log.py.
publisher = None
#: The stftime(3) format for printing timestamps:
timeFormat = '[%Y-%m-%d %H:%M:%S]'

# The default context for the logging eventDict subsystem.
context.setDefault(ILogContext, {'isError': 0,
                                 'system': 'bridgedb',
                                 'logLevel': level})


def _emit_with_level(eventDict):
    """Prepend basic ISO-8601 timestamps to log messages emitted on stdout.

    By default, the separator used is a single space (instead of a 'T'), and
    timestamp precision is taken to the seconds. Also, if
    ``eventDict['logLevel']`` exists, fail to emit the log message if
    ``log.level`` is greater.

    :param dict eventDict: see :func:`t.p.log.textFromEventDict`.
    """
    text = _log.textFromEventDict(eventDict)

    ## Setup log level handling:
    if 'logLevel' in eventDict:
        emission_level = eventDict['logLevel']
    elif eventDict['isError']:
        emission_level = LOG_LEVEL['ERROR']
        if 'failure' in eventDict:
            text = ((eventDict.get('why') or 'Unhandled Error')
                    + '\n' + eventDict['failure'].getTraceback())
    else: emission_level = LOG_LEVEL['INFO']

    ## Bail if no message string, or if this is at a level we're ignoring
    if (text is None) or (emission_level < level):
        return None, None

    lvlName = _levelNumberToStr(emission_level) + ':'
    fmtDict = {'system': eventDict['system'],
               'text': text.replace("\n", "\n\t"),
               'level': lvlName,
               'time': _formatTime(eventDict['time'])}
    message = _log._safeFormat("%(time)s %(level)s %(text)s\n", fmtDict)
    return emission_level, message

def _formatTime(when):
    """see :meth:`twisted.python.log.FileLogObserver.formatTime`."""
    if timeFormat:
        return datetime.fromtimestamp(when).strftime(timeFormat)
    return ''

def _msg(*arg, **kwargs):
    """Log a message at the INFO level."""
    if not 'logLevel' in kwargs:
        kwargs.update({'logLevel': LOG_LEVEL['INFO']})
    _log.msg(*arg, **kwargs)

def _utcdatetime():
    """Get the current UTC time, with format: '2013-06-27 06:53:40.929589'.

    :returns: String containing the current time in UTC, with ISO-8601 format.
    """
    return datetime.isoformat(datetime.utcnow())

def err(_stuff=None, _why=None, **kwargs):
    """Log a message at the ERROR level.

    :type _stuff: A :type:None, :class:`t.p.failure.Failure`, or
    :exc:Exception.

    :param _stuff: A failure to log. If ``_stuff`` is a :exc:Exception, it
        will get wrapped in a :class:`t.p.failure.Failure`. If it is None,
        then a :class:`t.p.failure.Failure` will be created from the current
        exception state.

    :param str _why: A message which should describe the context in which
        ``_stuff`` occurred.
    """
    kwargs.update({'logLevel': LOG_LEVEL['ERROR']})
    deferr(_stuff, _why, **kwargs)

def _exception(error=None, **kwargs):
    """Log an exception with its traceback.

    This function works regardless of whether or not there is currently an
    :class:`Exception`, and, if there is an ``Exception``, it doesn't matter
    if it is wrapped in a :class:`twisted.python.failure.Failure`.

    If ``error`` is a :class:`twisted.python.failure.Failure`, and
    :attr:`error.captureVars` is True, then a detailed traceback will be
    logged, which will include global and local variables. Note that this
    significantly slows down the logging facilities.

    If ``error`` is None, then nothing will happen.

    :type error: A :class:`twisted.python.failure.Failure`, an
        :exc:`Exception`, or None.
    :param error: An exception or failure to capture a traceback for.
    :param str _why: Some sort of explanation or context explaining why the
        ``error`` occured.
    """
    kwargs.update({'logLevel': LOG_LEVEL['CRITICAL']})
    if isinstance(error, failure.Failure):
        if error.captureVars:
            msg_str = error.printDetailedTraceback()
        else:
            msg_str = error.printTraceback()
    else:
        exc_type, exc_value, exc_traceback = sys.exc_info()
        msg_str = traceback.print_exception(exc_type, exc_value, exc_traceback)
    _log.msg(error, **kwargs)

def levelIntToStr(number):
    """Take an integer representing a LOG_LEVEL and return its name.

    :param str string: One of the values from the :attr:`log.LOG_LEVEL` dict.
    :raises: A :exc:`ValueError` if ``number`` is not in
        ``LOG_LEVEL.values()``.
    :rtype: str
    :returns: The corresponding name of the log level ``number``.
    """
    for key, value in LOG_LEVEL.items():
        if number == value:
            return key
    raise ValueError("Numeric log level '%d' doesn't exist." % number)

def levelStrToInt(string):
    """Take a string representing a LOG_LEVEL and return its numeric value.

    :param str string: One of the keys from the :attr:`log.LOG_LEVEL` dict.
    :raises: A :exc:`ValueError` if ``string`` is not in ``LOG_LEVEL.keys()``.
    :rtype: int
    :returns: The corresponding numeric value of the log level ``string``.
    """
    for key, value in LOG_LEVEL.items():
        if string.upper() == key:
            return value
    raise ValueError("String log level '%s' doesn't exist." % string.upper())

def setLevel(logLevel=None):
    """Set the level to log messages at. Defaults to 10, i.e. 'DEBUG' level.

    :type logLevel: str or int
    :param logLevel: The level (from log.LOG_LEVEL) to log at.
    """
    global level
    if logLevel.upper() in LOG_LEVEL.keys():
        level = levelStrToInt(logLevel)
    elif logLevel in LOG_LEVEL.values():
        level = logLevel
    else:
        _msg("Configured LOG_LEVEL must be one of: %r" % LOG_LEVEL)
        level = 10

def startLogging(log_file=None, *args, **kwargs):
    """Initialize the publisher and start logging to a specified file.

    :type file: str or None
    :param file: The filename to log to. If None, log only to stdout.
    """
    if isinstance(log_file, _log.StdioOnnaStick): return

    if log_file:
        fileobserver = BridgeDBFileLogObserver(log_file, *args, **kwargs).emit
        global publisher
        try:
            publisher.addObserver(fileobserver)
        except NameError:
            publisher = BridgeDBLogPublisher()
            publisher.addObserver(fileobserver)
        finally:
            publisher.start()


class BridgeDBLogObserver(FileLogObserver):
    """A logger for writing to sys.stdout."""

    def emit(self, eventDict):
        """Emit a log message."""
        emission_level, message = _emit_with_level(eventDict)
        if message:
            _util.untilConcludes(self.write, message)
            _util.untilConcludes(self.flush)

    def logPrefix(self):
        """Get the name of this logger instance."""
        try: lp = self.prefix
        except AttributeError: lp = 'bridgedb'
        return lp

directlyProvides(BridgeDBLogObserver, ILogObserver)

class BridgeDBFileLogObserver(FileLogObserver):
    """Writes to a file-like object and emits simple timestamps."""

    #: The folder to store logfiles in. This should be set outside this file
    #: by doing:
    #:
    #: >>> import bridgedb.log as logging
    #: >>> logging.folder = './putlogshere'
    #:
    folder = filepath.FilePath(folder)

    #: The default permissions to use for newly created logfiles.
    default_mode = stat.S_IREAD | stat.S_IWRITE

    def __init__(self, filename='bridgedb.log', daily=False,
                 max_size=None, max_files=None):
        """Log events to a file.

        When capturing to logfiles, by default, they are stored in the current
        working directory where BridgeDB is run from in a ``folder`` named
        'log'. If the ``daily`` setting is enabled, then the date is appended
        to that ``prefix``.

        By default, logfiles are created daily, are not limited by size, and
        are deleted after five days. To rotate based on size instead, do:

        :param str filename: The filename to write to.

        :param bool daily: If True, store separate logfiles for each day;
            otherwise, save everything in a logfile named ``prefix``.
            (default: False)

        :param int max_size: If not using ``daily`` logfiles, this is the
            maximum allowed size for a logfile, in bytes, before rotating. If
            daily rotation is not being used, and ``max_size`` is not set, it
            will default to 1000000 bytes.

        :param int max_files: If not using ``daily`` logfiles, this is the
            maximum number of logfiles to keep after rotating. If daily
            rotation is not used, and this is not set, it will default to 5.

        :ivar str timeFormat: A strftime(3) string for setting the timestamp
            format. See ``bridgedb.log.timeFormat``.
        """
        fn = None
        try:
            fn = open(filename, 'a+')
        except OSError:
            _msg("ERROR: Couldn't open logfile '%s'" % filename)

        ## no super(); t.p.l.FileLogObserver is an old-style class.
        FileLogObserver.__init__(self, fn)

        self.timeFormat = timeFormat

        if daily:
            _msg("WARNING: Daily logfiles will not be rotated/deleted!")
            self.logfile = logfile.DailyLogFile(filename,
                                                self.folder.path,
                                                defaultMode=self.default_mode)
        else:
            self.max_size = max_size if isinstance(max_size, int) else 10**6
            self.max_files = max_files if isinstance(max_files, int) else 5
            self.logfile = logfile.LogFile(name=filename,
                                           directory=self.folder.path,
                                           rotateLength=self.max_size,
                                           maxRotatedFiles=self.max_files)

    def emit(self, eventDict):
        emission_level, message = _emit_with_level(eventDict)
        if message:
            _util.untilConcludes(self.write, message)
            _util.untilConcludes(self.flush)

directlyProvides(BridgeDBFileLogObserver, ILogObserver)


## we put object as a second parent to workaround that t.p.log.LogPublisher
## is a Python  old-style class. :(
class BridgeDBLogPublisher(_log.LogPublisher, object):
    """Publishes logged events to all registered log observers.

    Currently, all log observers in the ``observers`` list will all be set to
    the same verbosity level.

    :ivar list observers: Any log observers which have been added to which
        logged events should be published.
    :ivar list synchronized: If running inside a thread, every call to these
        methods will be wrapped with a lock.
    """
    synchronized = ['msg']

    def __init__(self, log_to_stdout=True):
        """Create a log publisher.

        :param bool logToStdout: If True, log to stdout. (default: True)
        """
        self.observers = []
        self.stdout_observer = None
        self.log_to_stdout = log_to_stdout
        self.start()

    def mute(self):
        """Stop logging on stdout. Logging to files will still occur."""
        self.msg("Muting log events on stdout.")
        if self.stdout_observer:
            self.removeObserver(self.stdout_observer)

    def start(self):
        """Start logging on stdout, if :attr:`log_to_stdout` is True.

        Later, extra observers can be added via :meth:`addObserver`.
        """
        self.msg("Starting BridgeDB logging on %s" % _utcdatetime())
        if self.log_to_stdout:
            self.stdout_observer = BridgeDBLogObserver(sys.stdout).emit
            self.addObserver(self.stdout_observer)

    def stop(self):
        """Shutdown the logger."""
        self.msg("Stopping BridgeDB logging at %s" % _utcdatetime())
        self.observers = []

    def suspend(self, observer):
        """Suspend a log observer.

        :type observer: :interface:`t.p.log.ILogObserver`
        :param observer: The file-like object to cease writing log events to.
        """
        self.debug("Suspend called for log observer %r" % repr(observer))
        if observer in observers:
            self.debug("Observer found in observer list. Suspending observer")
            try: verifyObject(ILogObserver, observer)
            except BrokenImplementation: pass
            else: self.removeObserver(observer)
        else:
            self.debug("Observer %r not in observers list" % repr(observer))

    exception = _exception

    def err(self, _stuff=None, _why=None, **kwargs):
        """Log a message at the ERROR level.

        :type _stuff: A :type:None, :class:`t.p.failure.Failure`, or
            :exc:Exception.

        :param _stuff: A failure to log. If ``_stuff`` is a :exc:Exception, it
            will get wrapped in a :class:`t.p.failure.Failure`. If it is None,
            then a :class:`t.p.failure.Failure` will be created from the
            current exception state.

        :param str _why: A message which should describe the context in which
            ``_stuff`` occurred.
        """
        self.msg(failure=_stuff, why=_why, isError=1)

    def warn(self, message, *args, **kwargs):
        """Log a message at the WARN level.

        :param str message: The warning message to log.
        :param class category: The class which generated the message, its full
            import path will be automatically devised though
            :func:`reflect.qual`.
        :param str filename: The name of the current file where the warning
            occurred.
        :param str lineno: The line number where the warning occurred.
        """
        if level >= LOG_LEVEL['WARN']:
            return       ## The warnings modules won't take extra parameters
        kwargs.update({'logLevel': LOG_LEVEL['WARN']})
        self.msg(message, *args, **kwargs)

    def msg(self, *args, **kwargs):
        """Log a message. If no logLevel in kwargs, the level is INFO."""
        if not 'logLevel' in kwargs.keys():
            kwargs.update({'logLevel': LOG_LEVEL['INFO']})
        super(BridgeDBLogPublisher, self).msg(*args, **kwargs)
    info = msg

    def debug(self, message, *arg, **kwarg):
        """Log a message at the DEBUG level."""
        this_level = LOG_LEVEL['DEBUG']
        if level >= this_level:
            self.msg(message, *arg, logLevel=LOG_LEVEL['DEBUG'], **kwarg)

#: Make sure the locks get created for synchronized methods
synchronize(BridgeDBLogPublisher)

try:
    assert publisher is not None
except AssertionError:
    publisher = BridgeDBLogPublisher()
    addObserver = publisher.addObserver
    removeObserver = publisher.removeObserver
    start = publisher.start
    stop = publisher.stop
    suspend = publisher.suspend
    mute = publisher.mute
    exception = publisher.exception
    err = publisher.err
    warn = publisher.warn
    showwarning = publisher.showwarning
    msg = publisher.msg
    info = publisher.info
    debug = publisher.debug

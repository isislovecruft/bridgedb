# -*- coding: utf-8 ; test-case-name: bridgedb.test.test_util -*-
#
# This file is part of BridgeDB, a Tor bridge distribution system.
#
# :authors: Isis Lovecruft 0xA3ADB67A2CDB8B35 <isis@torproject.org>
#           Matthew Finkel 0x017DD169EA793BE2 <sysrqb@torproject.org>
# :copyright: (c) 2013-2014, Isis Lovecruft
#             (c) 2013-2014, Matthew Finkel
#             (c) 2007-2014, The Tor Project, Inc.
# :license: 3-Clause BSD, see LICENSE for licensing information

"""Common utilities for BridgeDB."""

from functools import partial

import logging
import logging.config
import logging.handlers
import os


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
    except AttributeError:
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

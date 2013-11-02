# -*- coding: utf-8 -*-
#
# This file is part of BridgeDB, a Tor bridge distribution system.
#
# :authors: Isis Lovecruft 0xA3ADB67A2CDB8B35 <isis@torproject.org>
#           please also see AUTHORS file
# :copyright: (c) 2013 Isis Lovecruft
#             (c) 2007-2013, The Tor Project, Inc.
#             (c) 2007-2013, all entities within the AUTHORS file
# :license: 3-clause BSD, see included LICENSE for information

"""Classes for finding and managing lists of open proxies.

** Module Overview: **

"""

from __future__  import print_function
from collections import MutableSet
from functools   import update_wrapper
from functools   import wraps

import ipaddr
import logging
import os
import time
import types

from twisted.internet import defer
from twisted.internet import protocol
from twisted.internet import reactor
from twisted.internet import utils as txutils
from bridgedb.runner  import find
from bridgedb.parse   import isIPAddress


def downloadTorExits(proxyList):
    """Run a script which downloads a list of Tor exit relays.

    :param proxyList: The :class:`ProxySet` instance from :mod:`bridgedb.Main`.
    :rtype: XXX
    """
    script = find('get-tor-exits')
    proto = ExitListProtocol(script)
    proto.deferred.addCallback(proxyList.addExitRelays)
    proto.deferred.addErrback(logging.exception)
    transport = reactor.spawnProcess(proto, script,
                                     args=[script, '--stdout'], env={})
    return proto.deferred

def loadProxiesFromFiles(proxyListFiles, proxySet=None):
    """Load proxy IP addresses from a list of files.

    :param list proxyListFiles: A list of strings, each string should be a
        filename, either absolute or relative to the current working
        directory, which contains the IP addresses of various open proxies,
        one per line.
    :type proxySet: None or :class:`~bridgedb.proxy.ProxySet`.
    :param proxySet: If given, load the addresses read from the files into
        this ``ProxySet``.
    :returns: A list of the loaded proxies.
    """
    logging.info("Reloading proxy lists...")

    addresses = []
    if proxySet: oldProxySet = proxySet.copy()

    for filename in proxyListFiles:
        with open(filename, 'r') as proxyFile:
            for line in proxyFile.readlines():
                line = line.strip()
                if proxySet: proxySet.add(line) # ProxySet will validate the IP
                else:
                    ip = isIPAddress(line)
                    if ip: addresses.append(ip)
    if proxySet:
        addresses = list(proxySet.difference(oldProxySet))

    return addresses

class ProxySet(MutableSet):
    """A :class:`collections.MutableSet` for storing validated IP addresses."""

    def __init__(self, proxies=dict()):
        """Initialise a ``ProxySet``.

        :type proxies: A tuple, list, dict, or set.
        :param proxies: Optionally, initialise with an iterable, ``proxies``.
            For each ``item`` in that iterable, ``item`` must either:
                1. be a string or int representing an IP address, or,
                2. be another iterable, whose first item satisfies #1.
        """
        super(ProxySet, self).__init__()
        self._proxydict = dict()
        self._proxies = set()
        self.addProxies(proxies)

    @property
    def proxies(self): return [x for x in self._proxies]
    @proxies.setter
    def proxies(self, *args, **kwargs): pass
    @proxies.deleter
    def proxies(self): self.clear()


    def __add__(self, ip=None, value=None):
        """Add an ip to this set.

        This has no effect if the ip is already present.  The ip is only added
        if it passes the checks in :func:`bridgedb.parse.isIPAddress`.

        :type ip: basestring or int
        :param ip: The IP address to check.
        :param value: An optional value to link to ``ip``. If not given, it
            will be a timestamp (in seconds since epoch) for when ``ip`` was
            first added to the set.
        :rtype: boolean
        :returns: True if ``ip`` is in this set; False otherwise.
        """
        ip = isIPAddress(ip)
        if ip:
            if self._proxies.isdisjoint(set(ip)):
                if value is True: value = time.time()
                self._proxies.add(ip)
                self._proxydict[ip] = value
                return True
        return False
    __radd__ = __add__

    def __contains__(self, ip):
        """x.__contains__(y) <==> y in x.

        :type ip: basestring or int
        :param ip: The IP address to check.
        :rtype: boolean
        :returns: True if ``ip`` is in this set; False otherwise.
        """
        ipset = [isIPAddress(ip),]
        try:
            if len(self._proxies.intersection(ipset)) == len(ipset):
                return True
        except TypeError: return False
        return False

    def __sub__(self, ip, ignoreErrors=True):
        """Entirely remove ``ip`` from this set.

        :type ip: basestring or int
        :param ip: The IP address to check.
        :param boolean ignoreErrors: If True, ignore any errors raised if
            ``ip`` was not in the set.
        """
        try:
            self._proxies.discard(ip)
            self._proxydict.pop(ip)
        except Exception:
            if ignoreErrors is True: pass
            else: raise

    def __rsub__(self, *a, **kw): raise NotImplemented

    @wraps(isIPAddress)
    def _checkIP(self, ip): return isIPAddress(ip)

    def _getErrorMessage(self, x=None, y=None):
        """Make an error message describing how this class works."""
        message = """
Parameter 'proxies' must be one of:
    - a {1} of {0}
    - a {2} of {0}
    - a {3}, whose keys are {0} (the values can be anything)
    - a {4} of {1}s, whose first object in each {1} must be a {0}
    - a {4} of {0}
        """.format(type(''), type(()), type([]), type({}), type(set(())))
        end = "You gave: a {0}".format(type(y))
        if isinstance(y, dict): end += ", whose keys are {0}".format(type(x[0]))
        else: end += " of {0}".format(type(x))
        return os.linesep.join((message, end))

    def addProxies(self, proxies):
        """Add proxies to this set.

        This calls :func:`add` for each item in the iterable ``proxies``.

        :type proxies: A tuple, list, dict, or set.
        :param proxies: An iterable.  For each ``item`` in that iterable,
            ``item`` must either:
                1. be a string or int representing an IP address, or,
                2. be another iterable, whose first item satisfies #1.
        """
        if isinstance(proxies, dict):
            [self.add(ip, value) for (ip, value) in proxies.items()]
        else:
            for x in proxies:
                if isinstance(x, (tuple, list, set)):
                    try:
                        if len(x) == 2:  (ip, value) = x
                        elif len(x) == 1: ip, value  = x, True
                        else: raise TypeError
                    except (TypeError, ValueError):
                        raise ValueError(self._getErrorMessage(x, proxies))
                    else: self.add(ip, value)
                elif isinstance(x, (basestring, int)): self.add(x)
                else: raise ValueError(self._getErrorMessage(x, proxies))

    def firstSeen(self, ip):
        """Get the timestamp when ``ip`` was first seen, if available.

        :type ip: basestring or int
        :param ip: The IP address to check.
        :rtype: float or None
        :returns: The timestamp (in seconds since epoch) if available.
            Otherwise, returns None.
        """
        try: when = self._proxydict.get(ip)
        except KeyError: pass
        if isinstance(when, float):
            return when
        return None

    def isExitRelay(self, ip):
        """Check if ``ip`` is a known Tor exit relay.

        :type ip: basestring or int
        :param ip: The IP address to check.
        :rtype: boolean
        :returns: True if ``ip`` is a known Tor exit relay; False otherwise.
        """
        if self._proxydict.has_key(ip):
            if self._proxydict[ip] == 'exitlist':
                return True
        return False

    def replaceProxyList(self, proxies):
        """Clear everything and add all ``proxies``.

        :type proxies: A tuple, list, dict, or set.
        :param proxies: An iterable.  For each ``item`` in that iterable,
            ``item`` must either:
                1. be a string or int representing an IP address, or,
                2. be another iterable, whose first item satisfies #1.
        """
        try:
            self.clear()
            self.addProxies(proxies)
        except Exception as error:
            log.exception(error)

    _assigned=('__name__', '__doc__')

    @wraps(addProxies)
    def addExitRelays(self, relays):
        logging.info("Loading exit relays into ProxySet...")
        [self.add(x, 'exitlist') for x in relays]

    @wraps(MutableSet._hash)
    def __hash__(self):      return self._hash()
    def __iter__(self):      return self._proxies.__iter__()
    def __len__(self):       return len(self._proxydict.items())
    def __repr__(self):      return type('')(self.proxies)
    def __str__(self):       return os.linesep.join(self.proxies)
    update_wrapper(__iter__, set.__iter__, _assigned)
    update_wrapper(__len__,  len, _assigned)
    update_wrapper(__repr__, repr, _assigned)
    update_wrapper(__str__,  str, _assigned)

    def add(self, ip, value=True): self.__add__(ip, value)
    def copy(self):          return self.__class__(self._proxydict.copy())
    def contains(self, ip):  return self.__contains__(ip)
    def discard(self, ip):   self.__sub__(ip)
    def remove(self, other): return self.__sub__(other, ignoreErrors=False)
    update_wrapper(add,      __add__)
    update_wrapper(copy,     __init__)
    update_wrapper(contains, __contains__)
    update_wrapper(discard,  __sub__)
    update_wrapper(remove,   __sub__)

    def difference(self, other):   return self._proxies.difference(other)
    def issubset(self, other):     return self._proxies.issubset(other)
    def issuperset(self, other):   return self._proxies.issuperset(other)
    def intersection(self, other): return self._proxies.intersection(other)
    def symmetric_difference(self, other): self._proxies.symmetric_difference(other)
    def union(self, other):        return self._proxies.union(other)
    def update(self, other):       return self._proxies.update(other)
    update_wrapper(difference,           set.difference, _assigned)
    update_wrapper(issubset,             set.issubset, _assigned)
    update_wrapper(issuperset,           set.issuperset, _assigned)
    update_wrapper(intersection,         set.intersection, _assigned)
    update_wrapper(symmetric_difference, set.symmetric_difference, _assigned)
    update_wrapper(union,                set.union, _assigned)
    update_wrapper(update,               set.update, _assigned)


class ExitListProtocol(protocol.ProcessProtocol):
    """A :class:`~twisted.internet.protocol.Protocol` for ``get-exit-list``.

    :attr boolean connected: True if our ``transport`` is connected.

    :type transport: An implementer of
        :interface:`twisted.internet.interface.IProcessTransport`.
    :attr transport: If :func:`twisted.internet.reactor.spawnProcess` is
        called with an instance of this class as it's ``protocol``, then
        :func:`~twisted.internet.reactor.spawnProcess` will return this
        ``transport``.
    """

    def __init__(self, script):
        """Create a protocol for downloading a list of current Tor exit relays.

        :type exitlist: :class:`ProxySet`
        :ivar exitlist: A :class:`~collections.MutableSet` containing the IP
            addresses of known Tor exit relays which can reach our public IP
            address.
        :ivar list data: A list containing a ``bytes`` object for each chuck
            of data received from the ``transport``.
        :ivar deferred: A deferred which will callback with the ``exitlist``
            when the process has ended.

        :param string script: The full pathname of the script to run.
        """
        self.exitlist = ProxySet()
        self.data = []
        self.script = script
        self.deferred = defer.Deferred()

    def childConnectionLost(self, childFD):
        """See :func:`t.i.protocol.ProcessProtocol.childConnectionLost`."""
        protocol.ProcessProtocol.childConnectionLost(self, childFD)

    def connectionMade(self):
        """Called when a connection is made.

        This may be considered the initializer of the protocol, because it is
        called when the connection is completed.  For clients, this is called
        once the connection to the server has been established; for servers,
        this is called after an accept() call stops blocking and a socket has
        been received.  If you need to send any greeting or initial message,
        do it here.
        """
        logging.debug("ExitListProtocol: Connection made with remote server")
        self.transport.closeStdin()

    def errReceived(self, data):
        """Some data was received from stderr."""
        logging.error(data)

    def outReceived(self, data):
        """Some data was received from stdout."""
        self.data.append(data)

    def outConnectionLost(self):
        """This will be called when stdout is closed."""
        logging.debug("Finished downloading list of Tor exit relays.")
        self.transport.loseConnection()

        data = ''.join(self.data).split('\n')
        for line in data:
            line.strip()
            if not line: continue
            # If it reached an errorpage, then we grabbed raw HTML that starts
            # with an HTML tag:
            if line.startswith('<'): break
            if line.startswith('#'): continue
            ip = isIPAddress(line)
            if ip:
                logging.info("Discovered Tor exit relay: %s" % ip)
                self.exitlist.add(ip)
            else:
                logging.debug("Got exitlist line that wasn't an IP: %s" % line)
                continue

    def processEnded(self, reason):
        """Called when the child process exits and all file descriptors
        associated with it have been closed.

        :type reason: :class:`twisted.python.failure.Failure`
        """
        self.transport.loseConnection()
        if reason.value.exitCode != 0:
            logging.debug(reason.getTraceback())
            logging.error("There was an error downloading Tor exit list: %s"
                          % reason.value)
        else:
            logging.info("Finished processing list of Tor exit relays.")
        logging.debug("Transferring exit list to storage...")
        self.deferred.callback(list(self.exitlist.proxies))

    def processExited(self, reason):
        """This will be called when the subprocess exits.

        :type reason: :class:`twisted.python.failure.Failure`
        """
        logging.debug("ExitListProtocol: exited with status %d"
                      % reason.value.exitCode)
        if reason.value.exitCode != 0:
            self.processEnded(reason)

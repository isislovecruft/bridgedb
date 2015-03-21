# -*- coding: utf-8 -*-
#
# This file is part of BridgeDB, a Tor bridge distribution system.
#
# :authors: Isis Lovecruft 0xA3ADB67A2CDB8B35 <isis@torproject.org>
#           please also see AUTHORS file
# :copyright: (c) 2013-2015 Isis Lovecruft
#             (c) 2007-2015, The Tor Project, Inc.
#             (c) 2007-2015, all entities within the AUTHORS file
# :license: 3-clause BSD, see included LICENSE for information

"""Classes for finding and managing lists of open proxies."""

from __future__ import print_function
from collections import MutableSet
from functools import update_wrapper
from functools import wraps

import ipaddr
import logging
import os
import time

from twisted.internet import defer
from twisted.internet import protocol
from twisted.internet import reactor
from twisted.internet import utils as txutils
from bridgedb.runner import find
from bridgedb.parse.addr import isIPAddress


def downloadTorExits(proxyList, ipaddress, port=443, protocol=None):
    """Run a script which downloads a list of Tor exit relays which allow their
    clients to exit to the given **ipaddress** and **port**.

    :param proxyList: The :class:`ProxySet` instance from :mod:`bridgedb.Main`.
    :param str ipaddress: The IP address that each Tor exit relay should be
        capable of connecting to for clients, as specified by its ExitPolicy.
    :param int port: The port corresponding to the above **ipaddress** that
        each Tor exit relay should allow clients to exit to. (See
        https://check.torproject.org/cgi-bin/TorBulkExitList.py.)
    :type protocol: :api:`twisted.internet.protocol.Protocol`
    :param protocol: A :class:`~bridgedb.proxy.ExitListProtocol`, or any other
        :api:`~twisted.internet.protocol.Protocol` implementation for
        processing the results of a process which downloads a list of Tor exit
        relays. This parameter is mainly meant for use in testing, and should
        not be changed.
    :rtype: :class:`~twisted.internet.defer.Deferred`
    :returns: A deferred which will callback with a list, each item in the
        list is a string containing an IP of a Tor exit relay.
    """
    proto = ExitListProtocol() if protocol is None else protocol()
    args = [proto.script, '--stdout', '-a', ipaddress, '-p', str(port)]
    proto.deferred.addCallback(proxyList.addExitRelays)
    proto.deferred.addErrback(logging.exception)
    transport = reactor.spawnProcess(proto, proto.script, args=args, env={})
    return proto.deferred

def loadProxiesFromFile(filename, proxySet=None, removeStale=False):
    """Load proxy IP addresses from a list of files.

    :param str filename: A filename whose path can be either absolute or
        relative to the current working directory. The file should contain the
        IP addresses of various open proxies, one per line, for example::

            11.11.11.11
            22.22.22.22
            123.45.67.89

    :type proxySet: None or :class:`~bridgedb.proxy.ProxySet`.
    :param proxySet: If given, load the addresses read from the files into
        this ``ProxySet``.
    :param bool removeStale: If ``True``, remove proxies from the **proxySet**
        which were not listed in any of the **files**.
        (default: ``False``)
    :returns: A list of all the proxies listed in the **files* (regardless of
        whether they were added or removed).
    """
    logging.info("Reloading proxy lists...")

    addresses = []
    if proxySet:
        oldProxySet = proxySet.copy()

    try:
        with open(filename, 'r') as proxyFile:
            for line in proxyFile.readlines():
                line = line.strip()
                if proxySet:
                    # ProxySet.add() will validate the IP address
                    if proxySet.add(line, tag=filename):
                        logging.info("Added %s to the proxy list." % line)
                        addresses.append(line)
                else:
                    ip = isIPAddress(line)
                    if ip:
                        addresses.append(ip)
    except Exception as error:
        logging.warn("Error while reading a proxy list file: %s" % str(error))

    if proxySet:
        stale = list(oldProxySet.difference(addresses))

        if removeStale:
            for ip in stale:
                if proxySet.getTag(ip) == filename:
                    logging.info("Removing stale IP %s from proxy list." % ip)
                    proxySet.remove(ip)
                else:
                    logging.info("Tag %s didn't match %s"
                                 % (proxySet.getTag(ip), filename))

    return addresses


class ProxySet(MutableSet):
    """A :class:`collections.MutableSet` for storing validated IP addresses."""

    #: A tag to apply to IP addresses within this ``ProxySet`` which are known
    #: Tor exit relays.
    _exitTag = 'exit_relay'

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
    def proxies(self):
        """All proxies in this set, regardless of tags."""
        return list(self._proxies)

    @property
    def exitRelays(self):
        """Get all proxies in this ``ProxySet`` tagged as Tor exit relays.

        :rtype: set
        :returns: A set of all known Tor exit relays which are contained
            within this :class:`~bridgedb.proxy.ProxySet`.
        """
        return self.getAllWithTag(self._exitTag)

    def __add__(self, ip=None, tag=None):
        """Add an **ip** to this set, with an optional **tag**.

        This has no effect if the **ip** is already present.  The **ip** is
        only added if it passes the checks in
        :func:`~bridgedb.parse.addr.isIPAddress`.

        :type ip: basestring or int
        :param ip: The IP address to add.
        :param tag: An optional value to link to **ip**. If not given, it will
            be a timestamp (seconds since epoch, as a float) for when **ip**
            was first added to this set.
        :rtype: bool
        :returns: ``True`` if **ip** is in this set; ``False`` otherwise.
        """
        ip = isIPAddress(ip)
        if ip:
            if self._proxies.isdisjoint(set(ip)):
                logging.debug("Adding %s to proxy list %r..." % (ip, self))
                self._proxies.add(ip)
                self._proxydict[ip] = tag if tag else time.time()
                return True
        return False

    def __radd__(self, *args, **kwargs): self.__add__(*args, **kwargs)

    def __contains__(self, ip):
        """x.__contains__(y) <==> y in x.

        :type ip: basestring or int
        :param ip: The IP address to check.
        :rtype: boolean
        :returns: True if ``ip`` is in this set; False otherwise.
        """
        ipset = [isIPAddress(ip),]
        if ipset and len(self._proxies.intersection(ipset)) == len(ipset):
            return True
        return False

    def __sub__(self, ip):
        """Entirely remove **ip** from this set.

        :type ip: basestring or int
        :param ip: The IP address to remove.
        """
        try:
            self._proxydict.pop(ip)
            self._proxies.discard(ip)
        except KeyError:
            pass

    def __rsub__(self, *args, **kwargs): raise NotImplemented

    def _getErrorMessage(self, x=None, y=None):
        """Make an error message describing how this class works."""
        message = """\nParameter 'proxies' must be one of:
    - a {1} of {0}
    - a {2} of {0}
    - a {3}, whose keys are {0} (the values can be anything)
    - a {4} of {1}s, whose first object in each {1} must be a {0}
    - a {4} of {0}
        """.format(type(''), type(()), type([]), type({}), type(set(())))
        end = "You gave: a {0}".format(type(y))
        end += " of {0}".format(type(x))
        return os.linesep.join((message, end))

    def addProxies(self, proxies, tag=None):
        """Add proxies to this set.

        This calls :func:`add` for each item in the iterable **proxies**.
        Each proxy, if added, will be tagged with a current timestamp.

        :type proxies: A tuple, list, dict, or set.
        :param proxies: An iterable.  For each ``item`` in that iterable,
            ``item`` must either:
                1. be a string or int representing an IP address, or,
                2. be another iterable, whose first item satisfies #1.
        :keyword tag: An optional value to link to all untagged
            **proxies**. If ``None``, it will be a timestamp (seconds since
            epoch, as a float) for when the proxy was first added to this set.
        """
        if isinstance(proxies, dict):
            [self.add(ip, value) for (ip, value) in proxies.items()]
        else:
            try:
                for x in proxies:
                    if isinstance(x, (tuple, list, set)):
                        if len(x) == 2:   self.add(x[0], x[1])
                        elif len(x) == 1: self.add(x, tag)
                        else: raise ValueError(self._getErrorMessage(x, proxies))
                    elif isinstance(x, (basestring, int)):
                        self.add(x, tag)
                    else:
                        raise ValueError(self._getErrorMessage(x, proxies))
            except TypeError:
                raise ValueError(self._getErrorMessage(proxies, None))

    @wraps(addProxies)
    def addExitRelays(self, relays):
        logging.info("Loading exit relays into proxy list...")
        [self.add(x, self._exitTag) for x in relays]

    def getTag(self, ip):
        """Get the tag for an **ip** in this ``ProxySet``, if available.

        :type ip: basestring or int
        :param ip: The IP address to obtain the tag for.
        :rtype: ``None`` or basestring or int
        :returns: The tag for that **ip**, iff **ip** exists in this
            ``ProxySet`` and it has a tag.
        """
        return self._proxydict.get(ip)

    def getAllWithTag(self, tag):
        """Get all proxies in this ``ProxySet`` with a given tag.

        :param basestring tag: A tag to search for.
        :rtype: set
        :returns: A set of all proxies which are contained within this
            :class:`~bridgedb.proxy.ProxySet` which are also tagged with
            **tag**.
        """
        return set([key for key, value in filter(lambda x: x[1] == tag,
                                                 self._proxydict.items())])

    def firstSeen(self, ip):
        """Get the timestamp when **ip** was first seen, if available.

        :type ip: basestring or int
        :param ip: The IP address to obtain a timestamp for.
        :rtype: float or None
        :returns: The timestamp (in seconds since epoch) if available.
            Otherwise, returns None.
        """
        when = self.getTag(ip)
        if isinstance(when, float):
            return when

    def isExitRelay(self, ip):
        """Check if ``ip`` is a known Tor exit relay.

        :type ip: basestring or int
        :param ip: The IP address to check.
        :rtype: boolean
        :returns: True if ``ip`` is a known Tor exit relay; False otherwise.
        """
        if self.getTag(ip) == self._exitTag:
            return True
        return False

    def replaceProxyList(self, proxies, tag=None):
        """Clear everything and add all ``proxies``.

        :type proxies: A tuple, list, dict, or set.
        :param proxies: An iterable.  For each ``item`` in that iterable,
            ``item`` must either:
                1. be a string or int representing an IP address, or,
                2. be another iterable, whose first item satisfies #1.
        """
        try:
            self.clear()
            self.addProxies(proxies, tag=tag)
        except Exception as error:
            logging.error(str(error))

    _assigned = ('__name__', '__doc__')

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

    def add(self, ip, tag=None): return self.__add__(ip, tag)
    def copy(self):              return self.__class__(self._proxydict.copy())
    def contains(self, ip):      return self.__contains__(ip)
    def discard(self, ip):       return self.__sub__(ip)
    def remove(self, other):     return self.__sub__(other)
    update_wrapper(add,          __add__)
    update_wrapper(copy,         __init__)
    update_wrapper(contains,     __contains__)
    update_wrapper(discard,      __sub__)
    update_wrapper(remove,       __sub__)

    def difference(self, other):           return self._proxies.difference(other)
    def issubset(self, other):             return self._proxies.issubset(other)
    def issuperset(self, other):           return self._proxies.issuperset(other)
    def intersection(self, other):         return self._proxies.intersection(other)
    def symmetric_difference(self, other): return self._proxies.symmetric_difference(other)
    def union(self, other):                return self._proxies.union(other)
    update_wrapper(difference,             set.difference, _assigned)
    update_wrapper(issubset,               set.issubset, _assigned)
    update_wrapper(issuperset,             set.issuperset, _assigned)
    update_wrapper(intersection,           set.intersection, _assigned)
    update_wrapper(symmetric_difference,   set.symmetric_difference, _assigned)
    update_wrapper(union,                  set.union, _assigned)


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

    def __init__(self):
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
        self.data = []
        self.script = find('get-tor-exits')
        self.exitlist = ProxySet()
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
        # The get-exit-list script uses twisted.python.log to log to stderr:
        logging.debug(data)  # pragma: no cover

    def outReceived(self, data):
        """Some data was received from stdout."""
        self.data.append(data)

    def outConnectionLost(self):
        """This will be called when stdout is closed."""
        logging.debug("Finished downloading list of Tor exit relays.")
        self.transport.loseConnection()
        self.parseData()

    def parseData(self):
        """Parse all data received so far into our
        :class:`<bridgedb.proxy.ProxySet> exitlist`.
        """
        unparseable = []

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
                unparseable.append(line)

        if unparseable:
            logging.warn(("There were unparseable lines in the downloaded "
                          "list of Tor exit relays: %r") % unparseable)

    def processEnded(self, reason):
        """Called when the child process exits and all file descriptors
        associated with it have been closed.

        :type reason: :class:`twisted.python.failure.Failure`
        """
        self.transport.loseConnection()
        if reason.value.exitCode != 0:  # pragma: no cover
            logging.debug(reason.getTraceback())
            logging.error("There was an error downloading Tor exit list: %s"
                          % reason.value)
        else:
            logging.info("Finished processing list of Tor exit relays.")
        logging.debug("Transferring exit list to storage...")
        # Avoid triggering the deferred twice, e.g. on processExited():
        if not self.deferred.called:
            self.deferred.callback(list(self.exitlist.proxies))

    def processExited(self, reason):
        """This will be called when the subprocess exits.

        :type reason: :class:`twisted.python.failure.Failure`
        """
        logging.debug("%s exited with status code %d"
                      % (self.script, reason.value.exitCode))

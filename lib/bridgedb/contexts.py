# -*- coding: utf-8 -*-
#
# This file is part of BridgeDB, a Tor bridge distribution system.
# 
# :authors: Isis Lovecruft 0xA3ADB67A2CDB8B35 <isis@torproject.org>
# :copyright: (c) 2007-2013, The Tor Project, Inc.
#             (c) 2007-2013, all entities within the AUTHORS file
# :license: 3-Clause BSD, see LICENSE for licensing information

"""contexts.py - contexts for tracking distribution metrics in BridgeDB"""

from twisted.python     import context
from twisted.python.log import ILogContext
from zope.interface     import implements

from bridgedb import config


class DistributorContextTracker(context.ContextTracker):
    """Track the contexts for all known bridge distribution mechanisms.

    >>> from bridgedb.contexts import HTTPSDistributorContext, call, get
    >>> from bridgedb import log
    >>> call(HTTPSDistributorContext, log.msg, ")

    XXX do we need to subclass context.ThreadedContextTracker instead?
    """

    def __init__(self, contexts):
        """Create a context tracker for the available distribution mechanisms.

        :param list contexts: A list of classes which are derived from
            :class:`DistributorContext`.
        """
        self.contexts = contexts

    def getContext(self, distContext, key=None, default=None):
        """Retrieve the value for a key from the context.

        :param distContext: The ``DistributorContext.name`` of the context for
            which we would like to retrieve the value of ``key``.
        :param key: The key to retrieve from the context.
        :param default: The value to return if ``key`` is not found in the context.
        """
        for ctx in self.contexts:
            if ctx.name == distContext.name:
                if key:
                    try: return ctx[key]
                    except KeyError: return default
                return ctx
        return default

class AssignmentContext(config.Conf):
    """Context for storing assignment metrics.

    Used for storing bridgepool assignment data within a
    :class:`bridgedb.context.DistributorContext`. 

    See https://metrics.torproject.org/formats.html#bridgepool .
    """
    implements(ILogContext)

    def __init__(self, fpr=None, pool=None, inet=None, ring=None, port=None,
                 transport=None):
        """Create a context for storing bridgepool assignment info.

        Bridge pool assignments are in the following form:

        | <SHA-1 hash of identity fingerprint>    <pool> <inets> <ring> <flags> <port> <transport>
        | 19a556b4376cc316e98da2165bf5745e49742813 https ip=4 ring=4 flag=stable port=443
        | 19a556b4376cc316e98da2165bf5745e49742813 https ip=4 ring=4 flag=stable transport=obfs3,obfs2 port=443

        :param str fpr: The bridge's fingerprint.
        :param str pool: The pool which the bridge was assigned to,
            i.e. 'https', 'email', or 'unallocated'.
        :param set inet: A set of integer(s) for the IP families which this
            bridge accepts connections on.
        :param int ring: A number corresponding to a subring which the bridge
            has been assigned to.
        :param set flags: The flags assigned to this descriptor by the
            directory authorities.
        :param int port: The bridge's ORPort.
        :param set transport: A set of transport type which the bridge
            supports.
        """
        ## XXX TODO get sysrqb's parses from https://trac.torproject.org/projects/tor/ticket/8614
        assignment = {
            'fingerprint': fpr if isinstance(fpr, str) else str(),
            'pool':        pool if isinstance(pool, str) else str(),
            'inet':        inet if isinstance(inet, set) else set(),
            'ring':        ring if isinstance(ring, int) else int(),
            'port':        port if isinstance(port, int) else int(),
            'flags':       flags if isinstance(flags, set) else set(),
            'transport':   transport if isinstance(transport, set) else set() }
        super(AssignmentContext, self).__init__(**assignment)

class RequestContext(config.Conf):
    """A context for storing metrics on requests for bridges."""
    implements(ILogContext)

    def __init__(self, total=None,
                 total_ip=None, unique_ip=None, hashed_ip=None,
                 total_email=None, unique_email=None, hashed_email=None):
        request = {
            'total':    total if isinstance(total, int) else int(),
            'total_ip': total_ip if isinstance(total_ip, int) else int(),
            'unique_ip': unique_ip if isinstance(unique_ip, int) else int(),
            'hashed_ip': hashed_ip if isinstance(hashed_ip, set) else set(),
            'total_email': total_email if isinstance(total_email, int) else int(),
            'unique_email': unique_email if isinstance(unique_email, int) else int(),
            'hashed_email': hashed_email if isinstance(hashed_email, set) else set() }
        super(RequestContext, self).__init__(**request)

class DistributorContext(config.Conf):
    """A context for storing and logging metrics for a bridge distributor.

    This can be used to automate the storing of information pertaining to a
    specific bridge distributor, i.e. the HTTPS distributor or the email
    distributor, which are relevant for agregating metrics. In simpler terms,
    rather than grepping bridge extra-info descriptors for
    ``geoip-client-origins`` (this became ``bridge-ips`` in tor>0.2.2.3-alpha)
    lines and then adding up all the countries, we should keep totals here.
    """
    implements(ILogContext)

    def __init__(self, name=None, assignments=None, requests=None):
        self.name = name
        if not assignments: assignments = list()
        if not requests: requests = RequestContext()
        self.assignments = assignments
        self.requests = requests

## The distributors, i.e. the available distribution methods:
try: HTTPSDistributorContext
except NameError: HTTPSDistributorContext = DistributorContext('https')

try: EmailDistributorContext
except NameError: EmailDistributorContext = DistributorContext('email')

try: UnallocatedContext
except NameError: UnallocatedContext = DistributorContext('unallocated')

context.installContextTracker(BridgeDBContextTracker([HTTPSDistributorContext,
                                                      EmailDistributorContext,
                                                      UnallocatedContext]))

def logAssignment(distributor, ctx, func, *args, **kwargs):
    """Log a bridge assignment and record it for that distibutor.

    :param str distributor: The :class:`DistributorContext` to log the
        assignment under.
    """
    newContext = context.get(distributor).copy()
    newContext.update(ctx)
    return context.call({distributor: newContext}, func, *args, **kwargs)

# -*- coding: utf-8 -*-
#
# This file is part of BridgeDB, a Tor bridge distribution system.
#
# :authors: Isis Lovecruft 0xA3ADB67A2CDB8B35 <isis@torproject.org>
#           please also see AUTHORS file
# :copyright: (c) 2013, Isis Lovecruft
#             (c) 2007-2013, The Tor Project, Inc.
#             (c) 2007-2013, all entities within the AUTHORS file
# :license: see LICENSE for licensing information


"""Helpers for testing the email distributor and its servers."""


import io

from bridgedb.Dist import IgnoreEmail
from bridgedb.Dist import TooSoonEmail
from bridgedb.persistent import Conf
from bridgedb.email.server import MailServerContext
from bridgedb.schedule import Unscheduled
from bridgedb.test.test_HTTPServer import DummyBridge


EMAIL_DIST = True
EMAIL_INCLUDE_FINGERPRINTS = True
EMAIL_GPG_SIGNING_ENABLED = True
EMAIL_GPG_HOMEDIR = '.gnupg'
EMAIL_GPG_PRIMARY_KEY_FINGERPRINT = '0017098C5DF4197E3C884DCFF1B240D43F148C21'
EMAIL_GPG_PASSPHRASE = None
EMAIL_GPG_PASSPHRASE_FILE = None
EMAIL_DOMAIN_MAP = {
   'googlemail.com': 'gmail.com',
   'mail.google.com': 'gmail.com',
}
EMAIL_DOMAIN_RULES = {
   'gmail.com': ["ignore_dots", "dkim"],
   'example.com': [],
   'localhost': [],
}
EMAIL_DOMAINS = ["gmail.com", "example.com", "localhost"]
EMAIL_WHITELIST = {'white@list.ed': 'ABCD1234ABCD1234ABCD1234ABCD1234ABCD1234'}
EMAIL_BLACKLIST = ['feidanchaoren0001@gmail.com']
EMAIL_FUZZY_MATCH = 4
EMAIL_USERNAME = "bridges"
EMAIL_SMTP_HOST = "127.0.0.1"
EMAIL_SMTP_PORT = 25
EMAIL_SMTP_FROM_ADDR = "bridges@localhost"
EMAIL_N_BRIDGES_PER_ANSWER = 3
EMAIL_FROM_ADDR = "bridges@localhost"
EMAIL_BIND_IP = "127.0.0.1"
EMAIL_PORT = 5225

TEST_CONFIG_FILE = io.StringIO(unicode("""\
EMAIL_DIST = %s
EMAIL_INCLUDE_FINGERPRINTS = %s
EMAIL_GPG_SIGNING_ENABLED = %s
EMAIL_GPG_HOMEDIR = %s
EMAIL_GPG_PRIMARY_KEY_FINGERPRINT = %s
EMAIL_GPG_PASSPHRASE = %s
EMAIL_GPG_PASSPHRASE_FILE = %s
EMAIL_DOMAIN_MAP = %s
EMAIL_DOMAIN_RULES = %s
EMAIL_DOMAINS = %s
EMAIL_WHITELIST = %s
EMAIL_BLACKLIST = %s
EMAIL_FUZZY_MATCH = %s
EMAIL_USERNAME = %s
EMAIL_SMTP_HOST = %s
EMAIL_SMTP_PORT = %s
EMAIL_SMTP_FROM_ADDR = %s
EMAIL_N_BRIDGES_PER_ANSWER = %s
EMAIL_FROM_ADDR = %s
EMAIL_BIND_IP = %s
EMAIL_PORT = %s
""" % (repr(EMAIL_DIST),
       repr(EMAIL_INCLUDE_FINGERPRINTS),
       repr(EMAIL_GPG_SIGNING_ENABLED),
       repr(EMAIL_GPG_HOMEDIR),
       repr(EMAIL_GPG_PRIMARY_KEY_FINGERPRINT),
       repr(EMAIL_GPG_PASSPHRASE),
       repr(EMAIL_GPG_PASSPHRASE_FILE),
       repr(EMAIL_DOMAIN_MAP),
       repr(EMAIL_DOMAIN_RULES),
       repr(EMAIL_DOMAINS),
       repr(EMAIL_WHITELIST),
       repr(EMAIL_BLACKLIST),
       repr(EMAIL_FUZZY_MATCH),
       repr(EMAIL_USERNAME),
       repr(EMAIL_SMTP_HOST),
       repr(EMAIL_SMTP_PORT),
       repr(EMAIL_SMTP_FROM_ADDR),
       repr(EMAIL_N_BRIDGES_PER_ANSWER),
       repr(EMAIL_FROM_ADDR),
       repr(EMAIL_BIND_IP),
       repr(EMAIL_PORT))))


def _createConfig(configFile=TEST_CONFIG_FILE):
    configuration = {}
    TEST_CONFIG_FILE.seek(0)
    compiled = compile(configFile.read(), '<string>', 'exec')
    exec compiled in configuration
    config = Conf(**configuration)
    return config

def _createMailServerContext(config=None, distributor=None):
    if not config:
        config = _createConfig()

    if not distributor:
        distributor = DummyEmailDistributor(
            domainmap=config.EMAIL_DOMAIN_MAP,
            domainrules=config.EMAIL_DOMAIN_RULES)

    context = MailServerContext(config, distributor, Unscheduled())
    return context


class DummyEmailDistributor(object):
    """A mocked :class:`bridgedb.Dist.EmailBasedDistributor` which is used to
    test :class:`bridgedb.EmailServer`.
    """

    def __init__(self, key=None, domainmap=None, domainrules=None,
                 answerParameters=None):
        """None of the parameters are really used, ― they are just there to retain an
        identical method signature.
        """
        self.key = self.__class__.__name__
        self.domainmap = domainmap
        self.domainrules = domainrules
        self.answerParameters = answerParameters

    def getBridgesForEmail(self, emailaddress, epoch, N=1, parameters=None,
                           countryCode=None, bridgeFilterRules=None):
        return [DummyBridge() for _ in xrange(N)]

    def cleanDatabase(self):
        pass


class DummyEmailDistributorWithState(DummyEmailDistributor):
    """A mocked :class:`bridgedb.Dist.EmailBasedDistributor` which raises
    :exc:`bridgedb.Dist.TooSoonEmail` on the second email and
    :exc:`bridgedb.Dist.IgnoreEmail` on the third.

    Note that the state tracking is done in a really dumb way. For example, we
    currently don't consider requests for help text or GnuPG keys to be a
    "real" request, so in the real email distributor they won't trigger either
    a TooSoonEmail or IgnoreEmail. Here we only track the total number of
    *any* type of request per client.
    """

    def __init__(self, *args, **kwargs):
        super(DummyEmailDistributorWithState, self).__init__()
        self.alreadySeen = {}

    def getBridgesForEmail(self, emailaddress, epoch, N=1, parameters=None,
                           countryCode=None, bridgeFilterRules=None):
        # Keep track of the number of times we've seen a client.
        if not emailaddress in self.alreadySeen.keys():
            self.alreadySeen[emailaddress] = 0
        self.alreadySeen[emailaddress] += 1

        if self.alreadySeen[emailaddress] <= 1:
            return [DummyBridge() for _ in xrange(N)]
        elif self.alreadySeen[emailaddress] == 2:
            raise TooSoonEmail(
                "Seen client '%s' %d times"
                % (emailaddress, self.alreadySeen[emailaddress]),
                emailaddress)
        else:
            raise IgnoreEmail(
                "Seen client '%s' %d times"
                % (emailaddress, self.alreadySeen[emailaddress]),
                emailaddress)

# -*- coding: utf-8 -*-
#
# This file is part of BridgeDB, a Tor bridge distribution system.
#
# :authors: Isis Lovecruft 0xA3ADB67A2CDB8B35 <isis@torproject.org>
#           please also see AUTHORS file
# :copyright: (c) 2013, Isis Lovecruft
#             (c) 2007-2013, The Tor Project, Inc.
#             (c) 2007-2013, all entities within the AUTHORS file
# :license: 3-Clause BSD, see LICENSE for licensing information

"""Unittests for the :mod:`bridgedb.email.templates` module."""

from __future__ import print_function
from __future__ import unicode_literals

from io import StringIO
from gettext import NullTranslations

from twisted.mail.smtp import Address
from twisted.trial import unittest

from bridgedb.email import templates


class EmailTemplatesTests(unittest.TestCase):
    """Unittests for :func:`b.e.templates`."""

    def setUp(self):
        self.t = NullTranslations(StringIO(unicode('test')))
        self.client = Address('blackhole@torproject.org')
        self.answer = 'obfs3 1.1.1.1:1111\nobfs3 2.2.2.2:2222'
        # This is the fingerprint of BridgeDB's offline, certification-only
        # GnuPG key. It should be present in any responses to requests for our
        # public keys.
        self.offlineFingerprint = '7B78437015E63DF47BB1270ACBD97AA24E8E472E'

    def shouldIncludeCommands(self, text):
        self.assertSubstring('COMMANDs', text)

    def shouldIncludeInstructions(self, text):
        self.assertSubstring('Tor Browser', text)

    def shouldIncludeBridges(self, text):
        self.assertSubstring(self.answer, text)
        self.assertSubstring('Here are your bridges:', text)

    def shouldIncludeGreeting(self, text):
        self.assertSubstring('Hey, blackhole!', text)

    def shouldIncludeAutomationNotice(self, text):
        self.assertSubstring('automated message', text)

    def shouldIncludeKey(self, text):
        self.assertSubstring('-----BEGIN PGP PUBLIC KEY BLOCK-----', text)

    def shouldIncludeFooter(self, text):
        self.assertSubstring('rainbows, unicorns, and sparkles', text)

    def test_templates_addCommands(self):
        text = templates.addCommands(self.t)
        self.shouldIncludeCommands(text)

    def test_templates_addGreeting(self):
        text = templates.addGreeting(self.t, self.client.local)
        self.shouldIncludeGreeting(text)

    def test_templates_addGreeting_noClient(self):
        text = templates.addGreeting(self.t, None)
        self.assertSubstring('Hello, friend!', text)

    def test_templates_addGreeting_withWelcome(self):
        text = templates.addGreeting(self.t, self.client.local, welcome=True)
        self.shouldIncludeGreeting(text)
        self.assertSubstring('Welcome to BridgeDB!', text)

    def test_templates_addGreeting_trueClient(self):
        text = templates.addGreeting(self.t, True)
        self.assertSubstring('Hey', text)

    def test_templates_addGreeting_23Client(self):
        text = templates.addGreeting(self.t, 23)
        self.assertSubstring('Hey', text)

    def test_templates_addHowto(self):
        text = templates.addHowto(self.t)
        self.shouldIncludeInstructions(text)

    def test_templates_addBridgeAnswer(self):
        text = templates.addBridgeAnswer(self.t, self.answer)
        self.shouldIncludeBridges(text)

    def test_templates_addFooter(self):
        text = templates.addFooter(self.t, self.client)
        self.shouldIncludeFooter(text)

    def test_templates_buildAnswerMessage(self):
        text = templates.buildAnswerMessage(self.t, self.client, self.answer)
        self.assertSubstring(self.answer, text)
        self.shouldIncludeAutomationNotice(text)
        self.shouldIncludeCommands(text)
        self.shouldIncludeFooter(text)

    def test_templates_buildKeyMessage(self):
        text = templates.buildKeyMessage(self.t, self.client)
        self.assertSubstring(self.offlineFingerprint, text)

    def test_templates_buildWelcomeText(self):
        text = templates.buildWelcomeText(self.t, self.client)
        self.shouldIncludeGreeting(text)
        self.assertSubstring('Welcome to BridgeDB!', text)
        self.shouldIncludeCommands(text)
        self.shouldIncludeFooter(text)

    def test_templates_buildSpamWarning(self):
        text = templates.buildSpamWarning(self.t, self.client)
        self.shouldIncludeGreeting(text)
        self.shouldIncludeAutomationNotice(text)
        self.shouldIncludeFooter(text)

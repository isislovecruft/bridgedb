# -*- coding: utf-8 ; test-case-name: bridgedb.test.test_email_templates -*-
#_____________________________________________________________________________
#
# This file is part of BridgeDB, a Tor bridge distribution system.
#
# :authors: Isis Lovecruft <isis@torproject.org> 0xA3ADB67A2CDB8B35
#           please also see AUTHORS file
# :copyright: (c) 2007-2014, The Tor Project, Inc.
#             (c) 2013-2014, Isis Lovecruft
# :license: see LICENSE for licensing information
#_____________________________________________________________________________

"""Templates for formatting emails sent out by the email distributor."""

from __future__ import print_function
from __future__ import unicode_literals

import logging
import os

from bridgedb import strings
from bridgedb.Dist import MAX_EMAIL_RATE
from bridgedb.HTTPServer import TEMPLATE_DIR


def buildCommands(template):
    # Tell them about the various email commands:
    cmdlist = []
    cmdlist.append(template.gettext(strings.EMAIL_MISC_TEXT.get(3)))
    for cmd, desc in strings.EMAIL_COMMANDS.items():
        command  = '  '
        command += cmd
        while not len(command) >= 25:  # Align the command descriptions
            command += ' '
        command += template.gettext(desc)
        cmdlist.append(command)

    commands  = "\n".join(cmdlist) + "\n\n"
    # And include the currently supported transports:
    commands += template.gettext(strings.EMAIL_MISC_TEXT.get(5))
    commands += "\n"
    for pt in strings.CURRENT_TRANSPORTS:
        commands += '  ' + pt + "\n"

    return commands

def buildHowto(template):
    howToTBB  = template.gettext(strings.HOWTO_TBB[1]) % strings.EMAIL_SPRINTF["HOWTO_TBB1"]
    howToTBB += u'\n\n'
    howToTBB += template.gettext(strings.HOWTO_TBB[2])
    howToTBB += u'\n\n'
    howToTBB += u'\n'.join(["> {0}".format(ln) for ln in
                            template.gettext(strings.HOWTO_TBB[3]).split('\n')])
    howToTBB += u'\n\n'
    howToTBB += template.gettext(strings.HOWTO_TBB[4])
    howToTBB += u'\n\n'
    howToTBB += strings.EMAIL_REFERENCE_LINKS.get("HOWTO_TBB1")
    howToTBB += u'\n\n'
    return howToTBB

def buildKeyfile(template):
    filename = os.path.join(TEMPLATE_DIR, 'bridgedb.asc')

    try:
        with open(filename) as fh:
            keyFile  = fh.read()
    except Exception as error:  # pragma: no cover
        logging.exception(error)
        keyFile = u''
    else:
        keyFile += u'\n\n'

    return keyFile

def buildWelcomeText(template):
    sections = []
    sections.append(template.gettext(strings.EMAIL_MISC_TEXT[4]))

    commands = buildCommands(template)
    sections.append(commands)

    # Include the same messages as the homepage of the HTTPS distributor:
    welcome  = template.gettext(strings.WELCOME[0]) % strings.EMAIL_SPRINTF["WELCOME0"]
    welcome += template.gettext(strings.WELCOME[1])
    welcome += template.gettext(strings.WELCOME[2]) % strings.EMAIL_SPRINTF["WELCOME2"]
    sections.append(welcome)

    message  = u"\n\n".join(sections)
    # Add the markdown links at the end:
    message += strings.EMAIL_REFERENCE_LINKS.get("WELCOME0")
    message += u"\n"

    return message

def buildBridgeAnswer(template):
    # Give the user their bridges, i.e. the `answer`:
    message = template.gettext(strings.EMAIL_MISC_TEXT[0]) + u"\n\n" \
              + template.gettext(strings.EMAIL_MISC_TEXT[1]) + u"\n\n" \
              + u"%s\n\n"
    return message

def buildMessage(template):
    message = None
    try:
        message  = buildBridgeAnswer(template)
        message += buildHowto(template)
        message += u'\n\n'
        message += buildCommands(template)
    except Exception as error:  # pragma: no cover
        logging.error("Error while formatting email message template:")
        logging.exception(error)
    return message

def buildSpamWarning(template):
    message = None
    try:
        message = template.gettext(strings.EMAIL_MISC_TEXT[0]) + u"\n\n" \
                  + template.gettext(strings.EMAIL_MISC_TEXT[2]) + u"\n"
        message = message % str(MAX_EMAIL_RATE / 3600)
    except Exception as error:  # pragma: no cover
        logging.error("Error while formatting email spam template:")
        logging.exception(error)
    return message

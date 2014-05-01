# BridgeDB i18n strings & helper routines. The string should go into pootle

import os
import gettext

def getLang(lang, localedir=os.path.expanduser("~") + "/share/locale"):
    """Return the Translation instance for a given language. If no Translation
       instance is found, return the one for 'en'
    """
    return gettext.translation("bridgedb", localedir=localedir, 
                               languages=[lang], fallback="en")

def _(text):
    """This is necessary because strings are translated when they're imported.
    Otherwise this would make it impossible to switch languages more than
    once.

    :returns: The **text**.
    """
    return text

# All text that needs translation goes here
BRIDGEDB_TEXT = [
    # BRIDGEDB_TEXT[0]
    _("""[This is an automated message; please do not reply.]"""),
    # BRIDGEDB_TEXT[1]
    _("""Here are your bridge relays: """),
    # BRIDGEDB_TEXT[2]
    _("""\
Bridge relays (or "bridges" for short) are Tor relays that aren't listed
in the main directory. Since there is no complete public list of them,
even if your ISP is filtering connections to all the known Tor relays,
they probably won't be able to block all the bridges."""),
    # BRIDGEDB_TEXT[3]
    _("""\
To use the above lines, go to Vidalia's Network settings page, and click
"My ISP blocks connections to the Tor network". Then add each bridge
address one at a time."""),
    # BRIDGEDB_TEXT[4]
    _("""\
Configuring more than one bridge address will make your Tor connection
more stable, in case some of the bridges become unreachable."""),
    # BRIDGEDB_TEXT[5]
    _("""The following commands are also supported:"""),
    # BRIDGEDB_TEXT[6]
    _("""ipv6 : request ipv6 bridges."""),
    # BRIDGEDB_TEXT[7]
    _("""transport NAME : request transport NAME. Example: 'transport obfs2'"""),
    # BRIDGEDB_TEXT[8]
    _("""\
You have exceeded the rate limit. Please slow down! The minimum time between
emails is %s hours. All further emails will be ignored."""),
]

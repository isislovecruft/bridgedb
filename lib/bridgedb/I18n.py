# BridgeDB i18n strings & helper routines. The string should go into pootle

import gettext

languages = {}

def setupLanguages(cfg):
    """Set up all languages we support
    """
    for lang in cfg.CONFIGURED_LOCALES:
        languages[lang] = gettext.translation("bridgedb", languages=[lang])

def _(text):
    """This is necessary because strings are translated when they're imported.
       Otherwise this would make it impossible to switch languages more than 
       once
    """
    return text

# All text that needs translation goes here
BRIDGEDB_TEXT = [
        _("""
    Here are your bridge relays:
    """),
        _("""
    Bridge relays (or "bridges" for short) are Tor relays that aren't listed
    in the main directory. Since there is no complete public list of them,
    even if your ISP is filtering connections to all the known Tor relays,
    they probably won't be able to block all the bridges.
    """),
        _("""
    To use the above lines, go to Vidalia's Network settings page, and click
    "My ISP blocks connections to the Tor network". Then add each bridge
    address one at a time.
    """),
        _("""
    Configuring more than one bridge address will make your Tor connection
    more stable, in case some of the bridges become unreachable.
    """),
        _("""
    Another way to find public bridge addresses is to send mail to
    bridges@torproject.org with the line "get bridges" by itself in the body
    of the mail. However, so we can make it harder for an attacker to learn
    lots of bridge addresses, you must send this request from a gmail or
    yahoo account.
    """),
        _("""
[This is an automated message; please do not reply.]
    """),
        _("""
Here are your bridge relays:
    """),
        _("""
Bridge relays (or "bridges" for short) are Tor relays that aren't listed
in the main directory. Since there is no complete public list of them,
even if your ISP is filtering connections to all the known Tor relays,
they probably won't be able to block all the bridges.
    """),
        _("""
To use the above lines, go to Vidalia's Network settings page, and click
"My ISP blocks connections to the Tor network". Then add each bridge
address one at a time.
    """),
        _("""
Configuring more than one bridge address will make your Tor connection
more stable, in case some of the bridges become unreachable.
    """),
        _("""
Another way to find public bridge addresses is to visit
https://bridges.torproject.org/. The answers you get from that page
will change every few days, so check back periodically if you need more
bridge addresses.
    """),
        _("(no bridges currently available)")
]

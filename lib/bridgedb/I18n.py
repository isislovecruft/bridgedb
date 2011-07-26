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
       once
    """
    return text

# All text that needs translation goes here
BRIDGEDB_TEXT = [
 # BRIDGEDB_TEXT[0]
 _("""Here are your bridge relays: """),
 # BRIDGEDB_TEXT[1]
 _("""Bridge relays (or "bridges" for short) are Tor relays that aren't listed
in the main directory. Since there is no complete public list of them,
even if your ISP is filtering connections to all the known Tor relays,
they probably won't be able to block all the bridges."""),
 # BRIDGEDB_TEXT[2]
 _("""To use the above lines, go to Vidalia's Network settings page, and click
"My ISP blocks connections to the Tor network". Then add each bridge
address one at a time."""),
 # BRIDGEDB_TEXT[3]
 _("""Configuring more than one bridge address will make your Tor connection
more stable, in case some of the bridges become unreachable."""),
 # BRIDGEDB_TEXT[4]
 _("""Another way to find public bridge addresses is to send mail to
bridges@torproject.org with the line "get bridges" by itself in the body
of the mail. However, so we can make it harder for an attacker to learn
lots of bridge addresses, you must send this request from an email address at
one of the following domains:"""),
 # BRIDGEDB_TEXT[5]
 _("""[This is an automated message; please do not reply.]"""),
 # BRIDGEDB_TEXT[6]
 _("""Another way to find public bridge addresses is to visit
https://bridges.torproject.org/. The answers you get from that page
will change every few days, so check back periodically if you need more
bridge addresses."""),
 # BRIDGEDB_TEXT[7]
 _("""(no bridges currently available)"""),
 # BRIDGEDB_TEXT[8]
 _("""(e-mail requests not currently supported)"""),
 # BRIDGEDB_TEXT[9]
 _("""To receive your bridge relays, please prove you are human"""),
 # BRIDGEDB_TEXT[10]
 _("""You have exceeded the rate limit. Please slow down, the minimum time between
emails is: """),
 # BRIDGEDB_TEXT[11]
 _("""hours"""),
 # BRIDGEDB_TEXT[12]
 _("""All further emails will be ignored.""")
]

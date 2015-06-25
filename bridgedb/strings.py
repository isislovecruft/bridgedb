# -*- coding: utf-8 ; test-case-name: bridgedb.test.test_strings ; -*-
#
# This file is part of BridgeDB, a Tor bridge distribution system.
#
# :authors: Isis Lovecruft 0xA3ADB67A2CDB8B35 <isis@torproject.org>
# :copyright: (c) 2007-2015, The Tor Project, Inc.
#             (c) 2013-2015, Isis Lovecruft
#             (c) 2007-2015, all entities within the AUTHORS file
# :license: 3-clause BSD, see included LICENSE for information

"""Commonly used string constants.

.. todo:: The instructions for the OpenPGP keys in
    :data:`BRIDGEDB_OPENPGP_KEY` are not translated… should we translate them?
    Should we tell users where to obtain GPG4Win/GPGTools/gnupg?  Should those
    instruction be that verbose?  Or should we get rid of the instructions
    altogether, and assume that any encouragement towards using GPG will just
    make users more frustrated, and (possibly) (mis-)direct that frustration
    at Tor or BridgeDB?
"""

from __future__ import unicode_literals

# This won't work on Python2.6, however
#     1) We don't use Python2.6, and
#     2) We don't care about supporting Python2.6, because Python 2.6 (and,
#        honestly, all of Python2) should die.
from collections import OrderedDict


def _(text):
    """This is necessary because strings are translated when they're imported.
    Otherwise this would make it impossible to switch languages more than
    once.

    :returns: The **text**.
    """
    return text


# TRANSLATORS: Please do not translate the word "TYPE".
EMAIL_MISC_TEXT = {
    0: _("""\
[This is an automated message; please do not reply.]"""),
    1: _("""\
Here are your bridges:"""),
    2: _("""\
You have exceeded the rate limit. Please slow down! The minimum time between
emails is %s hours. All further emails during this time period will be ignored."""),
    3: _("""\
COMMANDs: (combine COMMANDs to specify multiple options simultaneously)"""),
    # TRANSLATORS: Please DO NOT translate the word "BridgeDB".
    4: _("Welcome to BridgeDB!"),
    # TRANSLATORS: Please DO NOT translate the words "transport" or "TYPE".
    5: _("Currently supported transport TYPEs:"),
    6: _("Hey, %s!"),
    7: _("Hello, friend!"),
    8: _("Public Keys"),
    # TRANSLATORS: This string will end up saying something like:
    # "This email was generated with rainbows, unicorns, and sparkles
    #  for alice@example.com on Friday, 09 May, 2014 at 18:59:39."
    9: _("""\
This email was generated with rainbows, unicorns, and sparkles
for %s on %s at %s."""),
}

WELCOME = {
    # TRANSLATORS: Please DO NOT translate "BridgeDB".
    # TRANSLATORS: Please DO NOT translate "Pluggable Transports".
    # TRANSLATORS: Please DO NOT translate "Tor".
    # TRANSLATORS: Please DO NOT translate "Tor Network".
    0: _("""\
BridgeDB can provide bridges with several %stypes of Pluggable Transports%s,
which can help obfuscate your connections to the Tor Network, making it more
difficult for anyone watching your internet traffic to determine that you are
using Tor.\n\n"""),

    # TRANSLATORS: Please DO NOT translate "Pluggable Transports".
    1: _("""\
Some bridges with IPv6 addresses are also available, though some Pluggable
Transports aren't IPv6 compatible.\n\n"""),

    # TRANSLATORS: Please DO NOT translate "BridgeDB".
    # TRANSLATORS: The phrase "plain-ol'-vanilla" means "plain, boring,
    # regular, or unexciting". Like vanilla ice cream. It refers to bridges
    # which do not have Pluggable Transports, and only speak the regular,
    # boring Tor protocol. Translate it as you see fit. Have fun with it.
    2: _("""\
Additionally, BridgeDB has plenty of plain-ol'-vanilla bridges %s without any
Pluggable Transports %s which maybe doesn't sound as cool, but they can still
help to circumvent internet censorship in many cases.\n\n"""),
}
"""These strings should go on the first "Welcome" email sent by the
:mod:`~bridgedb.EmailServer`, as well as on the ``index.html`` template used
by the :mod:`~bridgedb.https.server`. They are used as an introduction to
explain what Tor bridges are, what bridges do, and why someone might want to
use bridges.
"""

FAQ = {
    0: _("What are bridges?"),
    1: _("""\
%s Bridges %s are Tor relays that help you circumvent censorship."""),
}

OTHER_DISTRIBUTORS = {
    0: _("I need an alternative way of getting bridges!"),
    1: _("""\
Another way to get bridges is to send an email to %s. Please note that you must
send the email using an address from one of the following email providers:
%s, %s or %s."""),
}

HELP = {
    0: _("My bridges don't work! I need help!"),
    # TRANSLATORS: Please DO NOT translate "Tor".
    1: _("""If your Tor doesn't work, you should email %s."""),
    # TRANSLATORS: Please DO NOT translate "Pluggable Transports".
    # TRANSLATORS: Please DO NOT translate "Tor Browser".
    # TRANSLATORS: Please DO NOT translate "Tor".
    2: _("""\
Try including as much info about your case as you can, including the list of
bridges and Pluggable Transports you tried to use, your Tor Browser version,
and any messages which Tor gave out, etc."""),
}

BRIDGES = {
    0: _("Here are your bridge lines:"),
    1: _("Get Bridges!"),
}

OPTIONS = {
    0: _("Please select options for bridge type:"),
    1: _("Do you need IPv6 addresses?"),
    2: _("Do you need a %s?"),
}

CAPTCHA = {
    0: _('Your browser is not displaying images properly.'),
    1: _('Enter the characters from the image above...'),
}

HOWTO_TBB = {
    0: _("""How to start using your bridges"""),
    # TRANSLATORS: Please DO NOT translate "Tor Browser".
    1: _("""\
To enter bridges into Tor Browser, first go to the %s Tor Browser download
page %s and then follow the instructions there for downloading and starting
Tor Browser."""),
    # TRANSLATORS: Please DO NOT translate "Tor".
    2: _("""\
When the 'Tor Network Settings' dialogue pops up, click 'Configure' and follow
the wizard until it asks:"""),
    # TRANSLATORS: Please DO NOT translate "Tor".
    3: _("""\
Does your Internet Service Provider (ISP) block or otherwise censor connections
to the Tor network?"""),
    # TRANSLATORS: Please DO NOT translate "Tor".
    4: _("""\
Select 'Yes' and then click 'Next'. To configure your new bridges, copy and
paste the bridge lines into the text input box. Finally, click 'Connect', and
you should be good to go! If you experience trouble, try clicking the 'Help'
button in the 'Tor Network Settings' wizard for further assistance."""),
}

EMAIL_COMMANDS = {
    "get help":             _("Displays this message."),
# TRANSLATORS: Please try to make it clear that "vanilla" here refers to the
# same non-Pluggable Transport bridges described above as being
# "plain-ol'-vanilla" bridges.
    "get bridges":          _("Request vanilla bridges."),
    "get ipv6":             _("Request IPv6 bridges."),
    # TRANSLATORS: Please DO NOT translate the word the word "TYPE".
    "get transport [TYPE]": _("Request a Pluggable Transport by TYPE."),
    # TRANSLATORS: Please DO NOT translate "BridgeDB".
    # TRANSLATORS: Please DO NOT translate "GnuPG".
    "get key":              _("Get a copy of BridgeDB's public GnuPG key."),
    #"subscribe":            _("Subscribe to receive new bridges once per week"),
    #"unsubscribe":          _("Cancel a subscription to new bridges"),
}

#-----------------------------------------------------------------------------
#           All of the following containers are untranslated!
#-----------------------------------------------------------------------------

#: SUPPORTED TRANSPORTS is dictionary mapping all Pluggable Transports
#: methodname to whether or not we actively distribute them. The ones which we
#: distribute SHOULD have the following properties:
#:
#:   1. The PT is in a widely accepted, usable state for most Tor users.
#:   2. The PT is currently publicly deployed *en masse*".
#:   3. The PT is included within the transports which Tor Browser offers in
#:      the stable releases.
#:
#: These will be sorted by methodname in alphabetical order.
#:
#: ***Don't change this setting here; change it in :file:`bridgedb.conf`.***
SUPPORTED_TRANSPORTS = {}

#: DEFAULT_TRANSPORT is a string. It should be the PT methodname of the
#: transport which is selected by default (e.g. in the webserver dropdown
#: menu).
#:
#: ***Don't change this setting here; change it in :file:`bridgedb.conf`.***
DEFAULT_TRANSPORT = ''

def _getSupportedTransports():
    """Get the list of currently supported transports.

    :rtype: list
    :returns: A list of strings, one for each supported Pluggable Transport
        methodname, sorted in alphabetical order.
    """
    supported = [name.lower() for name,w00t in SUPPORTED_TRANSPORTS.items() if w00t]
    supported.sort()
    return supported

def _setDefaultTransport(transport):
    global DEFAULT_TRANSPORT
    DEFAULT_TRANSPORT = transport

def _getDefaultTransport():
    return DEFAULT_TRANSPORT

def _setSupportedTransports(transports):
    """Set the list of currently supported transports.

    .. note: You shouldn't need to touch this. This is used by the config file
        parser. You should change the SUPPORTED_TRANSPORTS dictionary in
        :file:`bridgedb.conf`.

    :param dict transports: A mapping of Pluggable Transport methodnames
        (strings) to booleans.  If the boolean is ``True``, then the Pluggable
        Transport is one which we will (more easily) distribute to clients.
        If ``False``, then we (sort of) don't distribute it.
    """
    global SUPPORTED_TRANSPORTS
    SUPPORTED_TRANSPORTS = transports

def _getSupportedAndDefaultTransports():
    """Get a dictionary of currently supported transports, along with a boolean
    marking which transport is the default.

    It is returned as a :class:`collections.OrderedDict`, because if it is a
    regular dict, then the dropdown menu would populated in random order each
    time the page is rendered.  It is sorted in alphabetical order.

    :rtype: :class:`collections.OrderedDict`
    :returns: An :class:`~collections.OrderedDict` of the Pluggable Transport
        methodnames from :data:`SUPPORTED_TRANSPORTS` whose value in
        ``SUPPORTED_TRANSPORTS`` is ``True``.  If :data:`DEFAULT_TRANSPORT` is
        set, then the PT methodname in the ``DEFAULT_TRANSPORT`` setting is
        added to the :class:`~collections.OrderedDict`, with the value
        ``True``. Every other transport in the returned ``OrderedDict`` has
        its value set to ``False``, so that only the one which should be the
        default PT is ``True``.
    """
    supported = _getSupportedTransports()
    transports = OrderedDict(zip(supported, [False for _ in range(len(supported))]))

    if DEFAULT_TRANSPORT:
        transports[DEFAULT_TRANSPORT] = True

    return transports

EMAIL_SPRINTF = {
    # Goes into the "%s types of Pluggable Transports %s" part of ``WELCOME[0]``
    "WELCOME0": ("", "[0]"),
    # Goes into the "%s without Pluggable Transport %s" part of ``WELCOME[2]``
    "WELCOME2": ("-", "-"),
    # For the "%s Tor Browser download page %s" part of ``HOWTO_TBB[1]``
    "HOWTO_TBB1": ("", "[0]"),
    # For the "you should email %s" in ``HELP[0]``
    "HELP0": ("help@rt.torproject.org"),
}
"""``EMAIL_SPRINTF`` is a dictionary that maps translated strings which
contain format specifiers (i.e. ``%s``) to what those format specifiers should
be replaced with in a given template system.

For example, a string which needs a pair of HTML ``("<a href=''">, "</a>")``
tags (for the templates used by :mod:`bridgedb.https.server`) would need some
alternative replacements for the :mod:`EmailServer`, because the latter uses
templates with a ``text/plain`` mimetype instead of HTML. For the
``EmailServer``, the format strings specifiers are replaced with an empty
string where the opening ``<a>`` tags would go, and a numbered Markdown link
specifier where the closing ``</a>`` tags would go.

The keys in this dictionary are the Python variable names of the corresponding
strings which are being formatted, i.e. ``WELCOME0`` would be the string
replacements for ``strings.WELCOME.get(0)``.


For example, the ``0`` string in :data:`WELCOME` above has the substring::

    "%s without Pluggable Transport %s"

and so to replace the two ``%s`` format specifiers, you would use this mapping
like so::

>>> from bridgedb import strings
>>> welcome = strings.WELCOME[0] % strings.EMAIL_SPRINTF["WELCOME0"]
>>> print welcome.split('\n')[0]
BridgeDB can provide bridges with several types of Pluggable Transports[0],

"""

EMAIL_REFERENCE_LINKS = {
    "WELCOME0": "[0]: https://www.torproject.org/docs/pluggable-transports.html",
    "HOWTO_TBB1": "[0]: https://www.torproject.org/projects/torbrowser.html",
}

BRIDGEDB_OPENPGP_KEY = """\
# This keypair contains BridgeDB's online signing and encryption subkeys. This
# keypair rotates because it is kept online. However, the current online
# keypair will *ALWAYS* be certified by the offline keypair (at the bottom of
# this file).
#
# If you receive an email from BridgeDB, it should be signed with the
# 21B554E95938F4D0 subkey from the following keypair:

# pub   4096R/8DC43A2848821E32 2013-09-11 [expires: 2015-09-11]
#       Key fingerprint = DF81 1109 E17C 8BF1 34B5  EEB6 8DC4 3A28 4882 1E32
# uid                          BridgeDB <bridges@bridges.torproject.org>
# sub   4096R/21B554E95938F4D0 2013-09-11 [expires: 2015-09-11]
#       Key fingerprint = 9FE3 9D1A 7438 9223 3B3F  66F2 21B5 54E9 5938 F4D0
# sub   4096R/E7793047C5B54232 2013-09-11 [expires: 2015-09-11]
#       Key fingerprint = CFFB 8469 9048 37E7 8CAE  322C E779 3047 C5B5 4232

-----BEGIN PGP PUBLIC KEY BLOCK-----

mQINBFIv8YABEADRqvfLB4xWj3Fz+HEmUUt/qbJnZhqIjo5WBHaBJOmrzx1c9fLN
aYG36Hgo6A7NygI1oQmFnDinSrZAtrPaT63d1Jg49yZwr/OhMaxHYJElMFHGJ876
kLZHmQTysquYKDHhv+fH51t7UVaZ9NkP5cI+V3pqck0DW5DwMsVJXNaU317kk9me
mPJUDMb5FM4d2Vtk1N+54bHJgpgmnukNtpJmRyHRbZBqNMln5nWF7vdZ4u5PGPWj
bA0rPZhayeE3FQ0MHiGL12kHAy30pfg54QfPJDQBCywjABetRE+xaM9TcS+R31Pf
2VbLeb+Km7QpHMwOXI5xZLss9BAWm9EBbmXxuqaRBHyi830jjCrK9UYuzzOqKoUV
Mk1BRelZTFnGPWeVTE+Ps+pwJ0Dwx4ghppJBCoArmEbkNliblxR/2wYOOFi/ZVA4
Zc2ok9T3rBLVg07b7ezFUScGiTnc7ac7hp6r8Qsh09ZbhRr9erK/n194aEvkXTfr
qepwrAE7YeF4YuR206UOFFWDhxWDLbRu0gIWgrevEQu/cvQPrO9uH5fL6Gw/+mNP
Q/NIteejhkDyvyTUKyBu7x+Gls71zT2u/X13eOAJ8IxBkSVRKQ8tRD+oqJkWplOf
+BpaGU+g6u4kT2AzFDxTOupfrYcPvORTAV/V3suys2YQE4x422GASXDivQARAQAB
tClCcmlkZ2VEQiA8YnJpZGdlc0BicmlkZ2VzLnRvcnByb2plY3Qub3JnPokDJQQT
AQoBD0gUgAAAAAAXACh2ZXJpZmllZEB0b3Jwcm9qZWN0Lm9yZ0RGODExMTA5RTE3
QzhCRjEzNEI1RUVCNjhEQzQzQTI4NDg4MjFFMzJPFIAAAAAAHgAoYnJpZGdlc0Bi
cmlkZ2VzLnRvcnByb2plY3Qub3JnREY4MTExMDlFMTdDOEJGMTM0QjVFRUI2OERD
NDNBMjg0ODgyMUUzMioaaHR0cHM6Ly9icmlkZ2VzLnRvcnByb2plY3Qub3JnL3Bv
bGljeS50eHQCGwEDCw0JBBUKCQgEFgIBAAIeAQIXgCcYaHR0cHM6Ly9icmlkZ2Vz
LnRvcnByb2plY3Qub3JnL2tleS5hc2MFAlSKBKIFCQPDTiIACgkQjcQ6KEiCHjIs
jg//bJ12eRnBMfIGzOGh+T4wz7/YyKLfARAMnqDnSxhTxuE+M5hWm3QbxP03R6eY
x+PKwQaDJSmm7HhRhltb7QXUe8dqjnocFwwagpoLZ/81mBLxByqg5TKHGGIGy+DX
omIzCq5ijx1IUkHlgh708a5alG7bjRTqedT4Wxxyl6psGzDhGQdS8bqx/f32nQaE
h41l+A/EY1g2HVqky63ZHAP3S2v+mWCrk5DnkElc0229MXqaBuEr4nbYMXRkahMb
E2gnCmdSoeD21AY6bNyz7IcJGpyKCx9+hVgPjpm3J23JEYyPL+s48jn6QcI/Q2gD
yAtgU65y6IrdYn8SwkABI1FIq9WAwG7DaInxvkqkYqyBQLaZJEMyX8NTBvFoT5JS
jnkxG0xu61Vxq0BLYBIOJE0VFHAJ40/jOvSxQJkQhu9G4BK7htnADbtstmMDMM3q
xuuO5pcj2rl7YthNunyZ1yhPHXijUUyKrwR9piENpptztFBVN6+ijqU/TmWMOtbH
X7p9F+3tXCHHqwO5U/JMtsb/9M39MR8BrdcLc7m6dCpeuSUuR2LLroh+MoMJGviI
iesxHF95kFqkJAecW1Z3eKL9vrlbfO3waeuCi18k1TePnZuG5lmf2KjKDW5vHK4O
WFqvvfK2kxkCUjvGdLeTOAVOV+X+PQ23jvBJO2bS7YbOb9C5Ag0EUi/ygQEQALZ/
p7xRINHY7MMf3/bo/I0WRxWHd1AE9tRToyEg1S2u1YrWWL5M9D8saRsp9cpnpGEu
hW3vu7G4nasY27qOz4bSKu1YMAVIC58v1tEnBqdo1zErNjhs38PrmJKbbs9tDfYY
Oi2x0GlhMbIrNStcZpnCdLa6U6NLMbggDL1GxjMPYBMi4TtLgcIeRDUSjsZscZkg
Kxs5QkSVc3SrYyraayIc8WtIpDLcxPt6/g90rbatZzBfO+93Rz7qUXHmgzuM0hy1
Fvn619o3I5DsWrfOz9t/QuznoOBw4PfzDPNT7VlzZN4xHAcr5+7B+DH9IsvlCt5N
kQFuYpFZCpXNaD2XOtmIqjTCeLNfcgTEj0qoUIEKyKbBIgfP+7S2tLXy8JKUTy5g
9kxXQeHueLykQ4Mt18JH0nMHbHbQl0K3LGT4ucRDOmjNtlQCltVLkIk3GimyqKs/
vdZ9c+dm4Akx1qsJcwvveX+imJe2e9RUodcxWXxWrYnuPa5b5nfR1i+GfV0on/Pt
AQ8gc9CkJpMiq5TQDOFhFP6yQcq77sXuUkEl5qamptedz28E0I693ulnfwcsE80p
xkpIG6n33DZJSEyqgtWjE1P2pnsVfO5ILs3mKLe7bO1v3qMXcCkMCGH/kwzvtowq
YvY4gaZMDZtQFY8U7lI9FdRUvVdeHAB24y291nhzABEBAAGJBYMEGAEKANNIFIAA
AAAAFwAodmVyaWZpZWRAdG9ycHJvamVjdC5vcmdERjgxMTEwOUUxN0M4QkYxMzRC
NUVFQjY4REM0M0EyODQ4ODIxRTMyTxSAAAAAAB4AKGJyaWRnZXNAYnJpZGdlcy50
b3Jwcm9qZWN0Lm9yZ0RGODExMTA5RTE3QzhCRjEzNEI1RUVCNjhEQzQzQTI4NDg4
MjFFMzIqGmh0dHBzOi8vYnJpZGdlcy50b3Jwcm9qZWN0Lm9yZy9wb2xpY3kudHh0
AhsCBQJUigTTBQkDw01SAqTB2CAEGQEKAIEFAlIv8oFPFIAAAAAAHgAoYnJpZGdl
c0BicmlkZ2VzLnRvcnByb2plY3Qub3JnOUZFMzlEMUE3NDM4OTIyMzNCM0Y2NkYy
MjFCNTU0RTk1OTM4RjREMCoaaHR0cHM6Ly9icmlkZ2VzLnRvcnByb2plY3Qub3Jn
L3BvbGljeS50eHQACgkQIbVU6Vk49NDbPw/5ATe/T8+eaToC3v0TYNRH5nveQvzA
WdnshD3lnvfsgDhbilwifKpc5LHKXU3rvb42HH2cu0ckuksdDTvICZD9cJjRq/F+
Mzm0pNCAJg0pQnHaaWFQjw+CHYEoizai3S+iYxhNHeSdA6Ty7xm4+bHNf0Aqblbd
6dKwq9EvjwAI6zZsAHtsmHRUMdrFwGdKae6CSchUT2JQFBPEWMhvzdpDGACWVaSP
sxYKuYg9LgpswGcof+tprRjKRl8MtSh0ufjbVBlTeSKpL5Y+fcTRD3PI8w7Ocr3z
jr6XpYG4SUNHsWwxyu/DTXg76Lk1/+BdaH25hDOAasLUOU7yRL8zD/c7M0FkGXdj
r5I2DEEqwzJ9cPHWjpgb8N9fZLoPFP9JOmKGHINqxNe7TfwiTdD6uDKs/u/QK1U+
o3iYBXBTREdopPUdBTM9wYRUhyGXTEKLhUP3MGpXYlgeYPrSdp76VyN3BzLTbMv+
+7rxyKxL9cWYU0pnXHgPC5nyHX5nqXmhMnkxAD3Bnm8n9XDfgiyTDExqksEh2VXt
yhVfLezylEP2fwtd8/mABBCsTjzZW6FRfRRAjUZWZGFpFg8no1x5JS9uiswRP5g1
qHijNFWpGyTtJWl5VNd0d9+LtVUX1jRpDUpsjZcxqs3fsvw2p+H/zQ1wFvDrsoav
hqOTq+AEnJc7ZG8JEI3EOihIgh4ych8P/3GTyWb29+43YVibbSPPvEv4gFqziC+9
1p92FJ0V4XdaT7TW3qaZVp5edUNwB/jjF0SxBybwaMX2ZIGXOjnjF6/Zby4ynuTX
vZkS1mKRA0KWupB3e9PSMY3ZtssnqpGna/+3qlpxtunW7HcW4nCF/f59WHhlVjaO
MXjtuWj59yB56Dd1sNjwhcNCyp4/NpzGnRW97ZV3Pp4oqIOqcGzCQXkVPcnaqcOh
Cs9vIDJlMtn/IWBzUGimuRllDSSVSWkYkyJcG2NUHUwgXYpLwQz7sScvmCPchf4K
qarpX0FpkUDfqaVVuQ7A2XbPUAVFzIk930G1WzgOuOdg9vhWSEjou+SKrAoMz90w
3xHwEvmPDTTVJQft9ytoRbwZkIPfzzhII3mr4agbORAfzDaj5g/f6CVRdg6D3ME1
Etg9ZrfLgRY993g/arfIME6OOsiNcy5+PunN96Rw0o1xoD+97NmZuQrs/p4Mfn5o
8EwXHutREhahin+3/SV3hz9ReeLYmClq+OVhjPzPdtwZsFoyQyUJoFVHPTuSdChZ
FPaqN68FjlNMugmxnvski3ZDVT7pw3B6otjjaL3rr6q0PC2yhEb2ntb3IFUizHjn
80SmfE1Bqwit7ZHu8r/Gt/0iecGk5h84VzSgiGZGF/7m1i5UMVlNSeWnsInGa5Su
7HSzfMq+YmkzuQINBFIv8p4BEADTOLR5e5NKKRPpjCb4B/8YYkWh+orb70EogIZ6
j5v8d/djLyhjqZ9BIkh41/hYKMwnsa4KkDkTaX0eNu3BFB2zGgZ1GSd7525ESxiq
suXIlAg2pex7bysaFfua0nUx64tmaQm2XArdkj/wI0pbg+idWym3WQQmZLyTTbzl
8rpTEtTt+S2m6z3EeAhEHuNFH16hEDUywlef3EotX3njuFiLqaNvnzUYDxhUvKd2
2K1es1ggispgP+eb1bkMApxecf2rqmSUEcvsuTWip4oGZPBLGDQeNKHkCUVbj4wT
yWDIRtto3wi+4CFPEVzw+htj1cQfTstPqUdG7NSOmLQggedoUdv7AJm4MJJiyEax
l+IAf6Afwrrm3eOSv0PgoUxOrUb9vhIoL8ih8gtiqvQ9qYaRQfQA/w3Z0Su2Yfoc
fQS8Uw99qG+oTgieG6F6ud8+hMZAYVZFqbU+ztzMyDE6h4Hflkt6VNJ0Hk0VoF38
TTs77pHXXBbLD6SzR6tbNuR9r/lbmC8Qf2A1ZAThR0iuGhNRFtUPo28GxakxGdLZ
9kHIxjl7EN/gsmYTwuEhr+yfNtLwtSH0ojeqbDmgufvgh+SITCtyNDAUspjrZYEt
F0NHRpSom2NFVELMqMRydU/ncph1rGZgVp6/zVj6xIlhKmqj5P1y/9B0c4Tu1CzJ
pkJ5wwARAQABiQLpBBgBCgDTSBSAAAAAABcAKHZlcmlmaWVkQHRvcnByb2plY3Qu
b3JnREY4MTExMDlFMTdDOEJGMTM0QjVFRUI2OERDNDNBMjg0ODgyMUUzMk8UgAAA
AAAeAChicmlkZ2VzQGJyaWRnZXMudG9ycHJvamVjdC5vcmdERjgxMTEwOUUxN0M4
QkYxMzRCNUVFQjY4REM0M0EyODQ4ODIxRTMyKhpodHRwczovL2JyaWRnZXMudG9y
cHJvamVjdC5vcmcvcG9saWN5LnR4dAIbDAUCVIoE4QUJA8NNQwAKCRCNxDooSIIe
Mo7JEADDBtQpYxPhbj3MT0xpk96EDlon/5yHVf+cnk1pNisc+HkJsVe1nh7gAWOz
wJKdeqOVpgxiJTxIQdl6mipKwwFi0DreP7h56s1WQkuSSWJzqssAwWHfVAsX13fV
zWd0XyxN/OF9ZKQjX4qwpJ/na631PSwZLvHYhMaZnb9pjNwC5/PEKRmFqLbQT6Px
12miZT6ToPDCczHxJ4BxbEGVU+PtRsHwmTRT3JhxFNDfeVd+uwsQIMidJbUoqVW7
fe2zNd0TaWyz4Rw087oZE2OXdctjvtsu8fzXx6d/tkazI6cUOqoaMTR41KEu5X0T
BpWSAMADBYjNs9QRWXX7ZlsJRUSCX1EKbMhgoL6KIGceIkjH61M/LF6HqDgSgSWt
h+LIYGa+LrB/6819o32QSOSHHJ5+NJrbCSaLgKE/LKnf92V2QbZE8IGY6EOSjHqn
n1+j+CLRKY/kUyvk+1TumTghjg/aDs/8Jv8PvgSWLQ0q1rxHYbX7q9ZJhYC/4LdR
ya/Cho6w2l0N3tV/IMAwvFNHsaiIiiwfoOQbkBUvkyzBwjKt96Ai4I0QKt/63uH0
drQhlJEgIyGkOrorBByVqZAQdnoLENYIu6tDUj0bTbGObKqua4iPlSK3/g40zCm4
9OgcN7A8kFuNpgp2EHqj1/jrwd7mZYKsWTuGiR/7fwXf+4xbvg==
=raCx
-----END PGP PUBLIC KEY BLOCK-----

# The following keypair is BridgeDB's offline certification-only keypair. It
# is used to sign new online signing/encryption keypairs.
#
# If you import this key and mark it as trusted, emails from BridgeDB (if
# signed correctly with the online keypair above) should always be trusted. To
# do this, open a shell and do:
#
#     $ curl -O https://bridges.torproject.org/keys
#     $ gpg --import keys
#     $ gpg --check-sigs 7B78437015E63DF47BB1270ACBD97AA24E8E472E
#     $ gpg --edit-key 7B78437015E63DF47BB1270ACBD97AA24E8E472E
#
# Then type 'trust' to set the trust level. Choose a number that you like.
# Next type 'quit'. Finally, to create a local signature which will will not
# be uploaded to keyservers:
#
#     $ gpg --lsign-key 7B78437015E63DF47BB1270ACBD97AA24E8E472E
#

# pub   16384R/CBD97AA24E8E472E 2013-10-12
#      Key fingerprint = 7B78 4370 15E6 3DF4 7BB1  270A CBD9 7AA2 4E8E 472E
# uid            BridgeDB (Offline ID Key) <bridges@bridges.torproject.org>
-----BEGIN PGP PUBLIC KEY BLOCK-----

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
ILUXBkpIDfVSoZD7qWlntai53BDQr5pfMJhv15di4XAhtqv43vAmA57ifd+QJS2U
AfYc4CdX0lk2BZ4jRD8jCZ4Uxw15E3RqhnXsWDRxtD4fwsb2ZFi0DDuPlwBdGgh5
Rm2Bz9JjSV6gDEuXr/JtAzjSz1Jdh8wPkSofiHGTfxysVhlGlg+YPRziRlzML8A2
0xY+9mPxEEin5ZQ9wmrDyiiOBvPTbG3O9+Sp5VZDuD4ivW/DHumPWGVSRdjcAQDe
HMXUVGjhBDnj06XNrgJPhODdJeYq0EnGTt15ofZQSswD7TTTRPDOn0Cz/QARAQAB
tDpCcmlkZ2VEQiAoT2ZmbGluZSBJRCBLZXkpIDxicmlkZ2VzQGJyaWRnZXMudG9y
cHJvamVjdC5vcmc+iQkfBBMBCgEJBQJSWQfkSBSAAAAAABcAKHZlcmlmaWVkQHRv
cnByb2plY3Qub3JnN0I3ODQzNzAxNUU2M0RGNDdCQjEyNzBBQ0JEOTdBQTI0RThF
NDcyRU8UgAAAAAAeAChicmlkZ2VzQGJyaWRnZXMudG9ycHJvamVjdC5vcmc3Qjc4
NDM3MDE1RTYzREY0N0JCMTI3MEFDQkQ5N0FBMjRFOEU0NzJFKhpodHRwczovL2Jy
aWRnZXMudG9ycHJvamVjdC5vcmcvcG9saWN5LnR4dAIbAQMLDQkEFQoJCAQWAgEA
Ah4BAheAJxhodHRwczovL2JyaWRnZXMudG9ycHJvamVjdC5vcmcva2V5LmFzYwAK
CRDL2XqiTo5HLoqEP/48rFpJCVStn8xo+KkHSVvsqpxDRlb/nNheI+ov2UxILdwl
NIU6kLsvKECKPe1AHKdS/MzANbkTF35Y4QgZsNpVXaCVL7adGBSzOdPFupDJJVOu
wa+uFRc/FuNJyH/TIn56/+R5J5C54OxIYNxvW3WF4eHKLJYk/JZOMMfy4iWm7Sql
0nDC5O435nK4F4Jb4GLPlUIzioIy2OWqGoFHXymbGhL1tWaqasYmED4n3AMqlYw6
xnNhdWOc/KZelPl9nanybyh0IIdZqUKZleRt4BxSgIT8FqC2sZuZ8z7O9s987Naz
Q32SKaP4i2M9lai/Y2QYfKo+wlG+egmxtujz7etQMGlpgBZzFLdJ8/w4U11ku1ai
om74RIn8zl/LHjMQHnCKGoVlscTI1ZPt+p+p8hO2/9vOwTR8y8O/3DQSOfTSipwc
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
YnJpZGdlc0BicmlkZ2VzLnRvcnByb2plY3Qub3JnREY4MTExMDlFMTdDOEJGMTM0
QjVFRUI2OERDNDNBMjg0ODgyMUUzMioaaHR0cHM6Ly9icmlkZ2VzLnRvcnByb2pl
Y3Qub3JnL3BvbGljeS50eHQACgkQjcQ6KEiCHjIaqBAA0BuEs7horx6iCq4cjAhv
YPLrxuC4fKEfVyhAjCJMJSFFCPAlGgU+BjyPNDD57wzKAmUkdJG+Ss25mwWXa53w
5R2kDqDnHocOdZGtxZ7zx/uUd2eWLNBfVuK7nHOk1d1Hs0OZBnckc+MCqnLtuYe5
68pa9+jW6cNIjAnzMIListmoXWgYYWJvMKeBMG4DGtYJ8w7CJQjOHc5yar12DrX3
wnQ7hXtFuuqQblpEUnLnZGvHf2NKMZfBBMcP96h9OmLGNa+vmNYsMyPKU7n5hPgX
nTgmQ4xrv1G7JukjppZRA8SFoxupcaQeTixyWERGBhBiAbwZsbQz8L/TVZKierzg
sdNngHcFzE8MyjuJDvTos7qXPmgSRXFqJLRn0ZxpR5V1V8BVZUqCGuSZT89TizsD
z5vyv8c9r7HKD4pRjw32P2dgcEqyGRkqERAgSuFpObP+juty+kxYyfnadBNCyjgP
s7u0GmsTt4CZi7BbowNRL6bynrwrmQI9LJI1bPhgqfdDUbqG3HXwHz80oRFfKou8
JTYKxK4Iumfw2l/uAACma5ZyrwIDBX/H5XEQqch4sORzQnuhlTmZRf6ldVIIWjdJ
ef+DpOt12s+cS2F4D5g8G6t9CprCLYyrXiHwM/U8N5ywL9IeYKSWJxa7si3l9A6o
ZxOds8F/UJYDSIB97MQFzBo=
=JdC7
-----END PGP PUBLIC KEY BLOCK-----
"""

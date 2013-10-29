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

"""bridgedb.parse.headers -- Parsers for HTTP and Email headers.

** Module Overview: **

::

 parseAcceptLanguage - Parse the contents of a client 'Accept-Language' header

"""

import logging
log = logging.getLogger()

import re
import os

def parseAcceptLanguage(header):
    """Parse the contents of a client 'Accept-Language' header.

    Parse the header in the following manner:

      0. If ``header`` is None or an empty string, return an empty list.
      1. Split the ``header`` string on any commas.
      2. Chop of the RFC2616 quality/level suffix. We ignore these, and just
         use the order of the list as the preference order, without any
         parsing of quality/level assignments.
      3. Add a fallback language of the same type if it is missing. For
         example, if we only got ['es-ES', 'de-DE'], add 'es' after 'es-ES'
         and add 'de' after 'de-DE'.
      4. Change all hyphens to underscores.

    :param string header: The contents of an 'Accept-Language' header, i.e. as
        if taken from :func:`twisted.web.server.Request.getHeader`.
    :rtype: list
    :returns: A list of language codes (with and without locales), in order of
        preference.
    """
    langs = []

    if not header:
        return langs

    langHeader = header.split(',')

    for lang in langHeader:
        if lang.find(';') != -1:
            # Chop off the RFC2616 Accept `q=` and `level=` feilds
            code, _ = lang.split(';')
            langs.append(code)
        else:
            langs.append(lang)

    # Add a fallback language of the same type if it is missing.
    langsWithLocales = filter(lambda x: '-' in x, langs)
    langsOnly = map(lambda x: x.split('-')[0], langsWithLocales)
    for only in langsOnly:
        if only not in langs:
            # Add the fallback after the other languages like it:
            insertAfter = filter(lambda x: x.startswith(only),
                                 [x for x in langs])
            if insertAfter:
                placement = langs.index(insertAfter[0]) + 1
                langs.insert(placement, only)
                continue
            # Otherwise just put it at the end
            langs.append(only)

    # Gettext wants underderscores, because that is how it creates the
    # directories under i18n/, not hyphens:
    langs = map(lambda x: x.replace('-', '_'), [x for x in langs])
    return langs

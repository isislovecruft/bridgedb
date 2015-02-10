# -*- coding: utf-8 ; test-case-name: bridgedb.test.test_qrcodes ; -*-
#_____________________________________________________________________________
#
# This file is part of BridgeDB, a Tor bridge distribution system.
#
# :authors: Isis Lovecruft 0xA3ADB67A2CDB8B35 <isis@torproject.org>
#           please also see AUTHORS file
# :copyright: (c) 2007-2015, The Tor Project, Inc.
#             (c) 2014-2015, Isis Lovecruft
# :license: see LICENSE for licensing information
#_____________________________________________________________________________

"""Utilities for working with QRCodes."""


import cStringIO
import logging

try:
    import qrcode
except ImportError:  # pragma: no cover
    qrcode = False
    logging.warn("Could not import Python qrcode module.")
    logging.debug(("You'll need the qrcode Python module for this to "
                   "work. On Debian-based systems, this should be in the "
                   "python-qrcode package."))


def generateQR(bridgelines, imageFormat=u'JPEG', bridgeSchema=False):
    """Generate a QRCode for the client's bridge lines.

    :param str bridgelines: The Bridge Lines which we are distributing to the
        client.
    :param bool bridgeSchema: If ``True``, prepend ``'bridge://'`` to the
        beginning of each bridge line before QR encoding.
    :rtype: str or ``None``
    :returns: The generated QRCode, as a string.
    """
    logging.debug("Attempting to encode bridge lines into a QRCode...")

    if not bridgelines:
        return

    if not qrcode:
        logging.info("Not creating QRCode for bridgelines; no qrcode module.")
        return

    try:
        if bridgeSchema:
            # See https://bugs.torproject.org/12639 for why bridge:// is used.
            # (Hopefully, Orbot will pick up the ACTION_VIEW intent.)
            schema = 'bridge://'
            prefixed = []
            for line in bridgelines.strip().split('\n'):
                prefixed.append(schema + line)
            bridgelines = '\n'.join(prefixed)

        logging.debug("QR encoding bridge lines: %s" % bridgelines)

        qr = qrcode.QRCode()
        qr.add_data(bridgelines)

        buf = cStringIO.StringIO()
        img = qr.make_image().resize([350, 350])
        img.save(buf, imageFormat)
        buf.seek(0)

        imgstr = buf.read()
        return imgstr

    except KeyError as error:
        logging.error(str(error))
        logging.debug(("It seems python-imaging doesn't understand how to "
                       "save in the %s format.") % imageFormat)
    except Exception as error:  # pragma: no cover
        logging.error(("There was an error while attempting to generate the "
                       "QRCode: %s") % str(error))

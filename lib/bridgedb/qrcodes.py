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


def generateQR(bridgelines, imageFormat=u'JPEG'):
    """Generate a QRCode for the client's bridge lines.

    :param str bridgelines: The Bridge Lines which we are distributing to the
        client.
    :rtype: str or ``None``

    :returns: The generated QRCode, as a string.
    """
    logging.debug("Attempting to encode bridge lines into a QRCode...")

    if not bridgelines:
        return

    try:
        import qrcode

        qr = qrcode.QRCode()
        qr.add_data(bridgelines)
        buf = cStringIO.StringIO()
        img = qr.make_image().resize([350, 350])
        img.save(buf, imageFormat)
        buf.seek(0)
        imgstr = buf.read()
        logging.debug("Got QRCode image string.")
        
        return imgstr

    except ImportError as error:
        logging.error(str(error))
        logging.debug(("You'll need the qrcode Python module for this to "
                       "work. On Debian-based systems, this should be in the "
                       "python-qrcode package."))
    except KeyError as error:
        logging.error(str(error))
        logging.debug(("It seems python-imaging doesn't understand how to "
                       "save in the %s format.") % imgFormat)
    except Exception as error:
        logging.error(("There was an error while attempting to generate the "
                       "QRCode: %s") % str(error))

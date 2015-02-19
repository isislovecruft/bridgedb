#
#
# This file is part of BridgeDB, a Tor bridge distribution system.
#
# :authors: see AUTHORS file
# :copyright: (c) 2007-2015, The Tor Project, Inc.
# :license: 3-Clause BSD, see LICENSE for licensing information

"""
Boilerplate setup for GeoIP. GeoIP allows us to look up the country code
associated with an IP address. This is a "pure" python version which interacts
with the Maxmind GeoIP API (version 1). It requires, in Debian, the libgeoip-dev
and geoip-database packages.
"""

import logging
from os.path import isfile

from ipaddr import IPv4Address, IPv6Address

# IPv4 database
GEOIP_DBFILE = '/usr/share/GeoIP/GeoIP.dat'
# IPv6 database
GEOIPv6_DBFILE = '/usr/share/GeoIP/GeoIPv6.dat'
try:
    # Make sure we have the database before trying to import the module:
    if not (isfile(GEOIP_DBFILE) and isfile(GEOIPv6_DBFILE)):  # pragma: no cover
        raise EnvironmentError("Could not find %r. On Debian-based systems, "
                               "please install the geoip-database package."
                               % GEOIP_DBFILE)

    import pygeoip
    geoip = pygeoip.GeoIP(GEOIP_DBFILE, flags=pygeoip.MEMORY_CACHE)
    geoipv6 = pygeoip.GeoIP(GEOIPv6_DBFILE, flags=pygeoip.MEMORY_CACHE)
    logging.info("GeoIP databases loaded")
except Exception as err:  # pragma: no cover
    logging.warn("Error while loading geoip module: %r" % err)
    geoip = None
    geoipv6 = None

def getCountryCode(IPAddr):
    """Return the two-letter country code of a given IP address.

    :param IPAddr: (:class:`ipaddr.IPAddress`) An IPv4 OR IPv6 address.
    """

    ip = None
    version = None
    try:
        ip = IPAddr.compressed
        version = IPAddr.version
    except AttributeError as err:
        logging.warn("Wrong type passed to getCountryCode. Offending call:"
        " %r" % err)
        return None

    # GeoIP has two databases: one for IPv4 addresses, and one for IPv6
    # addresses. This will ensure we use the correct one.
    db = None
    # First, make sure we loaded GeoIP properly.
    if None in (geoip, geoipv6):
        logging.warn("GeoIP databases failed to load; could not look up"\
                     " country code.")
        return None
    else:
        if version == 4:
            db = geoip
        else:
            db = geoipv6

    # Look up the country code of the address.
    countryCode = db.country_code_by_addr(ip)
    if countryCode:
        logging.debug("Looked up country code: %s" % countryCode)
        return countryCode
    else:
        logging.debug("Country code was not detected. IP: %s" % ip)
        return None

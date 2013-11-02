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

"""bridge_server
----------------
Definitions and classes for parsing and creating
@type-bridge-server-descriptors. See the doc/DESCRIPTORS.md file within this
repository. Also see the metrics portal documentation on descriptor types [0]
(WARNING: outdated).

[0]: https://metrics.torproject.org/formats.html#descriptortypes
"""

from stem.descriptor import server_descriptor


class BridgeServerDescriptor(server_descriptor.BridgeDescriptor):
    """An @type-bridge-server-descriptor.

    As of tor-0.2.3.35, bridge router descriptors (found in the
    `bridge-descriptors` file), contain the 'opt ' prefix before certain
    fields. They look like this:

        @purpose bridge
        router Unnamed 10.0.1.113 9001 0 0
        platform Tor 0.2.3.25 on Linux
        opt protocols Link 1 2 Circuit 1
        published 2013-10-22 02:34:48
        opt fingerprint D4BB C339 2560 1B7F 226E 133B A85F 72AF E734 0B29
        uptime 938148
        bandwidth 25200 49200 44033
        opt extra-info-digest 3ABD120FCA67B18D48C8C8725B75EC7387A82C17
        onion-key
        -----BEGIN RSA PUBLIC KEY-----
        MIGJAoGBAL1bKPn8DUH5+EcnbSrdaIp2XU1gwJxCPTLdw4wDGNHT91a3liT/u8en
        FJYWIjc0g62hhZqJdkJkzxZypBoPUhMdF+wSKDVvNFBHRPPdJftrKTBuXEDg9ho1
        Ku5hGXpeWA9/ZVlZylI1EC0wMU/VYVF98v51TkURUiCoAX69IumZAgM8AAE=
        -----END RSA PUBLIC KEY-----
        signing-key
        -----BEGIN RSA PUBLIC KEY-----
        MIGJAoGBAOUKKy1AqC5GyVNOUFDsBjQ6bYS+8yVIqgDo0g0yzN+arrEkPRs1xqUk
        xWuk1IhwUIpZN3F6rwuzWbCFMkRW4TA4Zih55SRdAY1z9sLq5Fog+1dJtMiXlP5+
        JCqIA44vfMUwpXG9DzgdTG4//UoJ0gKL62whVizcM9y/o4vyY0EFAgMBAAE=
        -----END RSA PUBLIC KEY-----
        opt hidden-service-dir
        reject *:*
        router-signature
        -----BEGIN SIGNATURE-----
        rd981ZHtDmF1wiw37lpOh2PrBRunD5wb+WaYpZsKSwDv3hQFOTUwROQvUJY26wYH
        QT+02oM24yEfGXrs0uwWg4ycnmmskurrJKpNDPSJynYHKy82mxTNNE66Jr3FqytC
        VXAN4HoclQiNWdgZF3kAdCXW+8YR/rqyYtSOaLFOxgs=
        -----END SIGNATURE-----

    As of tor-0.2.4.15, bridge router descriptors may be missig the 'opt '
    prefix, and thus appear like this:

        @purpose bridge
        router Unnamed 10.0.1.171 9001 0 0
        platform Tor 0.2.4.17-rc on Linux
        protocols Link 1 2 Circuit 1
        published 2013-10-22 02:34:55
        fingerprint 6CE8 83D8 75E0 7996 7732 29E8 CA67 7A62 2B7F 05EF
        uptime 386679
        bandwidth 1073741824 1073741824 55832
        extra-info-digest FDAB376C3D6F1AA727C31EC6006745FB48663652
        onion-key
        -----BEGIN RSA PUBLIC KEY-----
        MIGJAoGBAL9L3mAtj8PtPSWFJ1s9gRm76b5OWL+46X2nL4dWl0eW6z+b88tlAFN5
        EZXEJ4OB8OnLzF4Q0vbSvWm2StqK+68M7FFCTp8c2ldrejJRK6PvTcBy/B0cejCF
        16+GUBw402j8znpxJFolT7A1zD5FvuPxU+2paN/hUqPTiNQDKkghAgMBAAE=
        -----END RSA PUBLIC KEY-----
        signing-key
        -----BEGIN RSA PUBLIC KEY-----
        MIGJAoGBAMepPKfnpG/EnoFC3xlRfckgmAS2DASLcAy9MWmVmHy9pvwNZauO2gtd
        WTbuQRI56xT25aIZhX0k0HkAPe4S3LOz+Llg2x7S/zpyDMtLkSDXvBdc+uBWea3u
        9O1w+SLxa4YujADMuhuiBDR3BYGQcibmMhwhLAgxZ0b/62m/VIb7AgMBAAE=
        -----END RSA PUBLIC KEY-----
        hidden-service-dir
        ntor-onion-key E2YxIe8jZvZ28DkTeU0PonF9D9Qr6/5QsP29AWrUAno=
        contact Somebody <somebody AT nowhere DOT net>
        reject *:*
        router-signature
        -----BEGIN SIGNATURE-----
        q5Wk1Sg6K84WZjXcbu8n7owGERVdAKMGQ/YBX7fv9jQo0OnTijFAF7SNUTmy7ZlI
        wtiwqhquDB3BTZ4FL9yZeoBnVhzlWGpzwef8zAQ5ivlPckYfUWHKRO4eux9tebkT
        B3RnIjfPs6q+m8gGz0ZDk7x7f3oDwyz/TKCgpZubp/w=
        -----END SIGNATURE-----
    """

    def __init__(self, raw_contents, validate=True,
                 annotations=None, scrubbed=False):
        super(BridgeServerDescriptor, self).__init__(raw_contects,
                                                     validate,
                                                     annotations)

    def _parse(self, entries, validate):
        entries = dict(entries)

        # handles fields only in bridge descriptors
        for keyword, values in entries.items():
            value, block_contents = values[0]
            line = "%s %s" % (keyword, value)

            if line == "@purpose bridge":
                logging.info("Got unsanitised bridge ('%s') descriptor"
                             % "@purpose bridge")
                
            # We don't need the 'opt ' prefix.
            #
            # In tor<=0.2.3.25, it existed on the 'fingerprint',
            # 'extra-info-digest', and 'hidden-service-dir' lines.
            #
            # In tor<0.2.3.x (XXX when exactly?), it existed on the
            # 'protocols' line as well.
            if keyword == "opt":
                keyword, value, block_contents = value.split(' ', 2)

            # XXX there are't any other bridge-specific lines, are there?
            super(BridgeServerDescriptor, self)._parse(entries, validate)
            self.checkDirPort()

    def checkDirPort(self):
        """Ensure that the descriptor's DirPort was set to `0`.

        Tor sets a bridge relay's DirPort setting to `0` when parsing the
        torrc, so if we ever encounter a descriptor which claims to be a
        bridge relay and yet still has a DirPort set, then something is wrong.
        """
        if self.dirport != 0:
            raise ValueError("A Bridge's DirPort MUST be 0.")

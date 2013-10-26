-*- mode: markdown ; coding: utf-8 -*-

# DESCRIPTORS

## Bridge router descriptors

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

As of tor-0.2.4.15, bridge router descriptors may be missig the 'opt ' prefix,
and thus appear like this:

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

# Extra-info descriptors

Bridge extra-info descriptors (from the `cached-extrainfo` and
`cached-extrainfo.new` files) contain extra data pertaining to a bridge. A
minimal bridge extra-info descriptor looks like this:

    extra-info Unnamed BFB9D952B9965847C42A0E214077C7DACA69275F
    published 2013-10-22 02:30:12
    write-history 2013-10-22 02:16:37 (900 s)
    92160,15360,9216,4096,173056,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,558080,552960,9216,6144,97280,5120,4096,3072,99328,9216,6144,4096,102400,11264,0,0,114688,6144,0,0,0,711680,31744,660480,23552,7168,5120,57344,8192,6144,4096,195584,24576,8192,8192,186368,6144,8192,8192,152576,16384,11264,10240,119808,33792,11264,6144
    read-history 2013-10-22 02:16:37 (900 s)
    1079296,33792,10240,7168,1199104,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,3818496,586752,14336,11264,1107968,10240,8192,6144,1134592,12288,9216,7168,1186816,22528,4096,0,1222656,11264,0,0,0,1857536,73728,1215488,23552,10240,5120,504832,13312,10240,8192,1510400,44032,13312,11264,1271808,9216,11264,11264,1173504,48128,15360,13312,1154048,70656,15360,9216
    router-signature
    -----BEGIN SIGNATURE-----
    u4qIZVeW67OPH7JTLsdHUVgUbqnjRjaIZwiQeUeBjTVO/NDJqZq5xeBDQGT3lNXN
    0/wm+X+2XuEDbQY2WryKC4pZ80/ArKlXUPRlblaw8soz22Q+6WtOJ/XOgFG1AzHz
    L6IYwgtDs3BXEx3p7bTtfFTg2resiyU+T3XT6FBDHvU=
    -----END SIGNATURE-----

Whereas a more dense bridge extra-info descriptor looks like this:

    extra-info Unnamed 48C9D4F2440997ACB32C88479A97B3ABF9820AF3
    published 2013-10-22 03:19:50
    write-history 2013-10-22 02:57:54 (900 s)
    87040,8192,6144,86016,23552,2048,16384,8192,79872,8192,72704,10240,19456,78848,9216,6144,4096,2048,97280,18432,70656,30720,9216,9216,628736,77824,4096,4096,10240,144384,9216,48128,38912,92160,27648,6144,2048,16384,6144,92160,18432,51200,12288,16384,69632,7168,8192,1024,76800,14336,1024,82944,13312,79872,7168,22528,95232,60416,17408,4096,5120,17408,89088,1024,5120,132096,8192,19456,5120,6144,8192,103424,7168,91136,3072,8192,44032,10240,5120,19456,68608,100352,19456,3072,82944,20480,6144,8192,63488,13312,5120,14336,76800,8192,59392,8192
    read-history 2013-10-22 03:12:54 (900 s)
    11264,9216,1069056,40960,6144,16384,11264,1053696,11264,1031168,22528,22528,668672,29696,9216,6144,2048,1068032,31744,486400,60416,13312,8192,1206272,674816,3072,8192,14336,1183744,26624,464896,409600,135168,205824,8192,5120,17408,9216,1125376,33792,481280,24576,16384,683008,8192,11264,1024,1080320,13312,1024,1108992,26624,739328,17408,31744,995328,227328,51200,3072,8192,21504,1173504,4096,6144,1225728,30720,22528,5120,9216,11264,1195008,15360,745472,5120,11264,483328,17408,8192,24576,715776,1115136,49152,2048,927744,28672,10240,11264,688128,20480,8192,17408,1048576,11264,630784,11264,7168
    geoip-db-digest 207A8167FC83230884A7B463B8EE12385CF1874F
    geoip6-db-digest 7F82A502C248B0CFBCCF6FE370919E34E04A21FA
    dirreq-write-history 2013-10-21 18:36:36 (900 s)
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1329152,2048
    dirreq-read-history 2013-10-21 18:36:36 (900 s)
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,199680,2048

If a bridge extra-info descriptor has the `dirreq-read-history` or the
`dirreq-write-history` lines shown above, then either of the following lines
will come after it (but not both):

    dirreq-stats-end 2013-10-21 17:27:06 (86400 s)
    bridge-stats-end 2013-10-21 17:27:06 (86400 s)

Optionally followed by:

    dirreq-v3-ips
    dirreq-v2-ips
    dirreq-v3-reqs
    dirreq-v2-reqs
    dirreq-v3-resp
    ok=0,not-enough-sigs=0,unavailable=0,not-found=0,not-modified=0,busy=0
    dirreq-v2-resp ok=0,unavailable=0,not-found=0,not-modified=0,busy=0
    dirreq-v3-direct-dl complete=0,timeout=0,running=0
    dirreq-v2-direct-dl complete=0,timeout=0,running=0
    dirreq-v3-tunneled-dl complete=0,timeout=0,running=0
    dirreq-v2-tunneled-dl complete=0,timeout=0,running=0
    bridge-stats-end 2013-10-21 17:28:15 (86400 s)
    bridge-ips de=8,nl=8,us=8

And, if it include the `bridge-ips` line, it MAY include the following right
afterwards:

    bridge-ip-versions v4=16,v6=8

An extra-info descriptor will always end with a signature, like this:

    router-signature
    -----BEGIN SIGNATURE-----
    f4ed3BwfcbH36E9ODxDSideWhld5IhlsBi9alOh10UFCuqdvXcCkgzjB0s3EC5sf
    hOjQkH96MdF8mtqGtJdEyA00lCqDkCulIrlgDlJRsj9AI29KeMjLPNb+7erNzPPL
    40f0vr+zuKQfUiI0piSR4txrEdAY58dDY0Hl1yEcsfo=
    -----END SIGNATURE-----

## An bridge extra-info descriptor for a bridge with pluggable transports

The following is an example of a bridge which supports the `obfs2` and `obfs3`
obproxy pluggable transport types:

    extra-info Unnamed DD91800E06C195B0AF804E30DB07830AC991AFD4
    published 2013-10-22 02:14:04
    write-history 2013-10-22 01:59:38 (900 s)
    3188736,2226176,2866176,2256896,2229248,2721792
    read-history 2013-10-22 01:59:38 (900 s)
    3891200,2483200,2698240,1789952,1921024,2811904
    dirreq-write-history 2013-10-22 01:59:38 (900 s)
    1024,0,2048,0,1024,0
    dirreq-read-history 2013-10-22 01:59:38 (900 s)
    0,0,0,0,0,0
    geoip-db-digest 67D32F60547F141E16FB0705D1F1710471697228
    geoip6-db-digest 9082A502C248B0CFBCCF6F9370919E34E04B21F2
    dirreq-stats-end 2013-10-21 13:04:22 (86400 s)
    dirreq-v3-ips
    dirreq-v3-reqs
    dirreq-v3-resp
    ok=16,not-enough-sigs=0,unavailable=0,not-found=0,not-modified=0,busy=0
    dirreq-v3-direct-dl complete=0,timeout=0,running=0
    dirreq-v3-tunneled-dl complete=12,timeout=0,running=0
    transport obfs3 10.0.1.111:3333
    transport obfs2 10.0.1.111:2222
    bridge-stats-end 2013-10-21 13:04:24 (86400 s)
    bridge-ips ca=8
    bridge-ip-versions v4=8,v6=0
    bridge-ip-transports <OR>=8
    router-signature
    -----BEGIN SIGNATURE-----
    Bo/HHLbGEj90z+JWlHQgbahrAh83prAUicv3fgdldrIjbHrPRpJ2ep9r/WgJY4KO
    TANz3XcqqfhUI5rg2AzjUif8xHUZv152xqgErZEXxn+m4JmEU03qAShT0e8eMj2S
    D9FLbPlXw4NWy9B32IT/luOHsENaAJNvOv7ociMPnsM=
    -----END SIGNATURE-----

## Bridge router microdescriptors

    r Unnamed /wywABJee98ZPOiCGYM1dpgQc70 NpK1tsi97A+SH8s0evowXkRcyr8 2013-10-22 01:49:45 88.200.197.4 9001 0
    a [6212:b13d:252e:479d:32b8:d713:3718:2fac]:9001
    s Fast Guard Running Stable Valid
    w Bandwidth=53
    p reject 1-65535

# -*- coding: utf-8 ; -*-
#_____________________________________________________________________________
#
# This file is part of BridgeDB, a Tor bridge distribution system.
#
# :authors: Isis Lovecruft 0xA3ADB67A2CDB8B35 <isis@torproject.org>
#           please also see AUTHORS file
# :copyright: (c) 2007-2016, The Tor Project, Inc.
#             (c) 2014-2016, Isis Lovecruft
# :license: see LICENSE for licensing information
#_____________________________________________________________________________

# bridgerequest.capnp - Cap'n'Proto schema for bridge requests.

@0xf5aaa21a39b352e4;

enum Transport {
  vanilla @0
  obfs2 @1;
  obfs3 @2;
  obfs4 @3;
  scramblesuit @4;
  fte @5;
}

struct BridgeRequest {
  ipversion @0 :UInt8;
  transports @1 :List(Transport);
  notblockedin @2 :List(Text);
  client @3 :Text;
}

struct Bridge {
  transport @0 :Transport;
  address @1 :Text;
  port @2 :UInt16;
  args @3 :Text;
}

union Bridges {
  unavailable @0 :Bool;
  bridges @1 :List(Bridge);
}

interface DatabaseManager {
  processBridgeRequest @0 (bridgerequest: BridgeRequest) -> (bridges: Bridges)
}


import Bridges
import socket

def uniformMap(ip):
    "Map an IP to an arbitrary 'area' string"
    # convert the IP for 4 bytes.
    s = socket.inet_aton(ip)
    # return the first 3.
    return s[:3]


class IPBasedDistributor(Bridges.BridgeHolder):
    def __init__(self, areaMapper, nClusters, key):
        self.areaMapper = areaMapper

        self.rings = []
        for n in xrange(nClusters):
            key1 = Bridges.get_hmac(key, "Order-Bridges-In-Ring-%d"%n)
            self.rings.append( Bridges.BridgeRing(key1) )

        key2 = Bridges.get_hmac(key, "Assign-Bridges-To-Rings")
        self.splitter = Bridges.FixedBridgeSplitter(key2, self.rings)

        key3 = Bridges.get_hmac(key, "Order-Areas-In-Rings")
        self.areaOrderHmac = Bridges.get_hmac_fn(key3, hex=True)

        key4 = Bridges.get_hmac(key, "Assign-Areas-To-Rings")
        self.areaClusterHmac = Bridges.get_hmac_fun(key4, hex=True)

    def insert(self, bridge):
        self.splitter.insert(bridge)

    def getBridgesForIP(self, ip, epoch, N=1):
        area = self.areaMapper(ip)

        # Which bridge cluster should we look at?
        h = int( self.areaClusterHmac(area)[:8], 16 )
        clusterNum = h % len(self.rings)
        ring = self.rings[clusterNum]

        # Now get the bridge.
        pos = self.areaOrderHmac("<%s>%s" % (epoch, area))
        return ring.getBridges(pos, N)


def normalizeEmail(addr):
    #XXXX make this better.
    return addr.strip().lower()

class EmailBasedDistributor(Bridges.BridgeHolder):
    def __init__(self, key, store):

        key1 = Bridges.get_hmac(key, "Map-Addresses-To-Ring")
        self.emailHmac = Bridges.get_hmac_fn(key1, hex=1)

        key2 = Bridges.get_hmac(key, "Order-Bridges-In-Ring")
        self.ring = Bridges.BrigeRing(key2)
        self.store = store

    def insert(self, bridge):
        self.ring.insert(bridge):

    def getBridgesForEmail(self, emailaddress, epoch, N=1):
        emailaddress = normalizeEmail(emailaddress)
        if store.has_key(emailaddress):
            result = []
            ids = store[emailaddress])
            for id in Bridges.chopString(ids, Bridges.ID_LEN)
                b = self.ring.getBridgeByID(id)
                if b != None:
                    result.append(b)
            return result

        pos = self.emailHmac("<%s>%s" % (epoch, emailaddress))
        result = ring.getBridges(pos, N)
        memo = "".join(b.getID() for b in result)
        self.store[emailaddress] = memo
        return result


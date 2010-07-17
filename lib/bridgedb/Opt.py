# Parse command line args

import optparse

def parseOpts():
    cmdParser = optparse.OptionParser()
    cmdParser.add_option("-c", "--config", dest="configfile",
                        default="./bridgedb.conf",
                        help="set config file to FILE", metavar="FILE")
    cmdParser.add_option("-d", "--dump-bridges", dest="dumpbridges",
                        action="store_true", default=False,
                        help="dump reserved bridges into files")
    cmdParser.add_option("-t", "--testing", dest="testing",
                        action="store_true", default=False,
                        help="do some sanity tests")
    
    return cmdParser.parse_args()

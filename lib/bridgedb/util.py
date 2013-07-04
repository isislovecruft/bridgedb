# -*- coding: utf-8 ; mode: python ; -*-
#
# :authors: Isis Lovecruft
# :copyright: (c) 2007-2013, The Tor Project, Inc.
# :license: see LICENSE for licensing information

"""Util.py - common utilities for BridgeDB"""

from __future__ import print_function

import stat
import os

from twisted.python import filepath


def touch(path, directory=False):
    """Create a directory or file if it doesn't exist.

    Useful for ensuring that logfiles and config files exist (before trying to
    read from/write to them) and that they have sane permissions. The default
    permissions for directories is 0700 (0x41c0) and for files is 0600 (0x180).

    :param str path: The directory or file to create, if it doesn't exist.
    :ivar hex chmodp: The permissions to assign to the directory.
    """
    #: The value for os.chmod() to set ``path`` permissions
    chmodp = 0x180
    #: The permissions bitmasks as given by os.stat().st_mode for directories
    stmode = (stat.S_IWUSR | stat.S_IRUSR)

    if directory:
        chmodp = 0x41c0
        stmode = (stat.S_IFDIR | stat.S_IRWXU)

    path = expand(path)
    try:
        fp = filepath.FilePath(path)
        if fp.exists():
            if directory and not fp.isdir(): ## delete path if not a directory
                print("WARNING: Deleting non-directory %s" % fp.path)
                fp.remove()
        ## try creating the file or directory:
        if directory: fp.createDirectory()
        else: fp.touch()

        fp.restat()
        ## a bitwise XOR is non-zero (i.e. True) if the bitmasks do not match:
        if bool(stmode ^ fp.statinfo.st_mode):
            fp.chmod(chmodp)

    except (OSError, AttributeError):
        pass
    except filepath.InsecurePath as err:
        print(err)

    return path

def expand(directory):
    """Expand to an abspath and normalise no matter what.

    :type directory: str or list
    :param directory: The path(s) to expand.

    :rtype: str or list
    :returns: A list of expanded pathnames if given a list, else a string with
         the expanded pathname
    """
    def expand_one(dirpath):
        ## deal with double slashes, dots, emtpy strings, unicode, and any
        ## other weirdness:
        dirpath = filepath.normpath(dirpath)
        if dirpath.startswith('~'):
             dirpath = os.path.expanduser(dirpath)
        return os.path.abspath(dirpath)

    try:
        if isinstance(directory, (list, tuple)):
            expanded = [expand_one(d) for d in directory]
        else:
            expanded = expand_one(directory)
    except (TypeError, AttributeError):
        print("ERROR: expand failed for directory '%s'" % directory)
    return expanded

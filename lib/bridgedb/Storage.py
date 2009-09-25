# BridgeDB by Nick Mathewson.
# Copyright (c) 2007-2009, The Tor Project, Inc.
# See LICENSE for licensing information

def _escapeValue(v):
    return "'%s'" % v.replace("'", "''")

class SqliteDict:
    """
       A SqliteDict wraps a SQLite table and makes it look like a
       Python dictionary.  In addition to the single key and value
       columns, there can be a number of "fixed" columns, such that
       the dictionary only contains elements of the table where the
       fixed columns are set appropriately.
    """
    def __init__(self, conn, cursor, table, fixedcolnames, fixedcolvalues,
                 keycol, valcol):
        assert len(fixedcolnames) == len(fixedcolvalues)
        self._conn = conn
        self._cursor = cursor
        keys = ", ".join(fixedcolnames+(keycol,valcol))
        vals = "".join("%s, "%_escapeValue(v) for v in fixedcolvalues)
        constraint = "WHERE %s = ?"%keycol
        if fixedcolnames:
            constraint += "".join(
                " AND %s = %s"%(c,_escapeValue(v))
                for c,v in zip(fixedcolnames, fixedcolvalues))

        self._getStmt = "SELECT %s FROM %s %s"%(valcol,table,constraint)
        self._delStmt = "DELETE FROM %s %s"%(table,constraint)
        self._setStmt = "INSERT OR REPLACE INTO %s (%s) VALUES (%s?, ?)"%(
            table, keys, vals)

        constraint = " AND ".join("%s = %s"%(c,_escapeValue(v))
                for c,v in zip(fixedcolnames, fixedcolvalues))
        if constraint:
            whereClause = " WHERE %s"%constraint
        else:
            whereClause = ""

        self._keysStmt = "SELECT %s FROM %s%s"%(keycol,table,whereClause)

    def __setitem__(self, k, v):
        self._cursor.execute(self._setStmt, (k,v))
    def __delitem__(self, k):
        self._cursor.execute(self._delStmt, (k,))
        if self._cursor.rowcount == 0:
            raise KeyError(k)
    def __getitem__(self, k):
        self._cursor.execute(self._getStmt, (k,))
        val = self._cursor.fetchone()
        if val == None:
            raise KeyError(k)
        else:
            return val[0]
    def has_key(self):
        self._cursor.execute(self._getStmt, (k,))
        return self._cursor.rowcount != 0
    def get(self, k, v=None):
        self._cursor.execute(self._getStmt, (k,))
        val = self._cursor.fetchone()
        if val == None:
            return v;
        else:
            return val[0]
    def setdefault(self, k, v):
        try:
            r = self[k]
        except KeyError:
            r = self[k] = v
        return r
    def keys(self):
        self._cursor.execute(self._keysStmt)
        return [ key for (key,) in self._cursor.fetchall() ]

    def commit(self):
        self._conn.commit()
    def rollback(self):
        self._conn.rollback()

#
#  The old DB system was just a key->value mapping DB, with special key
#  prefixes to indicate which database they fell into.
#
#     sp|<HEXID> -- given to bridgesplitter; maps bridgeID to ring name.
#     em|<emailaddr> -- given to emailbaseddistributor; maps email address
#            to concatenated hexID.
#     fs|<HEXID> -- Given to BridgeTracker, maps to time when a router was
#            first seen (YYYY-MM-DD HH:MM)
#     ls|<HEXID> -- given to bridgetracker, maps to time when a router was
#            last seen (YYYY-MM-DD HH:MM)
#

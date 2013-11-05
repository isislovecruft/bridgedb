#!/usr/bin/env python

from twisted.trial import unittest
from bridgedb import proxy
import sure


class ProxySetTest(unittest.TestCase):

    def setUp(self):
        self.ps = proxy.ProxySet(['1.1.1.1'])

    def test_instantiation(self):
        self.ps.should.be.ok
        self.ps.should.have.property('__contains__').being.callable
        self.ps.should.have.property('__iter__').being.callable
        self.ps.should.have.property('__len__').being.callable
        self.ps.should.have.property('add').being.callable
        self.ps.should.have.property('discard').being.callable

    def test_attributes(self):
        self.ps.should.have.property('proxies').being.a(list)
        self.ps.should.have.property('_proxies').being.a(set)
        self.ps.should.have.property('_proxydict').being.a(dict)

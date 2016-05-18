import unittest
import os
import inspect

import lib.naming
import lib.nacaddr

class Naming_Characterization_Tests(unittest.TestCase):
    """Tests to ensure that Naming works as expected on refactoring."""

    def setUp(self):
        # Not ideal to use characterization data in unit tests,
        # but better than nothing.
        curr_dir = os.path.dirname(os.path.abspath(inspect.getfile(inspect.currentframe())))
        self.def_dir = os.path.join(curr_dir, '..', 'characterization_data', 'def')
        self.assertTrue(os.path.exists(self.def_dir))
        self.naming = lib.naming.Naming(self.def_dir)

    def test_GetIpParents(self):
        data = [
            ['10.1.1.1', ['ANY', 'INTERNAL', 'RESERVED', 'RFC1918']],
            [lib.nacaddr.IP('10.1.1.1/32'), ['ANY', 'INTERNAL', 'RESERVED', 'RFC1918']],
            ['not_an_ip_address', []]
        ]
        for ip, expected in data:
            self.assertEqual(self.naming.GetIpParents(ip), expected)

    def test_GetServiceParents(self):
        data = [
            ['DNS', []],
            ['BOOTPC', ['DHCP']],
            ['INTERNAL', []],
            ['SOME_UNKNOWN_TOKEN', []]
        ]
        for svc, expected in data:
            self.assertEqual(self.naming.GetServiceParents(svc), expected)

    def test_GetNetParents(self):
        data = [
            ['DNS', []],
            ['BOOTPC', []],
            ['MULTICAST', ['RESERVED', 'BOGON']],
            ['SOME_UNKNOWN_TOKEN', []]
        ]
        for net, expected in data:
            self.assertEqual(self.naming.GetNetParents(net), expected)

    def test_GetService(self):
        data = [
            ['DNS', ['53/tcp', '53/udp']],
            ['BOOTPC', ['68/udp']],
            ['DHCP', ['67/udp', '68/udp']],
        ]
        for svc, expected in data:
            self.assertEqual(self.naming.GetService(svc), expected)

    def test_GetService_raises_if_unknown(self):
        for svc in ['MULTICAST', 'SOME_UNKNOWN_TOKEN']:
            with self.assertRaises(lib.naming.UndefinedServiceError):
                self.naming.GetService(svc)

    def test_GetServiceByProto(self):
        data = [
            ['DNS', 'tcp', ['53']],
            ['DNS', 'udp', ['53']],
            ['DHCP', 'tcp', []],
            ['DHCP', 'udp', ['67', '68']],
            ['BOOTPC', 'tcp', []],
            ['DHCP', 'xyz', []],
        ]
        for svc, proto, expected in data:
            actual = self.naming.GetServiceByProto(svc, proto)
            self.assertEqual(actual, expected, svc + '/' + proto)

    def test_GetNet(self):
        data = [
            ['ANY', ['0.0.0.0/0']],
            ['ANY # with a comment', ['0.0.0.0/0']],
            ['INTERNAL', ['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16']],
            ['RFC1918', ['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16']],
        ]
        for net, expected in data:
            actual = self.naming.GetNetAddr(net)
            self.assertEqual(actual, map(lib.nacaddr.IPv4, expected))

    def test_GetNet_raises_if_unknown(self):
        with self.assertRaises(lib.naming.UndefinedAddressError):
            self.naming.GetNetAddr('SOME_UNDEFINED_TOKEN')

    def test_GetNetAddr(self):
        """GetNetAddr delegates to GetNet (currently, at least)."""
        self.test_GetNet()

    def test_GetNetAddr_raises_if_unknown(self):
        """GetNetAddr delegates to GetNet (currently, at least)."""
        self.test_GetNet_raises_if_unknown()

    def test_parseServiceList(self):
        tok = 'SOME_UNKNOWN_TOKEN'
        with self.assertRaises(lib.naming.UndefinedServiceError):
            self.naming.GetService(tok)
        self.naming.ParseServiceList(['SOME_UNKNOWN_TOKEN = 888/tcp'])
        self.assertEqual(self.naming.GetService(tok), ['888/tcp'])

    def test_parseNetworkList(self):
        tok = 'SOME_UNKNOWN_TOKEN'
        with self.assertRaises(lib.naming.UndefinedAddressError):
            self.naming.GetNet(tok)
        self.naming.ParseNetworkList(['SOME_UNKNOWN_TOKEN = 10.1.1.1/32'])
        self.assertEqual(self.naming.GetNet(tok), [lib.nacaddr.IPv4('10.1.1.1/32')])


def main():
    unittest.main()

if __name__ == '__main__':
    main()


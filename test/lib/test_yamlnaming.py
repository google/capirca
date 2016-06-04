import unittest
import os
import inspect
from StringIO import StringIO
import re

import lib.yamlnaming
import lib.nacaddr
import yaml

class YamlNaming_Characterization_Tests(unittest.TestCase):
    """Verify feature parity with current Naming class, ensure data is good."""

    def setUp(self):
        # Not ideal to use characterization data in unit tests,
        # but better than nothing.
        curr_dir = os.path.dirname(os.path.abspath(inspect.getfile(inspect.currentframe())))
        self.def_dir = os.path.join(curr_dir, '..', 'yaml_policies', 'def')
        self.assertTrue(os.path.exists(self.def_dir))
        self.naming = lib.yamlnaming.YamlNaming(self.def_dir)

    def test_GetIpParents(self):
        data = [
            ['10.1.1.1', ['ANY', 'INTERNAL', 'RESERVED', 'RFC1918']],
            [lib.nacaddr.IP('10.1.1.1/32'), ['ANY', 'INTERNAL', 'RESERVED', 'RFC1918']],
            ['RFC1918', ['INTERNAL', 'RESERVED']],
            ['240.0.0.0/4', ['ANY', 'BOGON', 'CLASS-E', 'RESERVED']],
            ['not_a_real_token', []]
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
            ['CLASS-E', ['RESERVED', 'BOGON']],
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
        for svc in ['SOME_UNKNOWN_TOKEN']:
            with self.assertRaises(lib.yamlnaming.UndefinedServiceError):
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
            ['CLASS-E', ['240.0.0.0/4']],
            ['INTERNAL', ['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16']],
            ['RFC1918', ['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16']],
        ]
        for net, expected in data:
            actual = self.naming.GetNetAddr(net)
            self.assertEqual(actual, map(lib.nacaddr.IPv4, expected))

    def test_GetNet_adds_metadata_to_address(self):
        """The metadata (comments, etc) is used during ACL generation."""
        def to_s(a):
            return ','.join([str(a), a.text, a.token, a.parent_token])
        data = self.naming.GetNetAddr('INTERNAL')
        actual = map(to_s, self.naming.GetNetAddr('INTERNAL'))
        expected = [
            '10.0.0.0/8,non-public,RFC1918,INTERNAL',
            '172.16.0.0/12,non-public,RFC1918,INTERNAL',
            '192.168.0.0/16,non-public,RFC1918,INTERNAL'
        ]
        self.assertEqual(actual, expected)

    def test_GetNet_raises_if_unknown(self):
        with self.assertRaises(lib.yamlnaming.UndefinedAddressError):
            self.naming.GetNetAddr('SOME_UNDEFINED_TOKEN')

    def test_GetNetAddr(self):
        """GetNetAddr delegates to GetNet (currently, at least)."""
        self.test_GetNet()

    def test_GetNetAddr_raises_if_unknown(self):
        """GetNetAddr delegates to GetNet (currently, at least)."""
        self.test_GetNet_raises_if_unknown()


class YamlNaming_DataLoad_Tests(unittest.TestCase):
    """Tests for loading YamlNaming object from stream or dict."""

    def setUp(self):
        self.definitions = lib.yamlnaming.YamlNaming()
        self.data = {
            'network': { 'A': '10.1.1.1/32' },
            'services': { 'B': '25/tcp' }
        }

    def test_can_Append_data_from_dict(self):
        self.definitions.Append(self.data)
        self.assertEqual(self.definitions.networks['A'], [('10.1.1.1/32', None)])
        self.assertEqual(self.definitions.services['B'], [('25/tcp', None)])

    def test_network_and_services_do_not_overlap(self):
        self.data['services']['A'] = '33/udp'
        self.definitions.Append(self.data)
        self.assertEqual(self.definitions.networks['A'], [('10.1.1.1/32', None)])
        self.assertEqual(self.definitions.services['A'], [('33/udp', None)])

    def test_Append_either_network_or_service_data_only_is_ok(self):
        keys = self.data.keys()
        for k in keys:
            d = dict(self.data)
            d.pop(k)
            self.definitions.Append(d)

    def test_bad_data_in_Append_dict_should_throw(self):
        self.data['bad_data'] = 'should_throw'
        with self.assertRaises(lib.yamlnaming.BadYamlFormatError):
            self.definitions.Append(self.data)

    def test_AppendFromStream_smoke_test(self):
        s = """
network:
  A: 10.1.1.1/32
services:
  B: 25/tcp"""
        io = StringIO(s)
        self.definitions.AppendFromStream(io)
        self.assertEqual(self.definitions.networks['A'], [('10.1.1.1/32', None)])

    def test_AppendFromStream_raises_if_stream_contains_duplicate_keys(self):
        base_stream = """
network:
  A: 10.1.1.1/32
  STUB_A
services:
  B: 25/tcp
  STUB_B"""
        test_cases = [
            ['A: x', '', 'dup in network' ],
            ['', 'B: x', 'dup in services' ],
            ['A: x', 'B: x', 'dup in both' ]
        ]
        for a_val, b_val, description in test_cases:
            s = str(base_stream)  # copy
            s = s.replace('STUB_A', a_val)
            s = s.replace('STUB_B', b_val)
            io = StringIO(s)
            # print s, yaml.load(io.read())
            with self.assertRaises(lib.yamlnaming.BadYamlFormatError):
                self.definitions.AppendFromStream(io)

    def test_AppendFromStream_error_message_gives_hints_on_dup_keys(self):
        s = """network:
  A: x
  A: y"""
        io = StringIO(s)
        try:
            self.definitions.AppendFromStream(io)
        except lib.yamlnaming.BadYamlFormatError, e:
            self.assertTrue('Duplicate/overwrite of key A (existing value ''x''')

    def test_Append_raises_if_data_already_in_dict(self):
        d = {
            'network': { 'A': '10.1.1.1/32' },
            'services': { 'A': '25/tcp' }
        }
        self.definitions.Append(d)
        for k in d.keys():
            with self.assertRaises(lib.yamlnaming.BadYamlFormatError):
                add_dup = { k: { 'A': 'some_dup' } }
                self.definitions.Append(add_dup)

    def test_AppendFromStream_raises_if_data_already_in_dict(self):
        d = {
            'network': { 'A': '10.1.1.1/32' },
            'services': { 'A': '25/tcp' }
        }
        self.definitions.Append(d)
        s = """network:
  A: 10.1.1.1/32"""
        io = StringIO(s)
        # print s, yaml.load(io.read())
        with self.assertRaises(lib.yamlnaming.BadYamlFormatError):
            self.definitions.AppendFromStream(io)



class RecursiveLookup_Test(unittest.TestCase):

    def setUp(self):
        self.caps_pred = lambda x: re.search(r'^[A-Z_]+$', str(x))
        self.lower_pred = lambda x: re.search(r'^[a-z_]+$', str(x))

    def assertLookupEquals(self, d, key, pred, expected, raises=ValueError):
        actual = lib.yamlnaming.YamlNaming.RecursiveLookup(d, key, pred, raises)
        actual = [a[0] for a in actual]
        self.assertEqual(actual, expected)

    def test_lookup_resolves_tokens(self):
        d = { 'A': [1, 'B'], 'B': [2] }
        test_cases = [
            ['A', self.caps_pred, [1, 2]],
            ['B', self.caps_pred, [2]],
            ['A', self.lower_pred, [1, 'B']]  # B not looked up
        ]
        for key, pred, expected in test_cases:
            self.assertLookupEquals(d, key, pred, expected)

    def test_token_in_child_element_is_resolved(self):
        d = {
            'A': [1, 'B'],
            'B': ['C', 2],
            'C': [3]
        }
        self.assertLookupEquals(d, 'A', self.caps_pred, [1,2,3])

    def test_recursive_lookup_attaches_metadata_to_items(self):
        d = {
            'A_TOKEN': [('1', '1_comment'), ('B_TOKEN', 'another_comment')],
            'B_TOKEN': [('C_TOKEN', 'C_comment'), ('2', None)],
            'C_TOKEN': [('3', 'grandchild')]
        }
        pred = lib.yamlnaming.YamlNaming.yaml_token_predicate
        actual = map(str, lib.yamlnaming.YamlNaming.RecursiveLookup(d, 'A_TOKEN', pred, ValueError))
        expected = [
            "('1', '1_comment', 'A_TOKEN', 'A_TOKEN')",
            "('2', None, 'B_TOKEN', 'A_TOKEN')",
            "('3', 'grandchild', 'C_TOKEN', 'A_TOKEN')"
        ]
        self.assertEqual(actual, expected)

    def test_missing_token_definition_throws_appropriate_error(self):
        d = {
            'A': [1, 'B'],
            'B': ['MISSING', 2]
        }
        class MyErr(ValueError):
            pass
        for tok in ('A', 'B', 'Unknown_tok'):
            with self.assertRaises(MyErr):
                lib.yamlnaming.YamlNaming.RecursiveLookup(d, 'A', self.caps_pred, MyErr)


    def test_atom_handled_ok(self):
        p = self.caps_pred
        self.assertLookupEquals({ 'A': 42 }, 'A', p, [42])
        self.assertLookupEquals({ 'A': 'apple' }, 'A', p, ['apple'])

    def test_lookup_with_loops_throws(self):
        d = { 'A': [1, 'B'], 'B': 'A', 'C': 5 }
        self.assertLookupEquals(d, 'C', self.caps_pred, [5])
        for tok in ('A', 'B'):
            with self.assertRaises(lib.yamlnaming.InfiniteLookupLoopError):
                lib.yamlnaming.YamlNaming.RecursiveLookup(d, tok, self.caps_pred)

    def test_lookup_with_loops_returns_helpful_error_msg(self):
        d = { 'A': [1, 'B'], 'B': 'A', 'C': 5 }
        try:
            lib.yamlnaming.YamlNaming.RecursiveLookup(d, 'A', self.caps_pred)
        except lib.yamlnaming.InfiniteLookupLoopError, e:
            self.assertTrue('infinite loop between A and B' in str(e))

        d = { 'A': ['A'] }
        try:
            lib.yamlnaming.YamlNaming.RecursiveLookup(d, 'A', self.caps_pred)
        except lib.yamlnaming.InfiniteLookupLoopError, e:
            self.assertTrue('infinite loop between A and A' in str(e))


class YamlNaming_process_Tests(unittest.TestCase):

    def test_process(self):
        test_cases = [
            [ '   hello', [('hello',None)] ],
            [ 'is  , it  ', [('is',None), ('it',None)] ],
            [ ['me, you''re', 'looking', 'for'], [('me',None), ('you''re',None), ('looking',None), ('for',None)]]
        ]
        for s, expected in test_cases:
            actual = lib.yamlnaming.YamlNaming._process(s)
            self.assertEqual(actual, expected)

    def test_process_distributes_text_comments_to_nodes(self):
        """If a multi-entry line has a comment, it should be shared by all."""
        test_cases = [
            [ '   hello [there]', [('hello', 'there')] ],
            [ 'is  , it  [me]', [('is', 'me'), ('it', 'me')] ],
            [
                ['me, you are [yes, it is]', 'looking', 'for [yes]'],
                [('me', 'yes, it is'),
                 ('you are', 'yes, it is'),
                 ('looking', None),
                 ('for', 'yes')]
            ]
        ]
        for s, expected in test_cases:
            actual = lib.yamlnaming.YamlNaming._process(s)
            self.assertEqual(actual, expected)

def main():
    unittest.main()

if __name__ == '__main__':
    main()


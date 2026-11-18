"""Differential coverage for ordered SRX address-book insertion."""

import collections
import pathlib
import random
import unittest
from unittest import mock

from capirca.lib import junipersrx
from capirca.lib import nacaddr
from capirca.lib import naming
from capirca.lib import policy


def book():
  result = object.__new__(junipersrx.JuniperSRX)
  result.addressbook = collections.OrderedDict()
  return result


@unittest.skipIf(junipersrx._capirca_native is None, 'native extension not installed')
class NativeAddressBookTest(unittest.TestCase):

  def compare(self, batches, initial=None):
    reference, native = book(), book()
    if initial:
      for target in (reference, native):
        target.addressbook['trust'] = collections.defaultdict(list)
        target.addressbook['trust']['net'] = list(initial)
    for zone, addresses in batches:
      for address in addresses:
        reference._BuildAddressBook(zone, address)
      native._BuildAddressBookFromList(zone, addresses)
      self.assertEqual(list(reference.addressbook), list(native.addressbook))
      for key in reference.addressbook:
        expected, actual = reference.addressbook[key], native.addressbook[key]
        self.assertEqual(list(expected), list(actual))
        for name in expected:
          self.assertEqual([id(ip) for ip in expected[name]],
                           [id(ip) for ip in actual[name]])

  def test_first_overlap_and_duplicate_replacement(self):
    left = nacaddr.IP('10.0.0.0/25', comment='left', token='net')
    right = nacaddr.IP('10.0.0.128/25', comment='right', token='net')
    parent = nacaddr.IP('10.0.0.0/24', comment='parent', token='net')
    self.compare([('trust', [parent, left])], [left, left, right])
    result = book()
    result._BuildAddressBookFromList('trust', [left, right, parent])
    self.assertEqual([id(ip) for ip in result.addressbook['trust']['net']],
                     [id(parent), id(right)])

  def test_boundaries_and_aliases(self):
    addresses = [nacaddr.IP(value, token='net') for value in (
        '255.255.255.255/32', '0.0.0.0/32', '::/128',
        'ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128',
        '::ffff:192.0.2.1/128', '0.0.0.0/0', '::/0')]
    self.compare([('trust', []), ('trust', addresses),
                  ('untrust', addresses), ('trust', addresses)])
    result = book()
    result._BuildAddressBookFromList('trust', addresses[:1])
    original_list = result.addressbook['trust']['net']
    result._BuildAddressBookFromList('trust', addresses[-2:])
    self.assertIs(original_list, result.addressbook['trust']['net'])

  def test_seeded_mixed_networks(self):
    rng = random.Random(71205)
    for _ in range(120):
      batches = []
      for _ in range(5):
        addresses = []
        for _ in range(60):
          version = rng.choice((4, 6))
          bits = 32 if version == 4 else 128
          prefix = rng.randrange(bits + 1)
          start = (rng.getrandbits(bits) >> (bits - prefix)) << (bits - prefix)
          cls = nacaddr.IPv4 if version == 4 else nacaddr.IPv6
          address = cls((start, prefix), comment=str(rng.randrange(10)),
                        token='token-%d' % rng.randrange(3))
          address.parent_token = 'group-%d' % rng.randrange(4)
          addresses.append(address)
        batches.append((rng.choice(('trust', 'untrust')), addresses))
      self.compare(batches)

  def test_scoped_ipv6_uses_python_semantics(self):
    addresses = [nacaddr.IP(value, token='net') for value in (
        'fe80::1%eth0/128', 'fe80::1%eth1/128', 'fe80::1/128')]
    self.compare([('trust', addresses[:1]), ('trust', addresses[1:])])

  def test_subclasses_keep_their_subnet_methods(self):
    class SeparateNetwork(nacaddr.IPv4):
      def supernet_of(self, other):
        return False

    addresses = [SeparateNetwork('10.0.0.0/8', token='net'),
                 SeparateNetwork('10.0.0.0/16', token='net')]
    self.compare([('trust', addresses)])

  def test_invalid_native_inputs(self):
    function = junipersrx._capirca_native.address_book_indices
    for values, count in (([], 1), ([(5, 0, 0)], 0),
                          ([(4, 0, 33)], 0), ([(6, 0, 129)], 0),
                          ([(4, 1 << 32, 32)], 0), ([(4, 1, 24)], 0)):
      with self.subTest(values=values, count=count):
        with self.assertRaises(ValueError):
          function(values, count)

  def test_renderer_reaches_native_extension(self):
    root = pathlib.Path(__file__).resolve().parents[2]
    text = (root / 'policies/pol/sample_srx.pol').read_text()
    definitions = naming.Naming(str(root / 'def'))
    original = junipersrx._capirca_native.address_book_indices
    with mock.patch.object(junipersrx._capirca_native, 'address_book_indices',
                           wraps=original) as operation:
      native = str(junipersrx.JuniperSRX(policy.ParsePolicy(text, definitions), 2))
    self.assertGreater(operation.call_count, 0)
    with mock.patch.object(junipersrx, '_capirca_native', None):
      reference = str(junipersrx.JuniperSRX(policy.ParsePolicy(text, definitions), 2))
    self.assertEqual(reference, native)


class AddressBookFallbackTest(unittest.TestCase):

  def test_optional_extension(self):
    result = book()
    addresses = [nacaddr.IP('192.0.2.0/24', token='net')]
    with mock.patch.object(junipersrx, '_capirca_native', None):
      result._BuildAddressBookFromList('trust', addresses)
    self.assertIs(result.addressbook['trust']['net'][0], addresses[0])


if __name__ == '__main__':
  unittest.main()

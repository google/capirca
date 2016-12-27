# Copyright 2007 Google Inc. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Unittest for nacaddr.py module."""

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

__author__ = 'watson@google.com (Tony Watson)'

import unittest

from lib import nacaddr


class NacaddrUnitTest(unittest.TestCase):
  """Unit Test for nacaddr.py.

     nacaddr class extends ipaddr by adding .text fields to allow
     comments for each of the IPv4 and IPv6 classes.
  """

  def setUp(self):
    self.addr1 = nacaddr.IPv4('10.0.0.0/8', 'The 10 block')
    self.addr2 = nacaddr.IPv6('DEAD:BEEF:BABE:FACE:DEAF:FEED:C0DE:F001/64',
                              'An IPv6 Address')

  def testCollapsing(self):
    ip1 = nacaddr.IPv4('1.1.0.0/24', 'foo')
    ip2 = nacaddr.IPv4('1.1.1.0/24', 'foo')
    ip3 = nacaddr.IPv4('1.1.2.0/24', 'baz')
    ip4 = nacaddr.IPv4('1.1.3.0/24')
    ip5 = nacaddr.IPv4('1.1.4.0/24')

    # stored in no particular order b/c we want CollapseAddr to call [].sort
    # and we want that sort to call nacaddr.IP.__cmp__() on our array members
    ip6 = nacaddr.IPv4('1.1.0.0/22')

    # check that addreses are subsumed properlly.
    collapsed = nacaddr.CollapseAddrList([ip1, ip2, ip3, ip4, ip5, ip6])
    self.assertEqual(len(collapsed), 2)
    # test that the comments are collapsed properlly, and that comments aren't
    # added to addresses that have no comments.
    self.assertListEqual([collapsed[0].text, collapsed[1].text],
                         ['foo, baz', ''])
    self.assertListEqual(collapsed, [nacaddr.IPv4('1.1.0.0/22'),
                                     nacaddr.IPv4('1.1.4.0/24')])

    # test that two addresses are supernet'ed properlly
    collapsed = nacaddr.CollapseAddrList([ip1, ip2])
    self.assertEqual(len(collapsed), 1)
    self.assertEqual(collapsed[0].text, 'foo')
    self.assertListEqual(collapsed, [nacaddr.IPv4('1.1.0.0/23')])

    ip_same1 = ip_same2 = nacaddr.IPv4('1.1.1.1/32')
    self.assertListEqual(nacaddr.CollapseAddrList([ip_same1, ip_same2]),
                         [ip_same1])
    ip1 = nacaddr.IPv6('::2001:1/100')
    ip2 = nacaddr.IPv6('::2002:1/120')
    ip3 = nacaddr.IPv6('::2001:1/96')
    # test that ipv6 addresses are subsumed properlly.
    collapsed = nacaddr.CollapseAddrList([ip1, ip2, ip3])
    self.assertListEqual(collapsed, [ip3])

  def testNacaddrV4Comment(self):
    self.assertEqual(self.addr1.text, 'The 10 block')

  def testNacaddrV6Comment(self):
    self.assertEqual(self.addr2.text, 'An IPv6 Address')

  def testSupernetting(self):
    self.assertEqual(self.addr1.Supernet().text, 'The 10 block')
    self.assertEqual(self.addr2.Supernet().text, 'An IPv6 Address')
    self.assertEqual(self.addr1.Supernet().prefixlen, 7)
    self.assertEqual(self.addr2.Supernet().prefixlen, 63)

    token_ip = nacaddr.IP('1.1.1.0/24', token='FOO_TOKEN')
    self.assertEqual(token_ip.Supernet().token, 'FOO_TOKEN')
    self.assertEqual(nacaddr.IP('0.0.0.0/0').Supernet(),
                     nacaddr.IP('0.0.0.0/0'))
    self.assertEqual(nacaddr.IP('::0/0').Supernet(), nacaddr.IP('::0/0'))

    self.assertRaises(nacaddr.PrefixlenDiffInvalidError,
                      nacaddr.IP('1.1.1.0/24').Supernet, 25)
    self.assertRaises(nacaddr.PrefixlenDiffInvalidError,
                      nacaddr.IP('::1/64').Supernet, 65)

  def testAddressListExclusion(self):
    a1 = nacaddr.IPv4('1.1.1.0/24')
    a2 = nacaddr.IPv4('10.0.0.0/24')
    b1 = nacaddr.IPv4('1.1.1.1/32')
    b2 = nacaddr.IPv4('10.0.0.25/32')
    b3 = nacaddr.IPv4('192.168.0.0/16')

    expected = [nacaddr.IPv4('1.1.1.0/32'), nacaddr.IPv4('1.1.1.2/31'),
                nacaddr.IPv4('1.1.1.4/30'), nacaddr.IPv4('1.1.1.8/29'),
                nacaddr.IPv4('1.1.1.16/28'), nacaddr.IPv4('1.1.1.32/27'),
                nacaddr.IPv4('1.1.1.64/26'), nacaddr.IPv4('1.1.1.128/25'),
                nacaddr.IPv4('10.0.0.0/28'), nacaddr.IPv4('10.0.0.16/29'),
                nacaddr.IPv4('10.0.0.24/32'), nacaddr.IPv4('10.0.0.26/31'),
                nacaddr.IPv4('10.0.0.28/30'), nacaddr.IPv4('10.0.0.32/27'),
                nacaddr.IPv4('10.0.0.64/26'), nacaddr.IPv4('10.0.0.128/25')]

    self.assertListEqual(nacaddr.AddressListExclude([a1, a2], [b1, b2, b3]),
                         expected)
    # [1,2,3] + [4,5,6] = [1,2,3,4,5,6].  this is basically the same test as
    # above but i think it's a little more readable
    self.assertListEqual(nacaddr.AddressListExclude([a1, a2], [b1, b2, b3]),
                         a1.AddressExclude(b1) + a2.AddressExclude(b2))

  def testComplexAddressListExcludesion(self):
    # this is a big fugly test. there was a bug in AddressListExclude
    # which manifested itself when more than one member of the excludes
    # list was a part of the same superset token.
    #
    # for example, it used to be like so:
    #  excludes = ['1.1.1.1/32', '1.1.1.2/32']
    #  superset = ['1.1.1.0/30']
    #
    # '1.1.1.0/30'.AddressExclude('1.1.1.1/32') ->
    #    ['1.1.1.0/32', '1.1.1.2/32', '1.1.1.3/32']
    # '1.1.1.0/30'.AddressExclude('1.1.1.2/32') ->
    #    ['1.1.1.0/32', '1.1.1.1/32', '1.1.1.3/32']
    #
    # yet combining those two results gives you
    #   ['1.1.1.0/32', '1.1.1.1/32', '1.1.1.2/32' '1.1.1.3/32'], or
    #   '1.1.1.0/30', which clearly isn't right.

    excludes = [nacaddr.IPv4('10.0.0.0/23'), nacaddr.IPv4('10.1.0.0/16')]
    superset = [nacaddr.IPv4('0.0.0.0/0')]

    expected = [nacaddr.IPv4('0.0.0.0/5'), nacaddr.IPv4('8.0.0.0/7'),
                nacaddr.IPv4('10.0.2.0/23'), nacaddr.IPv4('10.0.4.0/22'),
                nacaddr.IPv4('10.0.8.0/21'), nacaddr.IPv4('10.0.16.0/20'),
                nacaddr.IPv4('10.0.32.0/19'), nacaddr.IPv4('10.0.64.0/18'),
                nacaddr.IPv4('10.0.128.0/17'), nacaddr.IPv4('10.2.0.0/15'),
                nacaddr.IPv4('10.4.0.0/14'), nacaddr.IPv4('10.8.0.0/13'),
                nacaddr.IPv4('10.16.0.0/12'), nacaddr.IPv4('10.32.0.0/11'),
                nacaddr.IPv4('10.64.0.0/10'), nacaddr.IPv4('10.128.0.0/9'),
                nacaddr.IPv4('11.0.0.0/8'), nacaddr.IPv4('12.0.0.0/6'),
                nacaddr.IPv4('16.0.0.0/4'), nacaddr.IPv4('32.0.0.0/3'),
                nacaddr.IPv4('64.0.0.0/2'), nacaddr.IPv4('128.0.0.0/1')]

    self.assertListEqual(nacaddr.AddressListExclude(superset, excludes),
                         expected)

  def testAddressListExcludeCaseOne(self):
  # Small block eliminated by large block, and an extra block that stays.
  # For both IP versions.
    superset = [nacaddr.IPv4('200.0.0.0/24'), nacaddr.IPv4('10.1.0.0/24'),
                nacaddr.IPv6('200::/56'), nacaddr.IPv6('10:1::/56')]
    excludes = [nacaddr.IPv6('10::/16'), nacaddr.IPv4('10.0.0.0/8')]
    expected = [nacaddr.IPv4('200.0.0.0/24'), nacaddr.IPv6('200::/56')]
    self.assertListEqual(nacaddr.AddressListExclude(superset, excludes),
                         expected)

  def testAddressListExcludeCaseTwo(self):
  # Two blocks out of the middle of a large block.
    superset = [nacaddr.IPv4('200.0.0.0/24'), nacaddr.IPv4('10.0.0.0/8'),
                nacaddr.IPv6('200::/56'), nacaddr.IPv6('10::/16')]
    excludes = [nacaddr.IPv6('10:8000::/18'), nacaddr.IPv6('10:4000::/18'),
                nacaddr.IPv4('10.128.0.0/10'), nacaddr.IPv4('10.64.0.0/10')]
    expected = [nacaddr.IPv4('10.0.0.0/10'), nacaddr.IPv4('10.192.0.0/10'),
                nacaddr.IPv4('200.0.0.0/24'),
                nacaddr.IPv6('10::/18'), nacaddr.IPv6('10:c000::/18'),
                nacaddr.IPv6('200::/56')]
    self.assertListEqual(nacaddr.AddressListExclude(superset, excludes),
                         expected)

  def testAddressListExcludeCaseThree(self):
  # Two blocks off both ends of a large block.
    superset = [nacaddr.IPv4('200.0.0.0/24'), nacaddr.IPv4('10.0.0.0/8'),
                nacaddr.IPv6('200::/56'), nacaddr.IPv6('10::/16')]
    excludes = [nacaddr.IPv6('10::/18'), nacaddr.IPv6('10:c000::/18'),
                nacaddr.IPv4('10.0.0.0/10'), nacaddr.IPv4('10.192.0.0/10')]
    expected = [nacaddr.IPv4('10.64.0.0/10'), nacaddr.IPv4('10.128.0.0/10'),
                nacaddr.IPv4('200.0.0.0/24'),
                nacaddr.IPv6('10:4000::/18'), nacaddr.IPv6('10:8000::/18'),
                nacaddr.IPv6('200::/56')]
    self.assertListEqual(nacaddr.AddressListExclude(superset, excludes),
                         expected)

  def testAddressListExcludeCaseFour(self):
  # IPv6 does not affect IPv4
    superset = [nacaddr.IPv4('0.0.0.0/0')]
    excludes = [nacaddr.IPv6('::/0')]
    expected = [nacaddr.IPv4('0.0.0.0/0')]
    self.assertListEqual(nacaddr.AddressListExclude(superset, excludes),
                         expected)

  def testAddressListExcludeCaseFive(self):
  # IPv6 does not affect IPv4
    superset = [nacaddr.IPv6('::/0')]
    excludes = [nacaddr.IPv4('0.0.0.0/0')]
    expected = [nacaddr.IPv6('::/0')]
    self.assertListEqual(nacaddr.AddressListExclude(superset, excludes),
                         expected)

  def testAddressListExcludeCaseSix(self):
  # IPv6 does not affect IPv4
    superset = [nacaddr.IPv6('0::ffff:0.0.0.0/96')]
    excludes = [nacaddr.IPv4('0.0.0.0/0')]
    expected = [nacaddr.IPv6('0::ffff:0.0.0.0/96')]
    self.assertListEqual(nacaddr.AddressListExclude(superset, excludes),
                         expected)

if __name__ == '__main__':
  unittest.main()

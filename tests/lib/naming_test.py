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

"""Unittest for naming.py module."""

__author__ = 'watson@google.com (Tony Watson)'

import io
import unittest
import os
import inspect

from lib import nacaddr
from lib import naming


class NamingUnitTest(unittest.TestCase):
  """Unit Test for naming.py.

     The Naming class allows us to specify if we want to use arrays of text
     instead of files.  Most of the tests below create an empty Naming class.
     To populate the class with data, we simply pass our test data in arrays
     to the ParseList method, or in some cases, pass an io.BytesIO stream.
  """

  def setUp(self):
    self.defs = naming.Naming(None)
    servicedata = []
    servicedata.append('SVC1 = 80/tcp 81/udp 82/tcp')
    servicedata.append('SVC2 = 80/tcp 81/udp 82/tcp SVC2')
    servicedata.append('SVC3 = 80/tcp 81/udp')
    servicedata.append('SVC4 = 80/tcp # some service')
    servicedata.append('TCP_90 = 90/tcp')
    servicedata.append('SVC5 = TCP_90')
    servicedata.append('SVC6 = SVC1 SVC5')
    networkdata = []
    networkdata.append('NET1 = 10.1.0.0/8 # network1')
    networkdata.append('NET2 = 10.2.0.0/16 # network2.0')
    networkdata.append('       NET1')
    networkdata.append('9OCLOCK = 1.2.3.4/32 # 9 is the time')
    networkdata.append('FOOBAR = 9OCLOCK')
    networkdata.append('FOO_V6 = ::FFFF:FFFF:FFFF:FFFF')
    networkdata.append('BAR_V6 = ::1/128')
    networkdata.append('BAZ = FOO_V6')
    networkdata.append('      BAR_V6')
    networkdata.append('BING = NET1')
    networkdata.append('       FOO_V6')

    self.defs.ParseServiceList(servicedata)
    self.defs.ParseNetworkList(networkdata)

  def testCommentedServices(self):
    self.assertEqual(self.defs.GetService('SVC4'), ['80/tcp'])
    self.assertListEqual(self.defs.GetServiceByProto('SVC4', 'tcp'),
                         ['80'])

  def testBadGetRequest(self):
    """Test proper handling of a non-existant service request."""
    self.assertRaises(naming.UndefinedServiceError, self.defs.GetService, 'FOO')
    self.assertRaises(naming.UndefinedServiceError, self.defs.GetServiceByProto,
                      'FOO', 'tcp')

  def testGetServiceRecursion(self):
    """Ensure we don't slip into recursion hell when object contains itself."""
    self.assertListEqual(self.defs.GetService('SVC2'),
                         ['80/tcp', '81/udp', '82/tcp'])

  def testGetService(self):
    """Verify proper results from a service lookup request."""
    self.assertListEqual(self.defs.GetService('SVC1'),
                         ['80/tcp', '81/udp', '82/tcp'])

  def testBadProtocol(self):
    """Test proper handling of a non-existant service request."""
    self.assertListEqual(self.defs.GetServiceByProto('SVC1', 'fud'), [])

  def testGetServiceByProto(self):
    self.assertListEqual(self.defs.GetServiceByProto('SVC1', 'tcp'),
                         ['80', '82'])

  def testGetServiceByProtoWithoutProtocols(self):
    """Ensure services with protocol are not returned when type is specified."""
    self.assertListEqual(self.defs.GetServiceByProto('SVC3', 'tcp'), ['80'])

  def testNetworkComment(self):
    self.assertEqual(self.defs.GetNetAddr('NET1')[0].text, 'network1')

  def testNestedNetworkComment(self):
    self.assertEqual(self.defs.GetNetAddr('NET2')[1].text, 'network1')

  def testUndefinedAddress(self):
    self.assertRaises(naming.UndefinedAddressError, self.defs.GetNetAddr, 'FOO')

  def testNamespaceCollisionError(self):
    badservicedata = []
    badservicedata.append('SVC1 = 80/tcp')
    badservicedata.append('SVC1 = 81/udp')
    testdefs = naming.Naming(None)
    self.assertRaises(naming.NamespaceCollisionError,
                      testdefs.ParseServiceList, badservicedata)

  def testNetworkAddress(self):
    self.assertListEqual(self.defs.GetNetAddr('NET1'),
                         [nacaddr.IPv4('10.0.0.0/8')])

  def testInet6Address(self):
    self.assertListEqual(self.defs.GetNetAddr('BAZ'),
                         [nacaddr.IPv6('::FFFF:FFFF:FFFF:FFFF'),
                          nacaddr.IPv6('::1/128')])

  def testMixedAddresses(self):
    self.assertListEqual(self.defs.GetNetAddr('BING'),
                         [nacaddr.IPv4('10.0.0.0/8'),
                          nacaddr.IPv6('::FFFF:FFFF:FFFF:FFFF')])
    # same thing but letting nacaddr decide which v4 or v6.
    self.assertListEqual(self.defs.GetNetAddr('BING'),
                         [nacaddr.IP('10.0.0.0/8'),
                          nacaddr.IP('::FFFF:FFFF:FFFF:FFFF')])

  def testNestedServices(self):
    self.assertListEqual(self.defs.GetServiceByProto('SVC6', 'tcp'),
                         ['80', '82', '90'])

  def testServiceParents(self):
    """SVC6 contains SVC5 which contains TCP_90 which contains 90/tcp."""
    self.assertListEqual(self.defs.GetServiceParents('90/tcp'),
                         ['TCP_90', 'SVC5', 'SVC6'])

  def testNetParents(self):
    """BIN & NET2 contain NET1, BING & BAZ contain FOO_V6."""
    self.assertItemsEqual(self.defs.GetNetParents('NET1'),
                          ['BING', 'NET2'])
    self.assertItemsEqual(self.defs.GetNetParents('FOO_V6'), ['BING', 'BAZ'])

  def testGetIpParents(self):
    """Ensure GetIpParents returns proper results."""
    self.assertListEqual(self.defs.GetIpParents('10.11.12.13/32'),
                         ['BING', 'NET1', 'NET2'])

  def testUndefinedTokenNesting(self):
    bad_servicedata = ['FOO = 7/tcp BAR']
    bad_networkdata = ['NETGROUP = 10.0.0.0/8 FOOBAR']
    baddefs = naming.Naming(None)
    baddefs.ParseServiceList(bad_servicedata)
    baddefs.ParseNetworkList(bad_networkdata)
    self.assertRaises(naming.UndefinedServiceError,
                      baddefs._CheckUnseen, 'services')
    self.assertRaises(naming.UndefinedAddressError,
                      baddefs._CheckUnseen, 'networks')

  def testParseNetFile(self):
    filedefs = naming.Naming(None)
    data = io.BytesIO('FOO = 127.0.0.1 # some network\n')
    filedefs._ParseFile(data, 'networks')
    self.assertEqual(filedefs.GetNetAddr('FOO'), [nacaddr.IPv4('127.0.0.1')])

  def testParseServiceFile(self):
    filedefs = naming.Naming(None)
    data = io.BytesIO('HTTP = 80/tcp\n')
    filedefs._ParseFile(data, 'services')
    self.assertEqual(filedefs.GetService('HTTP'), ['80/tcp'])


class Naming_Characterization_Tests(unittest.TestCase):
  """Tests to ensure that Naming works with the given test data file."""

  def setUp(self):
    # Not ideal to use characterization data in unit tests,
    # but better than nothing.
    curr_dir = os.path.dirname(os.path.abspath(inspect.getfile(inspect.currentframe())))
    self.def_dir = os.path.join(curr_dir, '..', 'characterization_data', 'def')
    self.assertTrue(os.path.exists(self.def_dir))
    self.naming = naming.Naming(self.def_dir)

  def test_GetIpParents(self):
    data = [
      ['10.1.1.1', ['ANY', 'INTERNAL', 'RESERVED', 'RFC1918']],
      [nacaddr.IP('10.1.1.1/32'), ['ANY', 'INTERNAL', 'RESERVED', 'RFC1918']],
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
      with self.assertRaises(naming.UndefinedServiceError):
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
      self.assertEqual(actual, map(nacaddr.IPv4, expected))

  def test_GetNet_adds_metadata_to_address(self):
    """The metadata (comments, etc) is used during ACL generation."""
    def to_s(a):
      return ','.join([str(a), a.text, a.token, a.parent_token])
    actual = map(to_s, self.naming.GetNetAddr('INTERNAL'))
    expected = [
      '10.0.0.0/8,non-public,RFC1918,INTERNAL',
      '172.16.0.0/12,non-public,RFC1918,INTERNAL',
      '192.168.0.0/16,non-public,RFC1918,INTERNAL'
    ]
    self.assertEqual(actual, expected)

  def test_GetNet_raises_if_unknown(self):
    with self.assertRaises(naming.UndefinedAddressError):
      self.naming.GetNetAddr('SOME_UNDEFINED_TOKEN')

  def test_parseServiceList(self):
    tok = 'SOME_UNKNOWN_TOKEN'
    with self.assertRaises(naming.UndefinedServiceError):
      self.naming.GetService(tok)
    self.naming.ParseServiceList(['SOME_UNKNOWN_TOKEN = 888/tcp'])
    self.assertEqual(self.naming.GetService(tok), ['888/tcp'])

  def test_parseNetworkList(self):
    tok = 'SOME_UNKNOWN_TOKEN'
    with self.assertRaises(naming.UndefinedAddressError):
      self.naming.GetNet(tok)
      self.naming.ParseNetworkList(['SOME_UNKNOWN_TOKEN = 10.1.1.1/32'])
      self.assertEqual(self.naming.GetNet(tok), [nacaddr.IPv4('10.1.1.1/32')])


if __name__ == '__main__':
  unittest.main()

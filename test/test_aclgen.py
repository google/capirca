import unittest
import sys
import os
from cStringIO import StringIO

import aclgen

class Test_AclGen(unittest.TestCase):

  def setUp(self):
    # Capture output during tests.
    self.iobuff = StringIO()
    sys.stderr = sys.stdout = self.iobuff

  def tearDown(self):
    sys.stdout = sys.__stdout__
    sys.stderr = sys.__stderr__

  def test_smoke_test_generates_successfully_with_no_args(self):
    aclgen.main([])

    expected_output = """writing ./filters/sample_cisco_lab.acl
writing ./filters/sample_gce.gce
writing ./filters/sample_ipset
WARNING:root:WARNING: Term accept-traceroute in policy LOOPBACK is expired and will not be rendered.
writing ./filters/sample_juniper_loopback.jcl
writing ./filters/sample_multitarget.jcl
writing ./filters/sample_multitarget.acl
writing ./filters/sample_multitarget.ipt
writing ./filters/sample_multitarget.asa
writing ./filters/sample_multitarget.demo
writing ./filters/sample_multitarget.eacl
writing ./filters/sample_multitarget.bacl
writing ./filters/sample_multitarget.xacl
writing ./filters/sample_multitarget.jcl
writing ./filters/sample_multitarget.acl
writing ./filters/sample_multitarget.ipt
writing ./filters/sample_multitarget.asa
WARNING:root:WARNING: Term accept-traceroute in policy inet is expired and will not be rendered.
WARNING:root:WARNING: Action ['next'] in Term ratelimit-large-dns is not valid and will not be rendered.
writing ./filters/sample_nsxv.nsx
writing ./filters/sample_packetfilter.pf
writing ./filters/sample_speedway.ipt
writing ./filters/sample_speedway.ipt
writing ./filters/sample_speedway.ipt
writing ./filters/sample_srx.srx
22 filters rendered
"""

    def subtract_list(lhs, rhs):
      return '; '.join([el for el in lhs if el not in rhs])

    expected = expected_output.split("\n")
    actual = self.iobuff.getvalue().split("\n")
    not_in_actual = subtract_list(expected, actual)
    not_in_expected = subtract_list(actual, expected)
    self.assertEqual('', not_in_actual, 'Not in actual: ' + not_in_actual)
    self.assertEqual('', not_in_expected, 'Not in expected: ' + not_in_expected)

  def test_generate_single_policy(self):
    aclgen.main(['-p', 'policies/sample_cisco_lab.pol'])

    expected_output = """writing ./filters/sample_cisco_lab.acl
1 filters rendered
"""
    self.assertEquals(expected_output, self.iobuff.getvalue())



def main():
    unittest.main()

if __name__ == '__main__':
    main()


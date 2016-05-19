# Copyright 2015 The Capirca Project Authors All Rights Reserved.
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

    self.assertEquals(expected_output, self.iobuff.getvalue())

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


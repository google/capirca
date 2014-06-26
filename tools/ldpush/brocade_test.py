#!/usr/bin/python
#
# Copyright 2013 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""Tests for brocade."""

import unittest
import brocade
import fake_ssh_connection


class BrocadeMlxDeviceTest(unittest.TestCase):

  def setUp(self):
    self.device = brocade.BrocadeMlxDevice(host='bx01.sql01')

  def testCmd(self):
    def DoCmd():
      self.device.Cmd('show interfaces')
    self.assertRaises(AttributeError, DoCmd)

  def testGetConfig(self):
    def DoGetConfig():
      self.device.GetConfig('running-config')
    self.assertRaises(AttributeError, DoGetConfig)

  def testDisconnect(self):
    self.assertIsNone(self.device._Disconnect())


class BrocadeTiDeviceTest(unittest.TestCase):

  def setUp(self):
    cli_prompt = 'SSH@cdzncsa1switch#'
    config_snippet = """\r
Current configuration:\r
!\r
ver 04.2.00d
!\r
interface ethernet 17\r
 port-name cs01.cd.xe-5/8 [T=naFP]\r
 ip address 10.240.129.82 255.255.255.252\r
 link-aggregate configure timeout short\r
 link-aggregate configure key 10001\r
 link-aggregate active\r
!
end\r
\r
%s""" % cli_prompt

    self.show_running_config_result = """Current configuration:
!
ver 04.2.00d
!
interface ethernet 17
 port-name cs01.cd.xe-5/8 [T=naFP]
 ip address 10.240.129.82 255.255.255.252
 link-aggregate configure timeout short
 link-aggregate configure key 10001
 link-aggregate active
!
end

"""
    # Commands and responses from the perspective of the device.
    command_response_dict = {
        '__logged_in__': cli_prompt,
        'skip-page-display\r': 'Disable page display mode\r\n%s' % cli_prompt,
        'show running-config\r': config_snippet}
    ssh_client = fake_ssh_connection.FakeSshClient(command_response_dict)
    self.device = brocade.BrocadeTiDevice(
        host='cdzncsa1switch', ssh_client=ssh_client)

  def testShowRunningConfig(self):
    self.device._Connect(username='userX', password='passwordX',
                         enable_password='enableX')
    response = self.device._Cmd('show running-config')
    self.assertEqual(self.show_running_config_result, response)


if __name__ == '__main__':
  unittest.main()

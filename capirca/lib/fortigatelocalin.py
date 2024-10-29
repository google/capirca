# Copyright 2022 Google Inc. All Rights Reserved.
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

"""Fortigate local-in generator.

This is a subclass of Fortigate generator.
"""

from capirca.lib import fortigate

class FortigateLocalIn(fortigate.Fortigate):
  """Fortigate local-in generator."""

  _PLATFORM = 'fortigatelocalin'

  def __str__(self):
    fw_policies = self._get_fw_policies()

    start_sys_settings = ['config sys setting']
    start_addresses_v4 = ['config firewall address']
    start_addresses_v6 = ['config firewall address6']
    start_addrgrps_v4 = ['config firewall addrgrp']
    start_addrgrps_v6 = ['config firewall addrgrp6']
    start_services = ['config firewall service custom']
    start_svcgrps = ['config firewall service group']
    start_schedules = ['config firewall schedule onetime']
    start_policies = ['config firewall local-in-policy']
    end = ['end']

    sys_settings = []
    if self._obj_container.get_sys_settings():
      sys_settings = start_sys_settings + \
               self._obj_container.get_sys_settings() + \
               end + ['']

    fw_addresses = []
    if self._obj_container.get_fw_addresses(4):
      fw_addresses += start_addresses_v4 + \
              self._obj_container.get_fw_addresses(4) + \
              end + ['']
    if self._obj_container.get_fw_addresses(6):
      fw_addresses += start_addresses_v6 + \
              self._obj_container.get_fw_addresses(6) + \
              end + ['']

    fw_addr_grps = []
    if self._obj_container.get_fw_addrgrps(4):
      fw_addr_grps += start_addrgrps_v4 + \
              self._obj_container.get_fw_addrgrps(4) + \
              end + ['']
    if self._obj_container.get_fw_addrgrps(6):
      fw_addr_grps += start_addrgrps_v6 + \
              self._obj_container.get_fw_addrgrps(6) + \
              end + ['']

    fw_services = []
    if self._obj_container.get_fw_services():
      fw_services = start_services + \
              self._obj_container.get_fw_services() + \
              end + ['']

    fw_svc_grps = []
    if self._obj_container.get_fw_svcgrps():
      fw_svc_grps = start_svcgrps + \
              self._obj_container.get_fw_svcgrps() + \
              end + ['']

    fw_schedules = []
    if self._obj_container.get_fw_schedules():
      fw_schedules = start_schedules + \
               self._obj_container.get_fw_schedules() + \
               end + ['']

    fw_policies = start_policies + fw_policies + end

    target = sys_settings + fw_addresses + fw_addr_grps + \
         fw_services + fw_svc_grps + fw_schedules + fw_policies

    return '\n'.join(target)
  
class Error(Exception):
  pass


class FilterDirectionError(Error):
  pass

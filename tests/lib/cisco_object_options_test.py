# Copyright 2026 Google Inc. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Regression tests for Cisco object-group rule options."""

from absl.testing import absltest
from absl.testing import parameterized
from capirca.lib import cisco
from capirca.lib import ciscoxr
from capirca.lib import naming
from capirca.lib import policy


class ObjectGroupOptionsTest(parameterized.TestCase):
  """Exercise shared Cisco and Cisco XR object-group option rendering."""

  @parameterized.product(
      platform=('cisco', 'ciscoxr'),
      family=('object-group', 'object-group-inet6'),
      option=('', 'established', 'tcp-established'),
      logging=(False, True))
  def test_established_and_logging(self, platform, family, option, logging):
    """Preserve TCP state and logging without applying state to UDP."""
    option_line = f'option:: {option}' if option else ''
    logging_line = 'logging:: true' if logging else ''
    pol = policy.ParsePolicy(f'''
header {{
  target:: {platform} TEST {family}
}}
term replies {{
  protocol:: tcp udp
  {option_line}
  {logging_line}
  action:: accept
}}
''', naming.Naming())
    generator = cisco.Cisco if platform == 'cisco' else ciscoxr.CiscoXR
    result = str(generator(pol, 0))
    suffix = ' log' if logging else ''
    ports = ' port-group 1024-65535' if option == 'established' else ''
    established = ' established' if option else ''
    self.assertIn(f' permit tcp any any{ports}{established}{suffix}\n', result)
    self.assertIn(f' permit udp any any{ports}{suffix}\n', result)


if __name__ == '__main__':
  absltest.main()

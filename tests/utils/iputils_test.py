import pytest

import pathlib

from capirca.utils import iputils
from capirca.lib import nacaddr


file_directory = pathlib.Path(__file__).parent.absolute()
exclude_address_testcases = []
with open(str(file_directory)+"/address_exclude_test_cases.txt", 'r') as f:
  for line in f:
    ipstr, exstrs, restrs = line.strip().split(' ')
    ip = nacaddr.IP(ipstr)
    exclude_ips = list(map(nacaddr.IP, exstrs.split(',')))
    expected_results = []
    for i in restrs.split(';'):
      result_strings = i.split(',')
      ip_map = map(nacaddr.IP, result_strings)
      ip_list = list(ip_map)
      expected_results.append(ip_list)
    for ex, res in zip(exclude_ips, expected_results):
      exclude_address_testcases.append((ip, ex, res))

class TestIPUtils:
  @pytest.mark.unit
  @pytest.mark.parametrize("ip,exclude,expected", exclude_address_testcases)
  def test_exclude_address(self, ip, exclude, expected):
    result = iputils.exclude_address(ip, exclude)

    assert list(result) == expected


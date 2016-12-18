# Copyright 2014 Google Inc. All Rights Reserved.
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

"""Tests for discontinuous subnet mask summarizer."""

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

__author__ = 'vklimovs@google.com (Vjaceslavs Klimovs)'

import os

import random
import time
import unittest

from lib import summarizer
import ipaddr
import logging


class SummarizerTest(unittest.TestCase):

  @classmethod
  def setUpClass(cls):
    random_seed = int(time.time())
    value = os.environ.get('TEST_RANDOM_SEED', '')
    try:
      random_seed = int(value)
    except ValueError:
      pass
    logging.info('Seeding random generator with seed %d', random_seed)
    random.seed(random_seed)

  def testToDottedQuad(self):
    net = (1<<32, 4294967264)
    self.assertRaises(ValueError)
    net = (3232235584, 1<<16)
    self.assertRaises(ValueError)
    net = (3232235584, 4294967264)
    self.assertEquals(summarizer.ToDottedQuad(net),
                      ('192.168.0.64', '255.255.255.224'))
    net = (3232235584, 4294901984)
    self.assertEquals(summarizer.ToDottedQuad(net, negate=True),
                      ('192.168.0.64', '0.0.255.31'))

    test_data = [((3232235584, 4294967295), True, ('192.168.0.64', '32')),
                 ((3232235584, 4294901760), True, ('192.168.0.64', '16')),
                 ((3232235584, 4294967294), True, ('192.168.0.64', '31')),
                 ((3232235584, 4290772992), True, ('192.168.0.64', '10')),
                 ((3232235584, 4294966016), True, ('192.168.0.64',
                                                   '255.255.251.0')),
                 ((3232235584, 4294901504), True, ('192.168.0.64',
                                                   '255.254.255.0'))]

    for net, nondsm, expected in test_data:
      self.assertEquals(summarizer.ToDottedQuad(net, nondsm=nondsm), expected)

  def testInt32ToDottedQuad(self):
    self.assertEquals(summarizer._Int32ToDottedQuad(3232235584),
                      '192.168.0.64')

  def testSummarizeEmptyList(self):
    nets = []
    result = summarizer.Summarize(nets)
    self.assertEqual(result, [])

  def testSummarizeNoNetworks(self):
    nets = []
    for octet in range(0, 256):
      net = ipaddr.IPv4Network('192.' + str(255 - octet) + '.' +
                               str(octet) + '.64/27')
      nets.append(net)
    random.shuffle(nets)
    result = summarizer.Summarize(nets)
    self.assertEqual(len(result), 256)

  def testSummarizeSomeNetworks(self):
    nets = [
        # continiously summarizable to one /25
        ipaddr.IPv4Network('192.168.0.0/27'),
        ipaddr.IPv4Network('192.168.0.32/27'),
        ipaddr.IPv4Network('192.168.0.64/27'),
        ipaddr.IPv4Network('192.168.0.96/27'),
        # discontiniously summarizable with above
        ipaddr.IPv4Network('128.168.0.0/25'),
        # not summarizable with above
        ipaddr.IPv4Network('10.0.0.0/8'),
    ]
    for octet in range(0, 256):
      net = ipaddr.IPv4Network('172.16.' + str(octet) + '.96/30')
      nets.append(net)
    random.shuffle(nets)
    result = summarizer.Summarize(nets)
    self.assertEquals(result, [(167772160, 4278190080),
                               (2158493696, 3221225344),
                               (2886729824, 4294902012)])

  def testSummarizeAllNetworks(self):
    nets = []
    for octet in range(0, 256):
      net = ipaddr.IPv4Network('192.168.' + str(octet) + '.64/27')
      nets.append(net)
    random.shuffle(nets)
    result = summarizer.Summarize(nets)
    # summarizes to 192.168.0.64 / 255.255.0.224
    self.assertEquals(result, [(3232235584, 4294901984)])

  def testSummarizeToAllSpace(self):
    nets = [
        ipaddr.IPv4Network('0.0.0.0/1'),
        ipaddr.IPv4Network('128.0.0.0/1'),
    ]
    random.shuffle(nets)
    result = summarizer.Summarize(nets)
    self.assertEquals(result, [(0, 0)])

  def testIpaddrToTuple(self):
    net = ipaddr.IPv4Network('192.168.0.64/27')
    self.assertEqual(summarizer._IpaddrToTuple(net), (3232235584, 4294967264))

  def testToPrettyBinaryFormat(self):
    # 192.168.0.64
    self.assertEqual(summarizer._ToPrettyBinaryFormat(3232235584),
                     '11000000 10101000 00000000 01000000')
    # 8.8.8.8
    self.assertEqual(summarizer._ToPrettyBinaryFormat(134744072),
                     '00001000 00001000 00001000 00001000')
    # 0.0.0.0
    self.assertEqual(summarizer._ToPrettyBinaryFormat(0),
                     '00000000 00000000 00000000 00000000')
    # fc00::1
    self.assertEqual(
        summarizer._ToPrettyBinaryFormat(
            334965454937798799971759379190646833153),
        '11111100 00000000 00000000 00000000 00000000 00000000 00000000 '
        '00000000 00000000 00000000 00000000 00000000 00000000 00000000 '
        '00000000 00000001')


if __name__ == '__main__':
  unittest.main()


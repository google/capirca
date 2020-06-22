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

import os

import random
import time
import unittest

from absl import logging
from capirca.lib import nacaddr
from capirca.lib import summarizer


class SummarizerTest(unittest.TestCase):

  def setUp(self):
    super(SummarizerTest, self).setUp()
    random_seed = int(time.time())
    value = os.environ.get('TEST_RANDOM_SEED', '')
    try:
      random_seed = int(value)
    except ValueError:
      pass
    logging.info('Seeding random generator with seed %d', random_seed)
    random.seed(random_seed)

  def testToDottedQuad(self):
    net = summarizer.DSMNet(1<<32, 4294967264)
    self.assertRaises(ValueError)
    net = summarizer.DSMNet(3232235584, 1<<16)
    self.assertRaises(ValueError)
    net = summarizer.DSMNet(3232235584, 4294967264)
    self.assertEqual(summarizer.ToDottedQuad(net),
                     ('192.168.0.64', '255.255.255.224'))
    net = summarizer.DSMNet(3232235584, 4294901984)
    self.assertEqual(summarizer.ToDottedQuad(net, negate=True),
                     ('192.168.0.64', '0.0.255.31'))

    test_data = [(summarizer.DSMNet(3232235584, 4294967295), True,
                  ('192.168.0.64', '32')),
                 (summarizer.DSMNet(3232235584, 4294901760), True,
                  ('192.168.0.64', '16')),
                 (summarizer.DSMNet(3232235584, 4294967294), True,
                  ('192.168.0.64', '31')),
                 (summarizer.DSMNet(3232235584, 4290772992), True,
                  ('192.168.0.64', '10')),
                 (summarizer.DSMNet(3232235584, 4294966016), True,
                  ('192.168.0.64', '255.255.251.0')),
                 (summarizer.DSMNet(3232235584, 4294901504), True,
                  ('192.168.0.64', '255.254.255.0'))]

    for net, nondsm, expected in test_data:
      self.assertEqual(summarizer.ToDottedQuad(net, nondsm=nondsm), expected)

  def testInt32ToDottedQuad(self):
    self.assertEqual(summarizer._Int32ToDottedQuad(3232235584),
                     '192.168.0.64')

  def testSummarizeEmptyList(self):
    nets = []
    result = summarizer.Summarize(nets)
    self.assertEqual(result, [])

  def testSummarizeNoNetworks(self):
    nets = []
    for octet in range(0, 256):
      net = nacaddr.IPv4('192.' + str(255 - octet) + '.' +
                         str(octet) + '.64/27')
      nets.append(net)
    random.shuffle(nets)
    result = summarizer.Summarize(nets)
    self.assertEqual(len(result), 256)

  def testSummarizeSomeNetworks(self):
    nets = [
        # continiously summarizable to one /25
        nacaddr.IPv4('192.168.0.0/27'),
        nacaddr.IPv4('192.168.0.32/27'),
        nacaddr.IPv4('192.168.0.64/27'),
        nacaddr.IPv4('192.168.0.96/27'),
        # discontiniously summarizable with above
        nacaddr.IPv4('128.168.0.0/25'),
        # not summarizable with above
        nacaddr.IPv4('10.0.0.0/8'),
    ]
    for octet in range(0, 256):
      net = nacaddr.IPv4('172.16.' + str(octet) + '.96/30')
      nets.append(net)
    random.shuffle(nets)
    result = summarizer.Summarize(nets)
    self.assertEqual(result, [summarizer.DSMNet(167772160, 4278190080),
                              summarizer.DSMNet(2158493696, 3221225344),
                              summarizer.DSMNet(2886729824, 4294902012)])

  def testSummarizeAllNetworks(self):
    nets = []
    for octet in range(0, 256):
      net = nacaddr.IPv4('192.168.' + str(octet) + '.64/27')
      nets.append(net)
    random.shuffle(nets)
    result = summarizer.Summarize(nets)
    # summarizes to 192.168.0.64 / 255.255.0.224
    self.assertEqual(result, [summarizer.DSMNet(3232235584, 4294901984)])

  def testSummarizeToAllSpace(self):
    nets = [
        nacaddr.IPv4('0.0.0.0/1'),
        nacaddr.IPv4('128.0.0.0/1'),
    ]
    random.shuffle(nets)
    result = summarizer.Summarize(nets)
    self.assertEqual(result, [summarizer.DSMNet(0, 0)])

  def testNacaddrNetToDSMNet(self):
    nacaddr_net = nacaddr.IPv4('192.168.0.64/27')
    dsm_net = summarizer.DSMNet(3232235584, 4294967264, '')
    self.assertEqual(summarizer._NacaddrNetToDSMNet(nacaddr_net), dsm_net)

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

  def testSummarizeDSMONetworks(self):
    fourth_octet = [2, 8, 20, 26, 28, 32, 40, 52, 58, 86, 130, 136, 148,
                    154, 156, 160, 168, 180, 186, 214]
    nets = list()

    for octet3 in range(56, 60):
      for octet4 in fourth_octet:
        nets.append(nacaddr.IPv4('192.168.' + str(octet3) + '.'
                                 + str(octet4) + '/31'))

    result = summarizer.Summarize(nets)
    self.assertEqual(result, [summarizer.DSMNet(3232249858, 4294966398),
                              summarizer.DSMNet(3232249864, 4294966366),
                              summarizer.DSMNet(3232249876, 4294966390),
                              summarizer.DSMNet(3232249882, 4294966366),
                              summarizer.DSMNet(3232249888, 4294966398),
                              summarizer.DSMNet(3232249908, 4294966398),
                              summarizer.DSMNet(3232249942, 4294966398),
                             ])

  def testMergeText(self):
    existing_comment = 'comment that already exists'
    addition = 'addition'

    dsm_net = summarizer.DSMNet(167772160, 4278190080)
    self.assertEqual(dsm_net.MergeText(addition), addition)

    dsm_net = summarizer.DSMNet(167772160, 4278190080, existing_comment)
    self.assertEqual(dsm_net.MergeText(existing_comment), existing_comment)

    dsm_net = summarizer.DSMNet(167772160, 4278190080, existing_comment)
    self.assertEqual(dsm_net.MergeText(addition),
                     existing_comment + ', ' + addition)

  def testOrder(self):
    nets = [
        # not discontinously summarizable with the other two
        nacaddr.IPv4('209.85.147.129/32'),
        # discontinuosly summarizable, but should come before the first one
        nacaddr.IPv4('74.125.20.129/32'),
        nacaddr.IPv4('74.125.21.129/32'),
    ]
    result = summarizer.Summarize(nets)
    self.assertEqual(result, [summarizer.DSMNet(1249711233, 4294967039),
                              summarizer.DSMNet(3512046465, 4294967295)
                             ])


if __name__ == '__main__':
  unittest.main()


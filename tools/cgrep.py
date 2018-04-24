# Copyright 2011 Google Inc. All Rights Reserved.
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
#

"""Simple util to grep through network and service definitions.

Examples:
  To find out which tokens contain "10.4.3.1" use
  $ cgrep.py -i 10.4.3.1

  To find out if token 'FOO' includes ip "1.2.3.4" use
  $ cgrep.py -t FOO -i 1.2.3.4

  To find the difference and union of tokens 'FOO' and 'BAR' use
  $ cgrep.py -c FOO BAR

  To find the difference of network tokens to which 2 IPs belong use
  $ cgrep.py -g 1.1.1.1 2.2.2.2

  To find which IPs are in the 'FOO' network token use
  $ cgrep.py -o FOO

  To find which port & protocol pairs are in a service token 'FOO' use
  $ cgrep.py -s FOO

  To find which service tokens contain port '22' and protocol 'tcp' use
  $ cgrep.py -p 22 tcp
"""

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import argparse
import pprint
import sys
from capirca.lib import nacaddr
from capirca.lib import naming

from absl import app
from absl import logging


def is_valid_ip(arg):
  """Validates a value to be an IP or not.

  Args:
    arg: potential IP address as a string.

  Returns:
    arg as IP object (if arg is an IP)

  Raises:
    Error (if arg is not an IP)
  """
  try:
    nacaddr.IP(arg)
  except:
    raise argparse.ArgumentTypeError('%s is an invalid ip address' % arg)
  return arg


def cli_options():
  """Builds the argparse options for cgrep.

  TODO(robankeny): Move this to flags.

  Returns:
    parser: the arguments, ready to be parsed.
  """

  parser = argparse.ArgumentParser(
      description='c[apirca]grep',
      formatter_class=argparse.RawTextHelpFormatter
  )

  parser.add_argument('-d', '--def', dest='defs',
                      help='Network Definitions directory location. \n',
                      default='./def')

  # -i and -t can be used together, but not with any other option.
  ip_group = parser.add_argument_group()
  # take 1 or more IPs
  ip_group.add_argument('-i', '--ip', dest='ip', nargs='+', type=is_valid_ip,
                        help='Return list of definitions containing the '
                        'IP(s).\nMultiple IPs permitted.')

  ip_group.add_argument('-t', '--token', dest='token',
                        help=('See if an IP is contained within the given '
                              'token.\nMust be used in conjunction with '
                              '-i/--ip [addr].'))

  exclusive_group = parser.add_mutually_exclusive_group()
  # the rest of the arguments are mutually exclusive with each other,
  # and -i / -t
  exclusive_group.add_argument('-c', '--cmp', dest='cmp', nargs=2,
                               metavar=('OBJ', 'OBJ'),
                               help=('Compare the two given network '
                                     'definition tokens'))

  exclusive_group.add_argument('-g', '--gmp', dest='gmp', nargs=2,
                               type=is_valid_ip, metavar=('IP', 'IP'),
                               help=('Diff the network objects to'
                                     ' which the given IP(s) belong'))

  exclusive_group.add_argument('-o', '--obj', dest='obj', nargs='+',
                               help=('Return list of IP(s) contained within '
                                     'the given token(s)'))

  exclusive_group.add_argument('-s', '--svc', dest='svc', nargs='+',
                               help=('Return list of port(s) contained '
                                     'within given token(s)'))

  exclusive_group.add_argument('-p', '--port', dest='port', nargs=2,
                               metavar=('PORT', 'PROTO'),
                               help=('Returns a list of tokens containing '
                                     'the given port and protocol'))

  return parser


def main(argv):
  """Determines the code path based on the arguments passed."""
  del argv  # Unused.
  parser = cli_options()
  options = parser.parse_args()
  db = naming.Naming(options.defs)
  p = pprint.PrettyPrinter(indent=1, depth=4, width=1).pprint

  # if -i and any other option:
  if options.ip and any([options.gmp, options.cmp, options.obj, options.svc,
                         options.port]):
    logging.info('You can only use -i with -t or by itself')

  # if -i and -t
  elif options.token and options.ip:
    try:
      get_nets([options.token], db)
    except naming.UndefinedAddressError:
      logging.info("Network group '%s' is not defined!", options.token)
    else:
      results = compare_ip_token(options, db)
      logging.info(results)

  # if -t, but not -i; invalid!
  elif options.token and not options.ip:
    logging.info('You must specify an IP Address with -i [addr]')

  # if -i
  elif options.ip:
    for ip in options.ip:
      groups = get_ip_parents(ip, db)
      logging.info('Results for IP: %s', ip)
      # iterate and print the tokens we found.
      for name, networks in groups:
        # print the group name [0], and the networks it was in [1]
        logging.info('%s  %s', name, networks)

  elif options.gmp:
    common, diff1, diff2 = group_diff(options, db)
    print_diff(options.gmp[0], common, diff1, diff2)
    logging.info('')
    print_diff(options.gmp[1], common, diff2, diff1)

  # if -c
  elif options.cmp:
    meta, results = compare_tokens(options, db)
    first_name = meta[0]
    second_name = meta[1]
    union = meta[2]
    logging.info('Union of %s and %s:\n %s\n', first_name, second_name, union)
    logging.info('Diff of %s and %s:', first_name, second_name)
    for i in results:
      logging.info(' ' + i)
    logging.info('')
    first_obj, sec_obj = options.cmp
    if check_encapsulated('network', first_obj, sec_obj, db):
      logging.info('%s fully encapsulates %s', sec_obj, first_obj)
    else:
      logging.info('%s does _not_ fully encapsulate %s', sec_obj, first_obj)
    # check the other way around.
    if check_encapsulated('network', sec_obj, first_obj, db):
      logging.info('%s fully encapsulates %s', first_obj, sec_obj)
    else:
      logging.info('%s does _not_ fully encapsulate %s', first_obj, sec_obj)

  # if -o
  elif options.obj:
    for obj in options.obj:
      try:
        token, ips = get_nets([obj], db)[0]
      except naming.UndefinedAddressError:
        logging.info('%s is an invalid object', obj)
      else:
        logging.info(token + ':')
        # convert list of ip objects to strings and sort them
        ips.sort(key=lambda x: int(x.ip))
        p([str(x) for x in ips])

  # if -s
  elif options.svc:
    try:
      results = get_ports(options.svc, db)
    except naming.UndefinedServiceError:
      logging.info('%s contains an invalid service object', str(options.svc))
    else:
      for result in get_ports(options.svc, db):
        svc, port = result
        logging.info(svc + ':')
        p(port)

  # if -p
  elif options.port:
    port, protocol, result = get_services(options, db)
    logging.info('%s/%s:', port, protocol)
    p(result)

  # if nothing is passed
  elif not any((options.cmp, options.ip, options.token, options.obj,
                options.svc, options.port)):
    parser.print_help()
  logging.info('')


def check_encapsulated(obj_type, first_obj, second_obj, db):
  """Checks if a network/service object is entirely contained within another.

  Args:
    obj_type: "network" or "service"
    first_obj: The name of the first network/service object
    second_obj: The name of the secondnetwork/service object
    db: The network and service definitions

  Returns:
    Error or bool:
      ValueError if an invalid object type is passed
      True if the first_obj is entirely within second_obj, otherwise False

  Raises:
    ValueError: When value is not a network or service.
  """
  if obj_type == 'network':
    # the indexing is to get the list of networks out of the tuple[1] and
    # list[0] returned by get_nets
    first = get_nets([first_obj], db)[0][1]
    second = get_nets([second_obj], db)[0][1]

  elif obj_type == 'service':
    first = get_ports([first_obj], db)[0][1]
    second = get_ports([second_obj], db)[0][1]
  else:
    raise ValueError("check_encapsulated() currently only supports "
                     "'network' and 'service' for the obj_type parameter")
  # iterates over each object in the first group, and then each obj in the
  # second group, making sure each one in the first is contained
  # somewhere in the second.
  for obj in first:
    for sec_obj in second:
      if obj in sec_obj:
        break
    # if we got through every object in the second group, and didn't have
    # a match, then the first group is not entirely contained.
    else:
      return False
  # if we got here, then the group was fully contained.
  return True


def print_diff(ip, common, diff1, diff2):
  """Print out the common, added, and removed network objects between 2 IPs.

  Args:
    ip: the IP being compared against
    common: the network objects shared between the two IPs
                    ('ip' and the other passed into options.cmp)
    diff1: the network objects present in 'ip' but not in the other IP
                   passed into options.cmp
    diff2: the network objects not present in 'ip' but are present in
                   the other IP passed into options.cmp
  """
  logging.info('IP: %s', ip)
  if common:
    common = ['  {0}'.format(elem) for elem in common]
    logging.info('\n'.join(common))
  if diff1:
    diff = ['+ {0}'.format(elem) for elem in diff1]
    logging.info('\n'.join(diff))
  if diff2:
    diff = ['- {0}'.format(elem) for elem in diff2]
    logging.info('\n'.join(diff))


def group_diff(options, db):
  """Diffs two different group objects.

  Args:
    options: the options sent to the script
    db : network and service definitions

  Returns:
    tuple: the common lines, the differences from 1 to 2,
                          and the differences from 2 to 1
  """
  nested_rvals = []
  for ip in options.gmp:
    nested_rvals.append(get_ip_parents(ip, db))
  # get just the list of groups, stripping out the networks.
  group1 = [x[0] for x in nested_rvals[0]]
  group2 = [x[0] for x in nested_rvals[1]]
  common = list(set(group1) & set(group2))
  diff1 = list(set(group1) - set(group2))
  diff2 = list(set(group2) - set(group1))
  return common, diff1, diff2


def get_ip_parents(ip, db):
  """Gets a list of all network objects that include an IP.

  Args:
    ip: the IP we're looking for the parents of
    db: network and service definitions

  Returns:
    results: a list of all groups that include the IP, in the format:
                     [("Group", ["networks", "matched"]), (etc)]
  """
  results = []
  rval = db.GetIpParents(ip)
  for v in rval:
    nested = db.GetNetParents(v)
    prefix_and_nets = get_nets_and_highest_prefix(ip, v, db)
    if nested:
      for n in nested:
        results.append(('%s -> %s' % (n, v), prefix_and_nets))
    else:
      results.append((v, prefix_and_nets))
  # sort the results by prefix length descending
  results = sorted(results, key=lambda x: x[1][0], reverse=True)
  # strip out the no longer needed prefix lengths before handing off
  for index, group in enumerate(results):
    results[index] = (group[0], group[1][1])
  return results


def get_nets_and_highest_prefix(ip, net_group, db):
  """Find the highest prefix length in all networks given it contains the IP.

  Args:
    ip: the IP address contained in net_group
    net_group: the name of the network object we'll be looking through
    db: network and service definitions

  Returns:
    highest_prefix_length, networks as tuple
      highest_prefix_length : the longest prefix length found,
      networks : network objects
  """
  highest_prefix_length = 0
  networks = []
  ip = nacaddr.IP(ip)
  # loop through all the networks in the net_group
  for net in get_nets([net_group], db)[0][1]:
    # find the highest prefix length for the networks that contain the IP
    if ip in net:
      networks.append(str(net))
      if net.prefixlen > highest_prefix_length:
        highest_prefix_length = net.prefixlen
  return highest_prefix_length, networks


def get_nets(objects, db):
  """Gets a list of all networks that are inside of a network object.

  Args:
    objects: network objects
    db: network and service definitions

  Returns:
    results : all networks inside a network object
  """
  results = []
  for obj in objects:
    net = db.GetNet(obj)
    results.append((obj, net))
  return results


def compare_tokens(options, db):
  """Compares to network objects against each other.

  Args:
    options: the options sent to the script
    db: network and service definitions

  Returns:
    meta, results :
      ((first object, second object, union of those two),
       diff of those two network objects)
  """
  t1, t2 = options.cmp
  d1 = db.GetNet(t1)
  d2 = db.GetNet(t2)
  union = list(set(d1 + d2))
  meta = (t1, t2, union)
  results = []
  for el in set(d1 + d2):
    el = nacaddr.IP(el)
    if el in d1 and el in d2:
      results.append(str(el))
    elif el in d1:
      results.append(str(el))
    elif el in d2:
      results.append(str(el))
  return meta, results


def compare_ip_token(options, db):
  """Looks to see if a network IP is contained in a network object.

  Args:
    options: the options sent to the script
    db: network and service definitions

  Returns:
    results : end-user string stating the results
  """
  token = options.token
  results = []
  for ip in options.ip:
    rval = db.GetIpParents(ip)
    if token in rval:
      results = '%s is in %s' % (ip, token)
    else:
      results = '%s is _not_ in %s' % (ip, token)
  return results


def get_ports(svc_group, db):
  """Gets the ports and protocols defined in a service group.

  Args:
    svc_group: a list of strings for each service group
    db: network and service definitions

  Returns:
    results: a list of tuples for each service defined, in the format:
                     (service name, "<port>/<protocol>")
  """
  results = []
  for svc in svc_group:
    port = db.GetService(svc)
    results.append((svc, port))
  return results


def get_services(options, db):
  """Finds any services with that include a specific port/protocol pair.

  Args:
    options: the options sent to the script
    db: network and service definitions

  Returns:
    port, protocol, results as tuple in the format:
    (port, protocol, list of the services containing this pair)
  """
  results = []
  port, protocol = options.port
  # swap values if they were passed in wrong order
  if port.isalpha() and protocol.isdigit():
    port, protocol = protocol, port
  results = db.GetPortParents(port, protocol)
  return port, protocol, results


if __name__ == '__main__':
  app.run(main, argv=sys.argv[:1])

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
"""Distribute bits of configuration to network elements.

Given some device names and configuration files (or a list of configuration
files with names hinting at the target device) send the configuration to the
target devices. These types of pushes can be IO bound, so threading is
appropriate.
"""

import getpass
import gflags
import logging
import os
import progressbar
import sys
import socket
import termcolor
import threading

# Eval is used for building vendor objects.
# pylint: disable-msg=W0611
import ios
import junos
import paramiko_device
# pylint: enable-msg=W0611


FLAGS = gflags.FLAGS

gflags.DEFINE_list('targets', '', 'A comma separated list of target devices.',
                     short_name='T')

gflags.DEFINE_bool('canary', False,
                   'Do everything possible, save for applying the config.',
                   short_name='c')

gflags.DEFINE_bool('devices_from_filenames', False,
                   'Use the configuration file names to determine the target '
                   'device.', short_name='d')

gflags.DEFINE_string('vendor', '', 'A vendor name. Must be one of the '
                     'implementations in this directory',
                     short_name='v')

gflags.DEFINE_string('user', '', 'Username for logging into the devices. This '
                     'will default to your own username.',
                     short_name='u')

gflags.DEFINE_string('command', '', 'Rather than a config file, you would like '
                     'to issue a command and get a response.',
                     short_name='C')

# TODO: Add devices_from_filenames.

class Error(Exception):
  """Base exception class."""


class UsageError(Error):
  """Incorrect flags usage."""


class PushThread(threading.Thread):
  def __init__(self, target, config, vendor_class, password):
    """Initiator.

    Args:
      target: str; Resolvable device name or IP of the target.
      config: str; Contents of the configuration or command to be sent to the
              target.
      vendor_class: type; Vendor appropriate class to use for this push.
      password: str; Password to use for devices (username is set in FLAGS).
    """
    threading.Thread.__init__(self)
    self._target = target
    self._config = config
    self._vendor_class = vendor_class
    self._password = password


  def run(self):
    device = self._vendor_class(host=self._target, loopback_ipv4=self._target)
    device.Connect(username=FLAGS.user, password=self._password)
    if FLAGS.command:
      print termcolor.cprint(self._target, 'red')
      print device.Cmd(command=self._config)
    else:
      device.SetConfig(destination_file='running-config', data=self._config,
                       canary=FLAGS.canary)
    device.Disconnect()


def JoinFiles(files):
  """Take a list of file names, read and join their content.

  Args:
    files: list; String filenames to open and read.
  Returns:
    str; The consolidated content of the provided filenames.
  """
  configlet = ''
  for f in files:
    # Let IOErrors happen naturally.
    configlet = configlet + (open(f).read())
  return configlet


def main(argv):
  """Check flags and start the threaded push."""

  files = FLAGS(argv)[1:]

  # Flags "devices" and "devices_from_filenames" are mutually exclusive.
  if ((not FLAGS.targets and not FLAGS.devices_from_filenames)
      or (FLAGS.targets and FLAGS.devices_from_filenames)):
    raise UsageError(
        'No targets defined, try --targets.')

  # User must provide a vendor.
  elif not FLAGS.vendor:
    raise UsageError(
        'No vendor defined, try the --vendor flag (i.e. --vendor ios)')

  # We need some configuration files unless --command is used.
  elif not files and not FLAGS.command:
    raise UsageError(
        'No configuration files provided. Provide these via argv / glob.')

  else:
    # Vendor implementations must be named correctly, i.e. IosDevice.
    vendor_classname = FLAGS.vendor.capitalize() + 'Device'
    class_path = '.'.join([FLAGS.vendor.lower(), vendor_classname])
    try:
      pusher = eval(class_path)
    except NameError:
      raise UsageError(
          'The vendor "%s" is not implemented or imported. Please select a '
          'valid vendor' % FLAGS.vendor)

    if not FLAGS.user:
      FLAGS.user = getpass.getuser()

    if FLAGS.devices_from_filenames:
      FLAGS.targets = [os.path.basename(x) for x in files]
      print 'Ready to push per-device configurations to %s' % FLAGS.targets
    else:
      print 'Ready to push %s to %s' % (files or FLAGS.command, FLAGS.targets)

    passw= getpass.getpass('Password:')

    widgets = [
        'Pushing... ', progressbar.Percentage(), ' ',
        progressbar.Bar(marker=progressbar.RotatingMarker()), ' ',
        progressbar.ETA(), ' ', progressbar.FileTransferSpeed()]
    pbar = progressbar.ProgressBar(widgets=widgets).start()

    for counter, device in enumerate(FLAGS.targets):
      if FLAGS.command:
        thread = PushThread(device, FLAGS.command, pusher, passw)
      else:
        consolidated = JoinFiles(files)
        thread = PushThread(device, consolidated, pusher, passw)

      thread.start()
      pbar.update((len(FLAGS.targets)/100.0) * counter)
    pbar.finish()


if __name__ == '__main__':
  main(sys.argv)

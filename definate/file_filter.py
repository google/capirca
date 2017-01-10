#!/usr/bin/python
#
# Copyright 2012 Google Inc. All Rights Reserved.
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

"""Module that holds all file-level filter classes of Definate."""

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

__author__ = 'msu@google.com (Martin Suess)'


import logging


class Error(Exception):
  """Base error class."""


class FileError(Error):
  """Exception to use when file handling files."""


class Container(object):
  """Container class to hold all information to be passed between filters."""

  def __init__(self, lines=None, relative_path='', absolute_path=''):
    """Initializer.

    Args:
      lines: Optional list of strings which will be added as lines.
        E.g. the file header can be added here directly.
      relative_path: Optional string to specify the path of the file relative to
        the location of the definition directory (e.g. 'AUTOGEN.net').
      absolute_path: Optional string to specify the absolute path of the local
        file to be written (e.g. '/tmp/AUTOGEN.net') or if a SCM software is
        used it can refer to the full path there
        (e.g. '//depot/def/AUTOGEN.net').
    """
    self.lines = lines if lines else []
    self.absolute_path = absolute_path
    self.relative_path = relative_path


class FileFilter(object):
  """Abstract class defining the interface for the filter chain objects."""

  def Filter(self, container, args):
    """Interface to filter or modify data passed into it.

    Args:
      container: Container object which holds all information for one definition
        file. See Container class for details.
      args: Dictionary of arguments depending on the actual filter in use.

    Raises:
      NotImplementedError: In any case since this is not implemented an needs
        to be defined by subclasses.
    """
    raise NotImplementedError(
        'This is an interface only. Implemented by subclasses.')


class PrintFilter(FileFilter):
  """FileFilter implementation which simply logs the file content."""

  def Filter(self, container, unused_args):
    """Filter method that prints the content of the file to stdout.

    Args:
      container: Container object which holds all information for one definition
        file. See Container class for details.
      unused_args: No extra arguments required by this filter implementation.

    Returns:
      Container object that has been passed in.
    """
    print('# File "%s"' % container.absolute_path)
    print('\n'.join(container.lines))
    return container


class WriteFileFilter(FileFilter):
  """FileFilter implementation which writes the content into a file."""

  def Filter(self, container, unused_args):
    """Filter method that writes the content of the file into a file.

    Args:
      container: Container object which holds all information for one definition
        file. See Container class for details.
      unused_args: No extra arguments required by this filter implementation.

    Returns:
      Container object that has been passed in.
    """
    try:
      f = file(container.absolute_path, 'w')
    except IOError as e:
      raise FileError('File "%s" could not be opened: %s' % (
          container.absolute_path, e))

    try:
      f.write('\n'.join(container.lines))
    except IOError as e:
      raise FileError('File "%s" could not be written: %s' % (
          container.absolute_path, e))
    else:
      f.close()

    logging.info('Wrote file: %s', container.absolute_path)
    return container

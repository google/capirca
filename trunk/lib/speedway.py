#!/usr/bin/python2.4
#
# Copyright 2011 Google Inc. All Rights Reserved.


"""Speedway iptables generator.

   This is a subclass of Iptables lib."""

__author__ = 'watson@google.com (Tony Watson)'

import iptables


class Term(iptables.Term):
  """Generate Iptables policy terms."""
  _PLATFORM = 'speedway'
  _PREJUMP_FORMAT = None
  _POSTJUMP_FORMAT = '-A %s -j %s'


class Speedway(iptables.Iptables):
  """Generates filters and terms from provided policy object."""

  _PLATFORM = 'speedway'
  _DEFAULT_PROTOCOL = 'all'
  _SUFFIX = '.ipt'

  _RENDER_PREFIX = '*filter'
  _RENDER_SUFFIX = 'COMMIT'
  _DEFAULTACTION_FORMAT = ':%s %s'

  _TERM = Term

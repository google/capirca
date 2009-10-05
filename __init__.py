#
# Network access control library and utilities
#
# capirca/__init__.py
#
# This package is intended to simplify the process of developing
# and working with large numbers of network access control lists
# for various platforms that share common network and service
# definitions.
#
# from capirca import naming
# from capirca import policy
# from capirca import cisco
# from capirca import juniper
# from capirca import iptables
#
#

__version__ = '1.0.0'

__all__ = ['naming', 'policy', 'cisco', 'juniper', 'iptables',
           'policyreader']

__author__ = 'Paul (Tony) Watson (watson@gmail.com / watson@google.com)'

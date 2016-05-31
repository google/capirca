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
# from capirca import gce
# from capirca import juniper
# from capirca import iptables
# from capirca import policyreader
# from capirca import aclcheck
# from capirca import aclgenerator
# from capirca import nacaddr
# from capirca import packetfilter
# from capirca import port
# from capirca import speedway
#

__version__ = '1.1.0'

__all__ = ['naming', 'yamlnaming', 'policy', 'cisco', 'cisconx', 'juniper', 'iptables',
           'policyparser', 'yamlpolicyparser',
           'policyreader', 'aclcheck', 'aclgenerator', 'nacaddr',
           'packetfilter', 'port', 'speedway', 'gce']

__author__ = 'Paul (Tony) Watson (watson@gmail.com / watson@google.com)'

# Set default logging handler to avoid "No handler found" warnings.
import logging
try:  # Python 2.7+
    from logging import NullHandler
except ImportError:
    class NullHandler(logging.Handler):
        def emit(self, record):
            pass

logging.getLogger(__name__).addHandler(NullHandler())

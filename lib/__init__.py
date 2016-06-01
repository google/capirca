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

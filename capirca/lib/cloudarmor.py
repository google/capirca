"""Google Cloud Armor Firewall Generator.

Refer to the links below for more information
https://cloud.google.com/armor/
https://cloud.google.com/armor/docs/
"""

import copy
import json
import logging

from capirca.lib import aclgenerator

import six


# Generic error class
class Error(Exception):
  """Generic error class."""


class ExceededMaxTermsError(Error):
  """Raised when number of terms in a policy exceed _MAX_RULES_PER_POLICY."""


class UnsupportedFilterTypeError(Error):
  """Raised when unsupported filter type (i.e address family) is specified."""


class Term(aclgenerator.Term):
  """Generates the Term for CloudArmor."""
  # Max srcIpRanges within a single term
  _MAX_IP_RANGES_PER_TERM = 5

  ACTION_MAP = {'accept': 'allow',
                'deny': 'deny(404)'}

  _MAX_TERM_COMMENT_LENGTH = 64

  def __init__(self, term, address_family='inet', verbose=True):
    super().__init__(term)
    self.term = term
    self.address_family = address_family
    self.verbose = verbose

  def __str__(self):
    return ''

  def ConvertToDict(self, priority_index):
    """Converts term to dictionary representation of CloudArmor's JSON format.

    Takes all of the attributes associated with a term (match, action, etc) and
    converts them into a dictionary which most closely represents
    the CloudArmor API's JSON rule format. Additionally, splits a single term
    into multiple terms if the number of srcIpRanges exceed
    _MAX_IP_RANGES_PER_TERM.

    Args:
      priority_index: An integer priority value assigned to the term. In case
      the term is split into i sub-terms, the ith sub-term has
      priority = priority_index + i

    Returns:
      A list of dicts where each dict is a term

    Raises:
      UnsupportedFilterTypeError: Raised when an unsupported filter type is
      specified
    """
    term_dict = {}
    rules = []

    if self.term.comment and self.verbose:
      raw_comment = ' '.join(self.term.comment)
      if len(raw_comment) > self._MAX_TERM_COMMENT_LENGTH:
        term_dict['description'] = raw_comment[:self._MAX_TERM_COMMENT_LENGTH]
        logging.warning('Term comment exceeds maximum length = %d; Truncating '
                        'comment..', self._MAX_TERM_COMMENT_LENGTH)
      else:
        term_dict['description'] = raw_comment

    term_dict['action'] = self.ACTION_MAP[self.term.action[0]]
    term_dict['preview'] = False

    if self.address_family == 'inet':
      saddrs = self.term.GetAddressOfVersion('source_address', 4)
    elif self.address_family == 'inet6':
      saddrs = self.term.GetAddressOfVersion('source_address', 6)
    elif self.address_family == 'mixed':
      saddrs = (self.term.GetAddressOfVersion('source_address', 4)
                + self.term.GetAddressOfVersion('source_address', 6))
    else:
      raise UnsupportedFilterTypeError("'%s' is not a valid filter type" %
                                       self.address_family)

    term_dict['match'] = {
        'versionedExpr': 'SRC_IPS_V1',
        'config': {
            'srcIpRanges': saddrs,
        }
    }
    # If scrIpRanges within a single term exceed _MAX_IP_RANGES_PER_TERM,
    # split into multiple terms
    source_addr_chunks = [
        saddrs[x:x+self._MAX_IP_RANGES_PER_TERM] for x in range(
            0, len(saddrs), self._MAX_IP_RANGES_PER_TERM)]

    if not source_addr_chunks:
      rule = copy.deepcopy(term_dict)
      rule['priority'] = priority_index
      rule['match']['config']['srcIpRanges'] = ['*']
      rules.append(rule)

    else:
      split_rule_count = len(source_addr_chunks)
      for i, chunk in enumerate(source_addr_chunks):
        rule = copy.deepcopy(term_dict)
        if split_rule_count > 1:
          term_position_suffix = ' [%d/%d]' % (i+1, split_rule_count)
          desc_limit = self._MAX_TERM_COMMENT_LENGTH - len(term_position_suffix)
          rule['description'] = (rule.get('description', '')[:desc_limit]
                                 + term_position_suffix)

        rule['priority'] = priority_index + i
        rule['match'] = {
            'versionedExpr': 'SRC_IPS_V1',
            'config': {
                'srcIpRanges': [str(saddr) for saddr in chunk],
            }
        }
        rules.append(rule)

    # TODO(robankeny@): Review this log entry to make it cleaner/more useful.
    # Right now, it prints the entire term which might be huge
    if len(source_addr_chunks) > 1:
      logging.debug('Current term [%s] was split into %d sub-terms since '
                    '_MAX_IP_RANGES_PER_TERM was exceeded',
                    str(term_dict), len(source_addr_chunks))
    return rules


class CloudArmor(aclgenerator.ACLGenerator):
  """A CloudArmor policy object."""

  _PLATFORM = 'cloudarmor'
  SUFFIX = '.gca'
  _SUPPORTED_AF = set(('inet', 'inet6', 'mixed'))

  # Maximum number of rules that a CloudArmor policy can contain
  _MAX_RULES_PER_POLICY = 200

  # Warn user when rule count exceeds this number
  _RULECOUNT_WARN_THRESHOLD = 190

  # Maps indiviudal filter options to their index positions in the POL header
  _FILTER_OPTIONS_MAP = {'filter_type': 0}

  def _BuildTokens(self):
    """Build supported tokens for platform.

    Returns:
      tuple containing both supported tokens and sub tokens
    """
    supported_tokens, _ = super()._BuildTokens()
    supported_tokens -= {'destination_address',
                         'destination_address_exclude',
                         'destination_port',
                         'expiration',
                         'icmp_type',
                         'stateless_reply',
                         'option',
                         'protocol',
                         'platform',
                         'platform_exclude',
                         'source_address_exclude',
                         'source_port',
                         'verbatim'}
    supported_sub_tokens = {'action': {'accept', 'deny'}}
    return supported_tokens, supported_sub_tokens

  def _TranslatePolicy(self, pol, exp_info):
    """Translates a Capirca policy into a CloudArmor-specific data structure.

    Takes in a POL file, parses each term and populates the cloudarmor_policies
    list. Each term in this list is a dictionary formatted according to
    CloudArmor's rule API specification.

    Args:
      pol: A Policy() object representing a given POL file.
      exp_info: An int that specifies number of weeks till policy expiry.

    Returns:
      N.A.

    Raises:
      ExceededMaxTermsError: Raised when the number of terms in a policy exceed
      _MAX_RULES_PER_POLICY.

      UnsupportedFilterTypeError: Raised when an unsupported filter type is
      specified
    """
    self.cloudarmor_policies = []

    for header, terms in pol.filters:
      if self._PLATFORM not in header.platforms:
        continue
      filter_options = header.FilterOptions(self._PLATFORM)
      verbose = True
      if 'noverbose' in filter_options:
        filter_options.remove('noverbose')
        verbose = False

      if filter_options is None or not filter_options:
        filter_type = 'inet'
        logging.debug('No filter_type specified. Defaulting to inet (IPv4)')

      else:
        filter_type = filter_options[self._FILTER_OPTIONS_MAP['filter_type']]
        if filter_type not in self._SUPPORTED_AF:
          raise UnsupportedFilterTypeError("'%s' is not a valid filter type" %
                                           filter_type)

      counter = 1

      for term in terms:

        json_rule_list = Term(term,
                              address_family=filter_type,
                              verbose=verbose).ConvertToDict(
                                  priority_index=counter)
        # count number of rules generated after split (if any)
        split_rule_count = len(json_rule_list)

        self.cloudarmor_policies.extend(json_rule_list)

        counter = counter + split_rule_count

        total_rule_count = len(self.cloudarmor_policies)

        if total_rule_count > self._RULECOUNT_WARN_THRESHOLD:

          if total_rule_count > self._MAX_RULES_PER_POLICY:
            raise ExceededMaxTermsError('Exceeded maximum number of rules in '
                                        ' a single policy | MAX = %d'
                                        % self._MAX_RULES_PER_POLICY)
          else:
            logging.warning('Current rule count (%d) is almost at maximum '
                            'limit of %d', total_rule_count,
                            self._MAX_RULES_PER_POLICY)

  def __str__(self):
    """Return the JSON blob for CloudArmor."""

    out = '%s\n\n' % (
        json.dumps(self.cloudarmor_policies, indent=2,
                   separators=(six.ensure_str(','), six.ensure_str(': ')),
                   sort_keys=True))
    return out

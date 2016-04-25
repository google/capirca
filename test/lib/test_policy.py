import unittest

from lib import policy

class Test_Header(unittest.TestCase):

    def setUp(self):
        target = policy.Target(['cisco', 'some', 'options'])
        h = policy.Header()
        h.target.append(policy.Target(['cisco', 'some', 'options']))
        h.target.append(policy.Target(['juniper', 'other_opts']))
        self.header = h

    def test_sanity_checks(self):
        """Sanity checks only."""
        h = self.header
        self.assertEqual(h.platforms, ['cisco', 'juniper'])
        self.assertEqual(h.FilterOptions('cisco'), ['some', 'options'])

    def test_can_add_same_platform_more_than_once(self):
        self.header.target.append(policy.Target(['cisco', 'other_options']))
        # If reach here, ok.

    def test_cannot_retrieve_platforms_if_same_target_added_more_than_once(self):
        """FilterOptions returns the first match by platform,
        so duplicate platforms should break things."""
        self.header.target.append(policy.Target(['cisco', 'other_options']))
        with self.assertRaises(policy.HeaderDuplicateTargetPlatformError):
            p = self.header.target
        with self.assertRaises(policy.HeaderDuplicateTargetPlatformError):
            p = self.header.FilterOptions('cisco')
        with self.assertRaises(policy.HeaderDuplicateTargetPlatformError):
            p = self.header.FilterName('cisco')

class Test_Policy(unittest.TestCase):

    def make_header_and_terms(self, platform):
        target = policy.Target([platform, 'some', 'options'])
        h = policy.Header()
        h.target.append(target)
        t = policy.Term()
        t.action.append('accept')
        terms = [t]
        return (h, terms)

    def setUp(self):
        h, terms = self.make_header_and_terms('cisco')
        self.policy = policy.Policy(h, terms, True, True)

    def test_can_get_platforms(self):
        self.assertEqual(['cisco'], self.policy.platforms)

    def test_multiple_platforms_in_multiple_headers_returns_unique_platforms(self):
        h, terms = self.make_header_and_terms('other')
        self.policy.AddFilter(h, terms)
        h, terms = self.make_header_and_terms('cisco')
        self.policy.AddFilter(h, terms)
        self.assertEqual(['cisco', 'other'], self.policy.platforms)

def main():
    unittest.main()

if __name__ == '__main__':
    main()


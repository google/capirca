import unittest

from lib import policy

class Test_Header(unittest.TestCase):

    def setUp(self):
        target = policy.Target(['cisco', 'some', 'options'])
        h = policy.Header()
        h.AddObject(policy.Target(['cisco', 'some', 'options']))
        h.AddObject(policy.Target(['juniper', 'other_opts']))
        self.header = h

    def test_sanity_checks(self):
        """Sanity checks only."""
        h = self.header
        self.assertEqual(h.platforms, ['cisco', 'juniper'])
        self.assertEqual(h.FilterOptions('cisco'), ['some', 'options'])

    def test_cannot_add_same_target_more_than_once(self):
        """FilterOptions returns the first match by platform,
        so adding the same platform to the headers is an error."""
        with self.assertRaises(policy.HeaderDuplicateTargetPlatformError):
            self.header.AddObject(policy.Target(['cisco', 'other_options']))

class Test_Policy(unittest.TestCase):

    def make_header_and_terms(self, platform):
        target = policy.Target([platform, 'some', 'options'])
        h = policy.Header()
        h.AddObject(target)
        a = policy.VarType(policy.VarType.ACTION, 'accept')
        terms = [policy.Term(a)]
        return (h, terms)

    def setUp(self):
        h, terms = self.make_header_and_terms('cisco')
        self.policy = policy.Policy(h, terms)

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


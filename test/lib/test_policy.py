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

    def make_header_and_terms(self):
        target = policy.Target(['cisco', 'some', 'options'])
        h = policy.Header()
        h.AddObject(target)
        a = policy.VarType(policy.VarType.ACTION, 'accept')
        terms = [policy.Term(a)]
        return (h, terms)

    def setUp(self):
        h, terms = self.make_header_and_terms()
        self.policy = policy.Policy(h, terms)
        self.override = policy.Target(['override', 'override_opts', 'here'])

    def assertPlatformsEquals(self, expected_platforms):
        # Note the platforms is an array of arrays:
        # a policy can have multiple headers, which in turn
        # have multiple targets (and platforms).
        actual_platforms = [h.platforms for h in self.policy.headers]
        self.assertEqual(actual_platforms, expected_platforms)


def main():
    unittest.main()

if __name__ == '__main__':
    main()


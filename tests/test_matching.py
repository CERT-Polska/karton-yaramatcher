import unittest
import os
from karton.yaramatcher import YaraHandler, normalize_rule_name


class TestMatchingRegressions(unittest.TestCase):
    def test_matching(self):
        cwd = os.path.abspath(os.path.dirname(__file__))
        testdir = os.path.join(cwd, './testdata')
        testfile = os.path.join(testdir, './nymaim')
        with open(testfile, 'rb') as testf:
            testdata = testf.read()

        handler = YaraHandler()
        self.assertEqual(['win_nymaim'], [normalize_rule_name(x.rule) for x in handler.get_matches(testdata)])


if __name__ == '__main__':
    unittest.main()

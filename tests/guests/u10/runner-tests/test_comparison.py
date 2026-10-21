"""Comparison rejects incomplete or wrong local dependency reports."""
import copy
import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
from comparison import compare, local_versions, normalized, probe_pass


class ComparisonTests(unittest.TestCase):
    def rows(self):
        return {'frozen': {'stdout': '', 'stderr': '+ filedep@1.0.0\n+ linked@2.0.0\n',
                           'exit': 0, 'timed_out': False},
                'list': {'stdout': '├── filedep 1.0.0\n└── linked 2.0.0\n', 'stderr': '',
                         'exit': 0, 'timed_out': False}}

    def test_correct_streams_accepted(self):
        local_versions(self.rows())

    def test_missing_dependency_rejected(self):
        for name, stream in [('frozen', 'stderr'), ('list', 'stdout')]:
            rows = self.rows()
            rows[name][stream] = rows[name][stream].splitlines()[0] + '\n'
            with self.assertRaises(ValueError):
                local_versions(rows)
        for stdout in ('', 'FAIL fs-basic\n', 'PASS fs-basic\nPASS fs-basic\n'):
            with self.assertRaises(ValueError):
                probe_pass({'stdout': stdout, 'exit': 0, 'timed_out': False}, ['fs-basic'])

    def test_former_zero_versions_rejected(self):
        rows = self.rows()
        rows['frozen']['stderr'] = '+ filedep@0.0.0\n+ linked@0.0.0\n'
        with self.assertRaises(ValueError):
            local_versions(rows)

    def test_failure_or_timeout_rejected(self):
        for name in ('frozen', 'list'):
            for field, value in [('exit', 1), ('timed_out', True)]:
                rows = self.rows()
                rows[name][field] = value
                with self.assertRaises(ValueError):
                    local_versions(rows)
                with self.assertRaises(ValueError):
                    compare(self.rows()[name], rows[name], '/native', '/guest')

    def test_ansi_report_accepted(self):
        rows = self.rows()
        rows['frozen']['stderr'] = '\x1b[32m' + rows['frozen']['stderr'] + '\x1b[0m'
        local_versions(rows)

    def test_normalization_is_narrow(self):
        self.assertEqual(normalized('\x1b[32m/tmp/root in 12ms\x1b[0m FAIL\n', '/tmp/root'),
                         '<FIXTURE> in <ELAPSED> FAIL\n')

    def test_stdout_mismatch_remains_failure(self):
        expected = self.rows()['list']
        actual = copy.deepcopy(expected)
        actual['stdout'] = actual['stdout'].replace('2.0.0', '0.0.0')
        with self.assertRaises(ValueError):
            compare(expected, actual, '/native', '/guest')
        actual = copy.deepcopy(expected)
        actual['stderr'] = 'FAIL unexpected stderr\n'
        with self.assertRaises(ValueError):
            compare(expected, actual, '/native', '/guest')
        expected = {'stdout': '', 'stderr': 'installed in 12ms\n', 'exit': 0, 'timed_out': False}
        actual = {'stdout': '', 'stderr': '\x1b[32minstalled in 2.4s\x1b[0m\n', 'exit': 0, 'timed_out': False}
        compare(expected, actual, '/native', '/guest')


if __name__ == '__main__':
    unittest.main()

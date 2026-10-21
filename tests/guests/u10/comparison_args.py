"""Test-only reporter choice; original argv observations remain separate."""
import copy

from comparison import normalized


def comparison_config(original):
    result = copy.deepcopy(original)
    for case in result['aube']:
        if case['name'] in ('install', 'frozen'):
            if not case['args'] or case['args'][0] != 'install':
                raise ValueError('unexpected install comparison arguments')
            if any(arg.startswith('--reporter') for arg in case['args']):
                raise ValueError('reporter already specified')
            case['args'].append('--reporter=append-only')
    return result


def compare_original(expected, actual, expected_root, actual_root):
    """Supplemental original argv: retain raw stderr, gate stable outcomes.

    The primary comparison checks stderr with the same official reporter.
    Original reporter heartbeat output varies with elapsed wall time, so this
    supplemental observation checks exit/stdout and retains both raw reports.
    """
    if expected['timed_out'] or actual['timed_out']:
        raise ValueError('original operation timed out')
    if expected['exit'] != actual['exit']:
        raise ValueError('original exit mismatch')
    if normalized(expected['stdout'], expected_root) != normalized(actual['stdout'], actual_root):
        raise ValueError('original stdout mismatch')

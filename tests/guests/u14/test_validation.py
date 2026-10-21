import copy
import json
import unittest

from validation import CASES, HEX_FIELDS, SSE_CASES, validate


def sse_row(name):
    return {
        "name": name,
        "signal": 0,
        "child_exit": 0,
        "code": "660f70c100c3",
        "in_flags": "00000000000008d7",
        "flags": "00000000000008d5",
        "flag_mask": "00000000000008d5",
        "rip": "0000000000000005",
        "in_gpr": ["0" * 16] * 16,
        "gpr": ["0" * 16] * 16,
        "in_xmm": ["0" * 32] * 16,
        "xmm": ["0" * 32] * 16,
    }


def observations():
    rows = []
    for name in CASES:
        row = {"name": name, "signal": 0, "child_exit": 0}
        if name in ("unmapped-data-fault", "division-fault"):
            row["signal"] = 11 if name == "unmapped-data-fault" else 8
            row["child_exit"] = None
        elif name in SSE_CASES:
            row = sse_row(name)
        else:
            row.update(dict.fromkeys(HEX_FIELDS, "0000000000000000"))
        rows.append(row)
    return rows


def first_sse(rows):
    return rows[CASES.index(SSE_CASES[0])]


def check(rows, **kwargs):
    return validate(
        "\n".join(json.dumps(row) for row in rows),
        seconds=kwargs.get("seconds", 1),
        exit_code=kwargs.get("exit_code", 0),
    )


class NativeValidation(unittest.TestCase):
    def test_complete_inventory_and_fault_rows(self):
        self.assertEqual(len(CASES), 28)
        self.assertEqual(len(SSE_CASES), 15)
        self.assertEqual(CASES[13:], SSE_CASES)
        self.assertEqual(check(observations()), observations())

    def test_each_integer_sse_case_is_required(self):
        for name in SSE_CASES:
            with self.subTest(name=name), self.assertRaises(ValueError):
                check([row for row in observations() if row["name"] != name])

    def test_sse_row_schema_is_exact(self):
        rows = observations()
        first_sse(rows)["ignored"] = 1
        with self.assertRaises(ValueError):
            check(rows)
        for field in ("code", "in_xmm", "xmm", "gpr", "rip", "in_flags"):
            rows = observations()
            del first_sse(rows)[field]
            with self.subTest(field=field), self.assertRaises(ValueError):
                check(rows)

    def test_sse_rows_cannot_use_scalar_schema(self):
        rows = observations()
        index = CASES.index(SSE_CASES[0])
        rows[index] = dict(rows[0], name=SSE_CASES[0])
        with self.assertRaises(ValueError):
            check(rows)

    def test_sse_register_files_are_complete_fixed_width_hex(self):
        for field, value in (
            ("xmm", ["0" * 32] * 15),
            ("xmm", ["0" * 16] * 16),
            ("in_xmm", ["0" * 31 + "G"] * 16),
            ("gpr", ["0" * 16] * 17),
            ("in_gpr", [0] * 16),
            ("gpr", "0" * 16),
        ):
            rows = observations()
            first_sse(rows)[field] = value
            with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                check(rows)

    def test_sse_rsp_is_not_observed(self):
        for field in ("in_gpr", "gpr"):
            rows = observations()
            values = ["0" * 16] * 16
            values[4] = "0000000000000008"
            first_sse(rows)[field] = values
            with self.subTest(field=field), self.assertRaises(ValueError):
                check(rows)

    def test_sse_code_has_one_final_ret_at_rip(self):
        for code, rip in (
            ("660f70c100", "0000000000000004"),
            ("c3660f70c1c3", "0000000000000005"),
            ("660f70c100c", "0000000000000005"),
            ("660F70C100C3", "0000000000000005"),
            ("", "0000000000000000"),
            ("660f70c100c3", "0000000000000004"),
        ):
            rows = observations()
            first_sse(rows).update(code=code, rip=rip)
            with self.subTest(code=code, rip=rip), self.assertRaises(ValueError):
                check(rows)

    def test_sse_flags_outside_mask_rejected(self):
        rows = observations()
        first_sse(rows)["flags"] = "0000000000000202"
        with self.assertRaises(ValueError):
            check(rows)

    def test_sse_signal_rejected(self):
        rows = observations()
        index = CASES.index(SSE_CASES[-1])
        rows[index] = {"name": SSE_CASES[-1], "signal": 11, "child_exit": None}
        with self.assertRaises(ValueError):
            check(rows)

    def test_each_je_condition_is_required(self):
        for name in ("je-zf1-taken", "je-zf0-not-taken"):
            with self.subTest(name=name), self.assertRaises(ValueError):
                check([row for row in observations() if row["name"] != name])

    def test_ambiguous_legacy_jne_labels_rejected(self):
        for name, old in (
            ("jne-zf1-not-taken", "branch-taken"),
            ("jne-zf0-taken", "branch-not-taken"),
        ):
            rows = observations()
            rows[CASES.index(name)]["name"] = old
            with self.subTest(name=name), self.assertRaises(ValueError):
                check(rows)

    def test_missing_case(self):
        with self.assertRaises(ValueError):
            check(observations()[:-1])

    def test_duplicate_case(self):
        rows = observations()
        rows[-1] = copy.deepcopy(rows[0])
        with self.assertRaises(ValueError):
            check(rows)

    def test_reordered_inventory(self):
        with self.assertRaises(ValueError):
            check(list(reversed(observations())))

    def test_extra_field(self):
        rows = observations()
        rows[0]["ignored"] = 1
        with self.assertRaises(ValueError):
            check(rows)

    def test_numeric_register_rejected(self):
        rows = observations()
        rows[0]["rax"] = 0
        with self.assertRaises(ValueError):
            check(rows)

    def test_unexpected_signal(self):
        rows = observations()
        rows[0] = {"name": CASES[0], "signal": 11, "child_exit": None}
        with self.assertRaises(ValueError):
            check(rows)

    def test_fault_success_rejected(self):
        rows = observations()
        index = CASES.index("unmapped-data-fault")
        rows[index] = dict(rows[0], name=CASES[index])
        with self.assertRaises(ValueError):
            check(rows)

    def test_nonzero_exit(self):
        with self.assertRaises(ValueError):
            check(observations(), exit_code=115)

    def test_wrong_fault_signal(self):
        rows = observations()
        rows[CASES.index("unmapped-data-fault")]["signal"] = 4
        with self.assertRaises(ValueError):
            check(rows)

    def test_signal_and_exit_are_distinct(self):
        rows = observations()
        rows[CASES.index("unmapped-data-fault")]["child_exit"] = 0
        with self.assertRaises(ValueError):
            check(rows)

    def test_child_failure(self):
        rows = observations()
        rows[0]["child_exit"] = 1
        with self.assertRaises(ValueError):
            check(rows)

    def test_deadline_and_nonfinite_duration(self):
        for seconds in (-1, 30.01, float("nan"), float("inf"), True):
            with self.subTest(seconds=seconds), self.assertRaises(ValueError):
                check(observations(), seconds=seconds)


if __name__ == "__main__":
    unittest.main()

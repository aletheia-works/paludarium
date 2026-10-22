"""The approved guest exceptions cannot widen the root license policy."""

import copy
import hashlib
import pathlib
import sys
import tempfile
import tomllib
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
from evidence import (
    LICENSE_EXCEPTIONS,
    LICENSE_SUFFIX,
    REGISTRY,
    digest,
    guest_policy,
    json_source_lock,
    license_file_name,
    policy_receipt_valid,
    record_source_after,
    snapshot,
)


class PolicyTests(unittest.TestCase):
    def test_exact_root_inheritance(self):
        root = b'[licenses]\nallow = ["Apache-2.0"]\nconfidence-threshold = 0.93\n'
        self.assertEqual(guest_policy(root, LICENSE_EXCEPTIONS), root + LICENSE_SUFFIX)

    def test_source_lock_uses_approved_exceptions(self):
        self.assertEqual(json_source_lock()["guest_license_exceptions"], LICENSE_EXCEPTIONS)

    def test_suffix_is_parsed_as_the_exact_exceptions(self):
        config = tomllib.loads(guest_policy(b"", LICENSE_EXCEPTIONS).decode())
        self.assertEqual(config["licenses"]["exceptions"], LICENSE_EXCEPTIONS)

    def changed(self, index, field, value):
        exceptions = copy.deepcopy(LICENSE_EXCEPTIONS)
        exceptions[index][field] = value
        with self.assertRaises(ValueError):
            guest_policy(b"", exceptions)

    def test_other_crate_rejected(self):
        self.changed(0, "crate", "other@1.0.10")

    def test_other_version_rejected(self):
        self.changed(0, "crate", "webpki-root-certs@1.0.9")
        self.changed(1, "crate", "option-ext@0.2.1")

    def test_extra_license_rejected(self):
        self.changed(0, "allow", ["CDLA-Permissive-2.0", "MIT"])
        self.changed(1, "allow", ["MPL-2.0", "GPL-3.0"])

    def test_missing_or_extra_exception_rejected(self):
        for exceptions in (
            LICENSE_EXCEPTIONS[:1],
            [*LICENSE_EXCEPTIONS, {"crate": "x@1", "allow": ["MIT"]}],
        ):
            with self.assertRaises(ValueError):
                guest_policy(b"", exceptions)

    def test_receipt_detects_policy_license_and_audit_changes(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = pathlib.Path(temporary)
            root = b'[licenses]\nallow = ["Apache-2.0"]\n'
            config = directory / "aube-deny.toml"
            config.write_bytes(guest_policy(root, LICENSE_EXCEPTIONS))
            (directory / "licenses").mkdir()
            licenses = {}
            for exception in LICENSE_EXCEPTIONS:
                license_file = directory / "licenses" / license_file_name(exception)
                license_file.write_bytes(b"complete test license fixture\n")
                licenses[exception["crate"]] = {"source": REGISTRY, "sha256": digest(license_file)}
            receipt = {
                "audits": {"probe": 0, "aube": 0, "ripgrep": 0},
                "license_policy": {
                    "exceptions": copy.deepcopy(LICENSE_EXCEPTIONS),
                    "root_config_sha256": hashlib.sha256(root).hexdigest(),
                    "guest_config_sha256": digest(config),
                    "licenses": licenses,
                },
            }
            policy_receipt_valid(directory, receipt, root)
            with self.assertRaises(ValueError):
                policy_receipt_valid(directory, receipt, root + b"changed")
            mpl = directory / "licenses/option-ext-0.2.0-MPL-2.0.txt"
            mpl.write_bytes(b"truncated")
            with self.assertRaises(ValueError):
                policy_receipt_valid(directory, receipt, root)
            mpl.write_bytes(b"complete test license fixture\n")
            licenses["option-ext@0.2.0"]["source"] = "git+https://example.invalid"
            with self.assertRaises(ValueError):
                policy_receipt_valid(directory, receipt, root)
            licenses["option-ext@0.2.0"]["source"] = REGISTRY
            removed = licenses.pop("option-ext@0.2.0")
            with self.assertRaises(ValueError):
                policy_receipt_valid(directory, receipt, root)
            licenses["option-ext@0.2.0"] = removed
            config.write_bytes(root)
            with self.assertRaises(ValueError):
                policy_receipt_valid(directory, receipt, root)
            config.write_bytes(guest_policy(root, LICENSE_EXCEPTIONS))
            receipt["license_policy"]["guest_config_sha256"] = "0" * 64
            with self.assertRaises(ValueError):
                policy_receipt_valid(directory, receipt, root)
            receipt["license_policy"]["guest_config_sha256"] = digest(config)
            receipt["license_policy"]["exceptions"] = LICENSE_EXCEPTIONS[:1]
            with self.assertRaises(ValueError):
                policy_receipt_valid(directory, receipt, root)
            receipt["license_policy"]["exceptions"] = copy.deepcopy(LICENSE_EXCEPTIONS)
            policy_receipt_valid(directory, receipt, root)
            receipt["audits"]["aube"] = 4
            with self.assertRaises(ValueError):
                policy_receipt_valid(directory, receipt, root)

    def test_failure_still_records_source_after(self):
        with tempfile.TemporaryDirectory() as temporary:
            upstream = pathlib.Path(temporary)
            (upstream / "Cargo.lock").write_bytes(b"fixed source")
            receipt = {"exit": 1, "source_before": snapshot(upstream)}
            record_source_after(upstream, receipt)
            self.assertEqual(receipt["source_before"], receipt["source_after"])
            self.assertTrue(receipt["source_unchanged"])
            self.assertEqual(receipt["exit"], 1)

    def test_changed_source_invalidates_success(self):
        with tempfile.TemporaryDirectory() as temporary:
            upstream = pathlib.Path(temporary)
            source = upstream / "Cargo.lock"
            source.write_bytes(b"original")
            receipt = {"exit": 0, "source_before": snapshot(upstream)}
            source.write_bytes(b"changed")
            record_source_after(upstream, receipt)
            self.assertFalse(receipt["source_unchanged"])
            self.assertEqual(receipt["exit"], 1)
            self.assertIn("source_error", receipt)


if __name__ == "__main__":
    unittest.main()

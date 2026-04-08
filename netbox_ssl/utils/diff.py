"""
Export diff utility for comparing certificate snapshots.

Compares two JSON export snapshots and identifies added, removed,
and changed certificates based on fingerprint matching.
"""

from typing import Any


class ExportDiffer:
    """Compare two export snapshots to find differences."""

    @classmethod
    def compare(
        cls,
        old_snapshot: list[dict[str, Any]],
        new_snapshot: list[dict[str, Any]],
        key_field: str = "fingerprint_sha256",
    ) -> dict[str, Any]:
        """
        Compare old and new export snapshots.

        Args:
            old_snapshot: List of certificate dicts from previous export
            new_snapshot: List of certificate dicts from current export
            key_field: Field to use for matching certificates

        Returns:
            Dict with 'added', 'removed', 'changed', and 'summary' keys
        """
        old_by_key = {cert[key_field]: cert for cert in old_snapshot if key_field in cert}
        new_by_key = {cert[key_field]: cert for cert in new_snapshot if key_field in cert}

        old_keys = set(old_by_key.keys())
        new_keys = set(new_by_key.keys())

        added_keys = new_keys - old_keys
        removed_keys = old_keys - new_keys
        common_keys = old_keys & new_keys

        added = [new_by_key[k] for k in added_keys]
        removed = [old_by_key[k] for k in removed_keys]

        changed = []
        for key in common_keys:
            old_cert = old_by_key[key]
            new_cert = new_by_key[key]
            diffs = cls._find_changes(old_cert, new_cert)
            if diffs:
                changed.append(
                    {
                        key_field: key,
                        "common_name": new_cert.get("common_name", "Unknown"),
                        "changes": diffs,
                    }
                )

        return {
            "added": added,
            "removed": removed,
            "changed": changed,
            "summary": {
                "added_count": len(added),
                "removed_count": len(removed),
                "changed_count": len(changed),
                "unchanged_count": len(common_keys) - len(changed),
            },
        }

    @staticmethod
    def _find_changes(old_cert: dict, new_cert: dict) -> list[dict[str, Any]]:
        """Find field-level changes between two certificate dicts."""
        # Fields worth comparing for change detection
        compare_fields = [
            "status",
            "valid_from",
            "valid_to",
            "issuer",
            "algorithm",
            "key_size",
            "assignment_count",
            "tenant",
        ]

        diffs = []
        for field in compare_fields:
            old_val = old_cert.get(field)
            new_val = new_cert.get(field)
            if old_val != new_val:
                diffs.append({"field": field, "old": old_val, "new": new_val})
        return diffs

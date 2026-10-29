# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

import base64
import unittest

from check_task_id import merged_task_event, parse_task_id, verify_task


class TaskIdTests(unittest.TestCase):
    def test_exact_field_and_release_exceptions(self):
        self.assertEqual(
            parse_task_id("owner", "Summary\r\nTask-ID: 34.01.03\r\n"), "34.01.03"
        )
        self.assertEqual(parse_task_id("owner", "Task-ID: none"), "none")
        self.assertEqual(parse_task_id("dependabot[bot]", None), "none")
        for body in [None, "Task-ID: 34.1.3", "Task-ID: 34.01.03\nTask-ID: none"]:
            with self.subTest(body=body), self.assertRaises(ValueError):
                parse_task_id("owner", body)

    def test_only_one_actionable_mirrored_matching_task_is_accepted(self):
        path = "work/epics/34-capacity/stories/34.01-reserve/tasks/34.01.03-binding/README.md"
        original = (
            "---\ntype: task\nid: '34.01.03'\nstatus: ready\n"
            "monday_item_id: 123\n---\n# Task\n"
        )
        for change in [
            None,
            ("status: ready", "status: in_progress"),
            ("status: ready", "status: blocked"),
            ("status: ready", "status: ready\nstatus: in_progress"),
            ("monday_item_id: 123", "monday_item_id: null"),
            ("id: '34.01.03'", "id: '34.01.04'"),
            ("type: task", "type: story"),
        ]:
            readme = original if change is None else original.replace(*change)

            def request(endpoint, readme=readme):
                if "/git/trees/" in endpoint:
                    return {"tree": [{"path": path}]}
                return {
                    "encoding": "base64",
                    "content": base64.b64encode(readme.encode()).decode(),
                }

            with self.subTest(change=change):
                if change is None or change[1] == "status: in_progress":
                    verify_task("34.01.03", request)
                else:
                    with self.assertRaises(ValueError):
                        verify_task("34.01.03", request)

        for tree in [
            {"tree": []},
            {"tree": [{"path": path}, {"path": path}]},
            {"tree": [{"path": path}], "truncated": True},
        ]:
            with self.subTest(tree=tree), self.assertRaises(ValueError):
                verify_task("34.01.03", lambda _, tree=tree: tree)

    def test_completion_requires_a_main_merge_and_preserves_receiver_contract(self):
        pr = {
            "merged": True,
            "base": {"ref": "main", "repo": {"full_name": "globster-monday/OpenShell"}},
            "body": "Task-ID: 34.01.03",
            "merge_commit_sha": "a" * 40,
            "number": 32,
            "html_url": "https://github.com/globster-monday/OpenShell/pull/32",
            "title": 'Title with "quotes"\nand newlines',
            "user": {"id": 123, "login": "owner"},
        }
        payload = merged_task_event({"pull_request": pr})
        self.assertEqual(payload["event_type"], "task-merged")
        self.assertEqual(
            payload["client_payload"],
            {
                "task_id": "34.01.03",
                "commit_url": "https://github.com/globster-monday/OpenShell/commit/"
                + "a" * 40,
                "repository": "globster-monday/OpenShell",
                "pr_number": "32",
                "pr_url": pr["html_url"],
                "pr_title": pr["title"],
                "pr_author_id": "123",
                "pr_author_login": "owner",
            },
        )
        for change in [
            {"merged": False},
            {"base": {"ref": "parent-task"}},
            {"merge_commit_sha": "not-a-commit"},
        ]:
            with self.subTest(change=change), self.assertRaises(ValueError):
                merged_task_event({"pull_request": pr | change})
        self.assertIsNone(
            merged_task_event({"pull_request": pr | {"body": "Task-ID: none"}})
        )


if __name__ == "__main__":
    unittest.main()

#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Public-fork task validation without downloading private executable code."""

import base64
import json
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

BOT_AUTHORS = {
    "release-please[bot]",
    "release-please-app-globster[bot]",
    "dependabot[bot]",
    "github-actions[bot]",
}
WORKSPACE = "/repos/globster-monday/workspace"


def parse_task_id(author, body):
    if author in BOT_AUTHORS:
        return "none"
    fields = re.findall(r"^[ \t]*Task-ID:([^\r\n]*)", body or "", re.MULTILINE)
    if len(fields) != 1:
        raise ValueError("PR body must have exactly one Task-ID field")
    task_id = fields[0].strip()
    if task_id != "none" and not re.fullmatch(r"[0-9]{2}\.[0-9]{2}\.[0-9]{2}", task_id):
        raise ValueError("Task-ID must be NN.NN.NN or none")
    return task_id


def verify_task(task_id, request):
    if not re.fullmatch(r"[0-9]{2}\.[0-9]{2}\.[0-9]{2}", task_id):
        raise ValueError("Invalid task identity")
    tree = request(f"{WORKSPACE}/git/trees/main?recursive=1")
    if tree.get("truncated"):
        raise ValueError(
            "Workspace tree is incomplete; task identity cannot be verified"
        )
    pattern = (
        rf"work/epics/[^/]+/stories/[^/]+/tasks/{re.escape(task_id)}-[^/]+/README\.md"
    )
    matches = [
        item["path"]
        for item in tree["tree"]
        if re.fullmatch(pattern, item.get("path", ""))
    ]
    if len(matches) != 1:
        raise ValueError("Task-ID must resolve to exactly one Workspace task")
    path = urllib.parse.quote(matches[0], safe="/")
    content = request(f"{WORKSPACE}/contents/{path}?ref=main")
    if content.get("encoding") != "base64":
        raise ValueError("Workspace task content is unavailable")
    readme = base64.b64decode(content["content"]).decode("utf-8")
    frontmatter = re.match(r"\A---\r?\n(.*?)\r?\n---(?:\r?\n|$)", readme, re.DOTALL)
    if not frontmatter:
        raise ValueError("Workspace task metadata is unavailable")

    def field(name):
        values = re.findall(rf"^{name}:[ \t]*([^\r\n]*)", frontmatter[1], re.MULTILINE)
        if len(values) != 1:
            raise ValueError("Workspace task metadata is ambiguous")
        return values[0].split("#", 1)[0].strip().strip("'\"")

    if field("type") != "task" or field("id") != task_id:
        raise ValueError("Workspace task identity does not match")
    if field("status") not in {"ready", "in_progress"}:
        raise ValueError("Workspace task is not actionable")
    if not re.fullmatch(r"[0-9]+", field("monday_item_id")):
        raise ValueError("Workspace task has not been mirrored")


def merged_task_event(event):
    pr = event["pull_request"]
    if not pr.get("merged") or pr["base"]["ref"] != "main":
        raise ValueError("Only a PR merged into main may complete a task")
    task_id = parse_task_id(pr["user"]["login"], pr.get("body"))
    if task_id == "none":
        return None
    repository = pr["base"]["repo"]["full_name"]
    merge_sha = pr["merge_commit_sha"]
    if not re.fullmatch(r"[0-9a-f]{40}", merge_sha):
        raise ValueError("Missing authoritative merge commit")
    return {
        "event_type": "task-merged",
        "client_payload": {
            "task_id": task_id,
            "commit_url": f"https://github.com/{repository}/commit/{merge_sha}",
            "repository": repository,
            "pr_number": str(pr["number"]),
            "pr_url": pr["html_url"],
            "pr_title": pr["title"],
            "pr_author_id": str(pr["user"]["id"]),
            "pr_author_login": pr["user"]["login"],
        },
    }


def github_request(path, data=None):
    request = urllib.request.Request(
        f"https://api.github.com{path}",
        data=json.dumps(data).encode() if data is not None else None,
        headers={
            "Authorization": f"Bearer {os.environ['GITHUB_TOKEN']}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "Content-Type": "application/json",
        },
    )
    with urllib.request.urlopen(request, timeout=30) as response:
        return None if response.status == 204 else json.load(response)


def main():
    if sys.argv[1:] == ["parse"]:
        event = json.loads(Path(os.environ["GITHUB_EVENT_PATH"]).read_text())
        pr = event["pull_request"]
        task_id = parse_task_id(pr["user"]["login"], pr.get("body"))
        with Path(os.environ["GITHUB_OUTPUT"]).open("a") as output:
            output.write(f"task_id={task_id}\n")
    elif sys.argv[1:] == ["verify"]:
        verify_task(os.environ["TASK_ID"], github_request)
        print("Workspace task identity, actionable status and mirror verified")
    elif sys.argv[1:] == ["notify"]:
        event = json.loads(Path(os.environ["GITHUB_EVENT_PATH"]).read_text())
        payload = merged_task_event(event)
        if payload is not None:
            github_request(f"{WORKSPACE}/dispatches", payload)
            print("Merged task dispatched to Workspace for authoritative verification")
    else:
        raise ValueError("Expected parse, verify or notify")


if __name__ == "__main__":
    try:
        main()
    except (ValueError, KeyError, TypeError, urllib.error.URLError):
        print(
            "::error::Task metadata validation failed; check the PR and task-sync app access"
        )
        sys.exit(1)

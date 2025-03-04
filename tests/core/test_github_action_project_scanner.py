import os
import pathlib

import pytest

from guarddog.scanners import GitHubActionDependencyScanner
from guarddog.scanners.github_action_project_scanner import parse_action_from_step, GitHubWorkflowStep, GitHubAction


def test_go_parse_requirements():
    scanner = GitHubActionDependencyScanner()

    with open(
        os.path.join(pathlib.Path(__file__).parent.resolve(), "resources", "workflow.yaml"),
        "r",
    ) as f:
        requirements = scanner.parse_requirements(f.read())
        assert requirements == {
            "actions/checkout": {"v4.2.2", "11bd71901bbe5b1630ceea73d27597364c9af683"},
            "actions/setup-python": {"v5.3.0"},
            "actions/create-github-app-token": {"0d564482f06ca65fa9e77e2510873638c82206f2"},
            "peter-evans/create-pull-request": {"v7"},
        }


@pytest.mark.parametrize(
    "step,expected_action",
    [
        (GitHubWorkflowStep(
            name="Checkout code",
            uses="actions/checkout@v4.2.2",
        ), GitHubAction(name="actions/checkout", ref="v4.2.2")),
        (GitHubWorkflowStep(
            name="Setup Python",
            uses="actions/setup-python@v5.3.0",
        ), GitHubAction(name="actions/setup-python", ref="v5.3.0")),
        (GitHubWorkflowStep(
            name="Create GitHub App Token",
            uses="actions/create-github-app-token@0d564482f06ca65fa9e77e2510873638c82206f2",
        ), GitHubAction(name="actions/create-github-app-token", ref="0d564482f06ca65fa9e77e2510873638c82206f2")),
        (GitHubWorkflowStep(
            name="Create Pull Request",
            uses="peter-evans/create-pull-request@v7",
        ), GitHubAction(name="peter-evans/create-pull-request", ref="v7")),
        (GitHubWorkflowStep(
            name="non-uses step",
            uses="",
        ), None),
        (GitHubWorkflowStep(
            name="Relative path",
            uses="./relative-path",
        ), None)
    ],
)
def test_parse_action_from_step(step, expected_action):
    assert parse_action_from_step(step) == expected_action

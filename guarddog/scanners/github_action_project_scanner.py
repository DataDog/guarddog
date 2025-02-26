import logging
from typing import List, Dict, TypedDict
from typing_extensions import NotRequired

import yaml
import re

from guarddog.scanners.github_action_scanner import GithubActionScanner
from guarddog.scanners.scanner import ProjectScanner

log = logging.getLogger("guarddog")


class GitHubWorkflowStep(TypedDict):
    name: NotRequired[str]
    uses: NotRequired[str]


class GitHubWorkflowJob(TypedDict):
    name: str
    uses: str
    runs_on: str
    steps: List[GitHubWorkflowStep]


class GitHubWorkflowFile(TypedDict):
    name: str
    jobs: Dict[str, GitHubWorkflowJob]


class GitHubAction(TypedDict):
    name: str
    ref: str


def parse_action_from_step(step: GitHubWorkflowStep) -> GitHubAction | None:
    """
    Parses a step in a GitHub workflow file and returns a GitHub action reference if it exists.

    Args:
        step (GitHubWorkflowStep): Step in a GitHub workflow file

    Returns:
        GitHubAction | None: GitHub action reference if it exists, None otherwise
    """
    if "uses" not in step:
        return None

    if step["uses"].startswith("/") or step["uses"].startswith("./"):
        return None
    parts = step["uses"].split("@", 1)
    if len(parts) != 2:
        log.debug(f"Invalid action reference: {step['uses']}")
        return None

    if re.search(r"^([\w-])+/([\w./-])+$", parts[0]):
        return GitHubAction(name=parts[0], ref=parts[1])
    return None


class GitHubActionDependencyScanner(ProjectScanner):
    """
    Scans all 3rd party actions in a GitHub workflow file.
    """

    def __init__(self) -> None:
        super().__init__(GithubActionScanner())

    def parse_requirements(self, raw_requirements: str) -> dict[str, set[str]]:
        actions = self.parse_workflow_3rd_party_actions(raw_requirements)

        requirements: dict[str, set[str]] = {}
        for action in actions:
            repo, version = action["name"], action["ref"]
            if repo in requirements:
                requirements[repo].add(version)
            else:
                requirements[repo] = {version}
        return requirements

    def parse_workflow_3rd_party_actions(
        self, workflow_file: str
    ) -> List[GitHubAction]:
        """
        Parses a GitHub workflow file and returns a list of 3rd party actions
        used in the workflow.

        Args:
            workflow_file (str): Contents of the GitHub workflow file

        Returns:
            List[GitHubAction]: List of 3rd party actions used in the workflow
        """
        f: GitHubWorkflowFile = yaml.safe_load(workflow_file)
        actions = []
        for job in f.get("jobs", {}).values():
            for step in job.get("steps", []):
                action = parse_action_from_step(step)
                if action:
                    actions.append(action)
        return actions

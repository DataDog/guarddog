import logging
import os
from typing import List, Dict, TypedDict
from typing_extensions import NotRequired

import yaml
import re

from guarddog.scanners.github_action_scanner import GithubActionScanner
from guarddog.scanners.scanner import ProjectScanner
from guarddog.scanners.scanner import Dependency, DependencyVersion

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

    def parse_requirements(self, raw_requirements: str) -> List[Dependency]:
        actions = self.parse_workflow_3rd_party_actions(raw_requirements)
        dependencies: List[Dependency] = []

        for action in actions:
            name = action["name"]
            version = action["ref"]
            idx = next(
                iter(
                    [
                        ix
                        for ix, line in enumerate(raw_requirements.splitlines())
                        if name in line
                    ]
                ),
                0,
            )
            # find the dep with the same name or create a new one
            dep_versions = [DependencyVersion(version=version, location=idx + 1)]

            dep = next(
                filter(
                    lambda d: d.name == name,
                    dependencies,
                ),
                None,
            )
            if not dep:
                dep = Dependency(name=name, versions=[])
                dependencies.append(dep)

            dep.versions.extend(dep_versions)

        return dependencies

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

    def find_requirements(self, directory: str) -> list[str]:
        requirement_files = []

        if not os.path.isdir(os.path.join(directory, ".git")):
            raise Exception(
                "unable to find github workflows, not called from git directory"
            )
        workflow_folder = os.path.join(directory, ".github/workflows")
        if os.path.isdir(workflow_folder):
            for name in os.listdir(workflow_folder):
                if re.match(r"^(.+)\.y(a)?ml$", name, flags=re.IGNORECASE):
                    requirement_files.append(os.path.join(workflow_folder, name))
        return requirement_files

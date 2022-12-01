from abc import abstractmethod


class Detector:
    def __init__(self) -> None:
        pass

    # returns (ruleMatches, message)
    @abstractmethod
    def detect(self, package_info) -> tuple[bool, str]:
        pass
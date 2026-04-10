# Legitimate code that should NOT trigger threat-process-cryptomining

# Base64 hashes in package metadata (RECORD-style)
CHECKSUMS = {
    "mylib/utils.py": "sha256=rybiH839YwzyY13SiGA676iHCBTh3mqFdam5tqx041I",
    "mylib/core.py": "sha256=1JRCqi7jtvDEOfxb3nnGpqXobXUJ7ICvf0eTUQyw_JQ",
}

# Common words that overlap with mining terminology
class TaskScheduler:
    def assign_worker(self, task):
        """Assign a worker to this task."""
        self.workers.append(task)

    def get_difficulty(self):
        """Return the difficulty level of the puzzle."""
        return self.difficulty

    def count_shares(self):
        """Count shares allocated to this user."""
        return len(self.shares)

# Port numbers in legitimate networking
SERVER_CONFIG = {
    "debug_port": ":3333",
    "metrics_port": ":4444",
}

# Legitimate code that should NOT trigger threat-process-write-exec.
# Both cases write a temp file and then hand its path to a subprocess, which is
# the shape most at risk of a false positive. Neither one executes the file it
# wrote: the temp file is input *data* for an unrelated binary.
import json
import subprocess
from tempfile import NamedTemporaryFile


def transcode(source_path, options):
    """Write an ffmpeg filter script, then let ffmpeg read it."""
    with NamedTemporaryFile(suffix=".txt", delete=False, mode="w") as filters:
        filters.write("scale=1280:-2\n")

    subprocess.run(["ffmpeg", "-i", source_path, "-filter_script", filters.name], check=True)


def apply_config(cfg):
    """Serialize config to a temp file for a CLI that only accepts a path."""
    with NamedTemporaryFile(suffix=".json", delete=False, mode="w") as handle:
        handle.write(json.dumps(cfg))

    subprocess.check_call(["terraform", "apply", "-var-file", handle.name])


def cache_report(rows):
    """Write a report to a scratch file and read it back — no execution at all."""
    with NamedTemporaryFile(suffix=".csv", delete=False, mode="w") as report:
        report.write("name,count\n")
        for name, count in rows:
            report.write(f"{name},{count}\n")

    with open(report.name) as fh:
        return fh.read()

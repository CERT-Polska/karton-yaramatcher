import argparse
import logging
import os
import re
import tempfile
import zipfile
from collections import defaultdict
from itertools import chain
from typing import Optional

import yara  # type: ignore
from karton.core import Config, Karton, Task

from .__version__ import __version__

log = logging.getLogger(__name__)


def normalize_rule_name(match: str) -> str:
    """Malpedia's rule names have their own unique naming convention. This function is
    used for normalizing the naming by removing Malpedia's unique suffixes.
    """

    parts = match.split("_")
    for ignore_pattern in ["g\\d+", "w\\d+", "a\\d+", "auto"]:
        if re.match(ignore_pattern, parts[-1]):
            return "_".join(parts[:-1])
    return match


class YaraHandler:
    """Used to load and compile Yara rules from a folder and match them
    against a sample.
    """

    def __init__(self, path: Optional[str] = None) -> None:
        # load and compile all Yara rules from a folder
        yara_path = path or "rules"
        rule_paths = []

        # if it's a directory, then walk recursively
        if os.path.isdir(yara_path):
            for root, _, f_names in os.walk(yara_path):
                # Recursively collect paths for yara rules in the folder
                for f in f_names:
                    # Ignore non Yara files based on extension
                    if not f.endswith(".yar") and not f.endswith(".yara"):
                        continue
                    rule_paths.append(os.path.join(root, f))

            if not rule_paths:
                raise RuntimeError("The yara rule directory is empty")

            # Convert the list to a dict {"0": "rules/rule1.yar", "1": "rules/dir/rul...
            rules_dict = {str(i): rule_paths[i] for i in range(0, len(rule_paths))}
        # if it's an index file (e.g., https://github.com/Yara-Rules/rules)
        elif os.path.isfile(yara_path) and yara_path.endswith(".yar"):
            rules_dict = {"0": yara_path}
        else:
            raise RuntimeError("Please supply a valid path to Yara rule(s)")

        log.info("Compiling Yara rules. This might take a few moments...")
        # Hold yara.Rules object with the compiled rules
        self.rules = yara.compile(filepaths=rules_dict)
        log.info("Loaded yara rules from {} files".format(len(rules_dict)))

    def get_matches(self, content) -> yara.Rules:
        """Use the compiled Yara rules and scan them against a sample

        Args:
            content (bytes): Bytes representing the binary data of the sample

        Returns:
            yara.Rules: Rules that matched the sample
        """
        return self.rules.match(data=content)


class YaraMatcher(Karton):
    """
    Scan samples and analysis results and tag malware samples using matched yara rules.
    """

    identity = "karton.yaramatcher"
    persistent = True
    version = __version__
    filters = [
        {"type": "sample", "stage": "recognized", "kind": "runnable"},
        {"type": "sample", "stage": "recognized", "kind": "dump"},
        {"type": "analysis", "kind": "drakrun"},
        {"type": "analysis", "kind": "joesandbox"},
    ]

    @classmethod
    def args_parser(cls):
        parser = super().args_parser()
        parser.add_argument("--rules", help="Yara rules directory", default="rules")
        return parser

    @classmethod
    def config_from_args(cls, config: Config, args: argparse.Namespace) -> None:
        super().config_from_args(config, args)
        config.load_from_dict({"yaramatcher": {"rules": args.rules}})

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.yara_handler = YaraHandler(
            path=self.config.get("yaramatcher", "rules", fallback="rules")
        )

    def scan_sample(self, sample: bytes) -> list[str]:
        # Get all matches for this sample
        matches = self.yara_handler.get_matches(sample)
        rule_names = []
        for match in matches:
            rule_names.append(normalize_rule_name(match.rule))
        return rule_names

    def process_drakrun(self, task: Task) -> defaultdict[str, list[str]]:
        """Scan artifacts of drakvuf-sandbox analysis

        Args:
            task: drakrun analysis task (with dumps.zip resource in payload)

        Returns:
            matches_dict: mapping matched yara rule names to lists of matched dump names
        """
        self.log.info("Processing drakrun analysis")
        matches_dict: defaultdict[str, list[str]] = defaultdict(list)

        with tempfile.TemporaryDirectory() as tmpdir:
            dumpsf = os.path.join(tmpdir, "dumps.zip")
            task.get_resource("dumps.zip").download_to_file(dumpsf)  # type: ignore

            zipf = zipfile.ZipFile(dumpsf)
            zipf.extractall(tmpdir)

            for rootdir, _dirs, files in os.walk(tmpdir):
                for filename in files:
                    # skip non-dump files
                    if not re.match(r"^[a-f0-9]{4,16}_[a-f0-9]{16}$", filename):
                        continue

                    with open(f"{rootdir}/{filename}", "rb") as dumpf:
                        content = dumpf.read()
                    file_matches = self.scan_sample(content)
                    for rule in file_matches:
                        matches_dict[rule].append(filename)

        return matches_dict

    def process_joesandbox(self, task: Task) -> defaultdict[str, list[str]]:
        """Scan artifacts of joesandbox analysis

        Args:
            task: jesandbox analysis task (with dumps.zip resource in payload)

        Returns:
            matches_dict: mapping matched yara rule names to lists of matched dump names
        """
        self.log.info("Processing joesandbox analysis")
        matches_dict: defaultdict[str, list[str]] = defaultdict(list)

        with tempfile.TemporaryDirectory() as tmpdir:
            dumpsf = os.path.join(tmpdir, "dumps.zip")
            task.get_resource("dumps.zip").download_to_file(dumpsf)  # type: ignore

            zipf = zipfile.ZipFile(dumpsf)
            zipf.extractall(tmpdir, pwd=b"infected")

            for rootdir, _dirs, files in os.walk(tmpdir):
                for filename in files:
                    with open(f"{rootdir}/{filename}", "rb") as dumpf:
                        content = dumpf.read()
                    file_matches = self.scan_sample(content)
                    for rule in file_matches:
                        matches_dict[rule].append(filename)

        return matches_dict

    def process(self, task: Task) -> None:
        headers = task.headers
        sample = task.get_resource("sample")
        yara_matches: list[str] = []
        matches_dict: defaultdict[str, list[str]] = defaultdict(list)

        if headers["type"] == "sample":
            self.log.info(f"Processing sample {sample.metadata['sha256']}")
            if sample.content is not None:
                yara_matches = self.scan_sample(sample.content)
                # For sample type, use sha256 as the filename
                for rule in yara_matches:
                    matches_dict[rule] = [sample.metadata["sha256"]]
        elif headers["type"] == "analysis":
            if headers["kind"] == "drakrun":
                matches_dict = self.process_drakrun(task)
            elif headers["kind"] == "joesandbox":
                matches_dict = self.process_joesandbox(task)

        if not matches_dict:
            self.log.info("Couldn't match any yara rules")
            return None

        self.log.info(
            "Got %d yara hits in total with %s distinct names",
            len(list(chain(matches_dict.values()))),
            len(matches_dict.keys()),
        )

        self.log.info(f"Matches: {matches_dict}")

        # Add "yara:" prefix to tags
        tags = [f"yara:{match}" for match in matches_dict.keys()]

        tag_task = Task(
            {"type": "sample", "stage": "analyzed"},
            payload={"sample": sample, "tags": tags, "yara-matches": matches_dict},
        )
        self.send_task(tag_task)

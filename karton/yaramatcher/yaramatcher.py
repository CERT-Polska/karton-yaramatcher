import logging
import os
import re
import tempfile
import zipfile
from typing import List, Optional

import yara  # type: ignore
from karton.core import Config, Karton, Task  # type: ignore

from .__version__ import __version__

log = logging.getLogger(__name__)


def normalize_rule_name(match: str) -> str:
    """Malpedia's rule names have their own unique naming convention. This function is used
    for normalizing the naming by removing Malpedia's unique suffixes.
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
        super().__init__()
        # load and compile all Yara rules from a folder
        yara_path = path or "rules"
        rule_paths = []

        for root, _, f_names in os.walk(yara_path):
            # Recursively collect paths for yara rules in the folder
            for f in f_names:
                # Ignore non Yara files based on extension
                if not f.endswith(".yar") and not f.endswith(".yara"):
                    continue
                rule_paths.append(os.path.join(root, f))

        if not rule_paths:
            raise RuntimeError("The yara rule directory is empty")

        # Convert the list to a dict {"0": "rules/rule1.yar", "1": "rules/folder/rul...
        rules_dict = {str(i): rule_paths[i] for i in range(0, len(rule_paths))}

        log.info("Compiling Yara rules. This might take a few moments...")
        # Hold yara.Rules object with the compiled rules
        self.rules = yara.compile(filepaths=rules_dict)
        log.info("Loaded {} yara rules".format(len(rule_paths)))

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
        {"type": "analysis", "kind": "cuckoo1"},
        {"type": "analysis", "kind": "drakrun"},
        {"type": "analysis", "kind": "joesandbox"},
    ]

    @classmethod
    def args_parser(cls):
        parser = super().args_parser()
        parser.add_argument("--rules", help="Yara rules directory", default="rules")
        return parser

    @classmethod
    def main(cls):
        parser = cls.args_parser()
        args = parser.parse_args()

        config = Config(args.config_file)
        service = YaraMatcher(config=config, yara_rule_dir=args.rules)
        service.loop()

    def __init__(self, yara_rule_dir: Optional[str] = None, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.yara_handler = YaraHandler(path=yara_rule_dir or "rules")

    def scan_sample(self, sample: bytes) -> List[str]:
        # Get all matches for this sample
        matches = self.yara_handler.get_matches(sample)
        rule_names = []
        for match in matches:
            rule_names.append("yara:{}".format(normalize_rule_name(match.rule)))
        return rule_names

    def process_cuckoo(self, task: Task) -> List[str]:
        yara_matches: List[str] = []
        analysis = task.get_payload("analysis")
        self.log.info(f"Processing cuckoo analysis {analysis.name}")

        with analysis.extract_temporary() as analysis_dir:
            dump_dir = f"{analysis_dir}/dumps"
            for rootdir, _dirs, files in os.walk(dump_dir):
                for filename in files:
                    if filename.endswith(".txt") or filename.endswith(".metadata"):
                        continue
                    self.log.debug(f"Checking {filename}")
                    with open(f"{rootdir}/{filename}", "rb") as dumpf:
                        content = dumpf.read()
                    yara_matches += self.scan_sample(content)

        return yara_matches

    def process_drakrun(self, task: Task) -> List[str]:
        self.log.info("Processing drakrun analysis")
        yara_matches: List[str] = []

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
                    yara_matches += self.scan_sample(content)

        return yara_matches

    def process_joesandbox(self, task: Task) -> List[str]:
        self.log.info("Processing joesandbox analysis")
        yara_matches: List[str] = []

        with tempfile.TemporaryDirectory() as tmpdir:
            dumpsf = os.path.join(tmpdir, "dumps.zip")
            task.get_resource("dumps.zip").download_to_file(dumpsf)  # type: ignore

            zipf = zipfile.ZipFile(dumpsf)
            zipf.extractall(tmpdir, pwd=b"infected")

            for rootdir, _dirs, files in os.walk(tmpdir):
                for filename in files:
                    with open(f"{rootdir}/{filename}", "rb") as dumpf:
                        content = dumpf.read()
                    yara_matches += self.scan_sample(content)

        return yara_matches

    def process(self, task: Task) -> None:  # type: ignore
        headers = task.headers
        sample = task.get_resource("sample")
        yara_matches: List[str] = []

        if headers["type"] == "sample":
            self.log.info(f"Processing sample {sample.metadata['sha256']}")
            if sample.content is not None:
                yara_matches = self.scan_sample(sample.content)
        elif headers["type"] == "analysis":
            if headers["kind"] == "cuckoo1":
                yara_matches += self.process_cuckoo(task)
            elif headers["kind"] == "drakrun":
                yara_matches += self.process_drakrun(task)
            elif headers["kind"] == "joesandbox":
                yara_matches += self.process_joesandbox(task)

        if not yara_matches:
            self.log.info("Couldn't match any yara rules")
            return None

        unique_matches = sorted(list(set(yara_matches)))

        self.log.info(
            "Got %d yara hits in total with %s distinct names",
            len(yara_matches),
            len(unique_matches),
        )

        tag_task = Task(
            {"type": "sample", "stage": "analyzed"},
            payload={"sample": sample, "tags": unique_matches},
        )
        self.send_task(tag_task)

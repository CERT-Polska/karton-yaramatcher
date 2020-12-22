import unittest
from karton.yaramatcher import YaraMatcher, normalize_rule_name
from karton.core.test import KartonTestCase
from karton.core import Resource, Task


class TestUtils(unittest.TestCase):
    def test_normalize_rule_name(self) -> None:
        self.assertEqual("win_remcos", normalize_rule_name("win_remcos_auto"))
        self.assertEqual("win_agent_tesla", normalize_rule_name("win_agent_tesla_w0"))
        self.assertEqual("win_nymaim", normalize_rule_name("win_nymaim_a0"))
        self.assertEqual("duck", normalize_rule_name("duck_g123"))


class YaraMatcherTestBasic(KartonTestCase):
    karton_class = YaraMatcher
    kwargs = {"yara_rule_dir": "tests/testdata/rules"}

    def test_pass(self) -> None:
        res = Resource("sample", b"z")
        task = Task(
            {"type": "sample", "stage": "recognized", "kind": "runnable"},
            payload={"sample": res},
        )
        res_tasks = self.run_task(task)
        self.assertTasksEqual(res_tasks, [])

    def test_match_1(self) -> None:
        res = Resource("sample", b"a")
        input_task = Task(
            {"type": "sample", "stage": "recognized", "kind": "runnable"},
            payload={"sample": res},
        )
        expected_task = Task(
            {"type": "sample", "origin": "karton.yaramatcher", "stage": "analyzed"},
            payload={"sample": res, "tags": ["yara:a"]},
        )
        res_tasks = self.run_task(input_task)
        self.assertTasksEqual(res_tasks, [expected_task])

    def test_match_2(self) -> None:
        res = Resource("sample", b"ab")
        input_task = Task(
            {"type": "sample", "stage": "recognized", "kind": "runnable"},
            payload={"sample": res},
        )
        expected_task = Task(
            {"type": "sample", "origin": "karton.yaramatcher", "stage": "analyzed"},
            payload={"sample": res, "tags": ["yara:a", "yara:b"]},
        )
        res_tasks = self.run_task(input_task)
        self.assertTasksEqual(res_tasks, [expected_task])


if __name__ == "__main__":
    unittest.main()

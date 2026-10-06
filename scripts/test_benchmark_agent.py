"""性能报告的反例校验，避免漏调用、重复插件或失败请求成为有效样本。"""
import copy
import unittest

from benchmark_agent import validate_run


class BenchmarkAccountingTest(unittest.TestCase):
    def sample(self, mode="plugin", scenario="mixed"):
        return {"mode": mode, "scenario": scenario, "threads": 2, "operations": 20,
                "modelCalls": 20, "toolCalls": 20 if scenario == "mixed" else 0,
                "pluginConstructions": 1 if mode == "plugin" else 0,
                "pluginChecks": 80 if mode == "plugin" else 0,
                "elapsedNanos": 1000, "operationsPerSecond": 20000000,
                "p50Nanos": 10, "p95Nanos": 20, "p99Nanos": 30,
                "firstByteP95Nanos": 20 if scenario == "stream" else 0}

    def test_accepts_valid_mixed_and_stream(self):
        for scenario in ("mixed", "stream"):
            validate_run(self.sample(scenario=scenario), "plugin", scenario, 2, 10)

    def test_rejects_missing_calls_wrong_plan_and_duplicate_plugins(self):
        for key, value in (("modelCalls", 19), ("toolCalls", 19), ("operations", 19),
                           ("pluginConstructions", 2), ("pluginChecks", 0),
                           ("mode", "no-agent"), ("scenario", "stream"), ("threads", 1)):
            with self.subTest(key=key):
                sample = copy.deepcopy(self.sample())
                sample[key] = value
                with self.assertRaises(ValueError):
                    validate_run(sample, "plugin", "mixed", 2, 10)

    def test_rejects_zero_negative_or_missing_latency(self):
        for value in (0, -1, None, float("nan")):
            sample = self.sample()
            sample["p95Nanos"] = value
            with self.assertRaises(ValueError):
                validate_run(sample, "plugin", "mixed", 2, 10)

    def test_stream_requires_first_byte_measurement(self):
        sample = self.sample(scenario="stream")
        sample["firstByteP95Nanos"] = 0
        with self.assertRaises(ValueError):
            validate_run(sample, "plugin", "stream", 2, 10)

    def test_non_plugin_mode_must_not_construct_plugin(self):
        sample = self.sample(mode="no-policy")
        sample["pluginConstructions"] = 1
        with self.assertRaises(ValueError):
            validate_run(sample, "no-policy", "mixed", 2, 10)


if __name__ == "__main__":
    unittest.main()

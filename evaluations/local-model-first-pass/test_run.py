"""Offline checks for capture boundaries and reproducible task inputs."""

import ast
import importlib.util
import io
import json
import re
import tempfile
import unittest
import urllib.error
import urllib.request
from pathlib import Path
from unittest.mock import Mock

ROOT = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("local_capture", ROOT / "run.py")
RUN = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(RUN)


class CaptureBoundaryTests(unittest.TestCase):
    def test_prompt_matches_fixture_without_executing_it(self):
        fixture = ast.parse((ROOT / "fixtures/review_lookup.py").read_text())
        prompt = (ROOT / "prompts/review.md").read_text()
        snippets = re.findall(r"```python\n(.*?)```", prompt, re.S)
        self.assertEqual(len(snippets), 1)
        self.assertEqual(len(snippets[0].rstrip().splitlines()), 3)
        self.assertEqual(ast.dump(ast.parse(snippets[0]).body[0]), ast.dump(fixture.body[1]))

    def test_inputs_preserve_guidance_and_exclude_assessment_oracle(self):
        requests, provenance = RUN.prepare()
        self.assertEqual(len(requests), 4)
        self.assertEqual(len(provenance["rule_sources"]), 2)
        for task in ("generation", "review"):
            baseline = requests[(task, "baseline")][0]["content"]
            guided = requests[(task, "codeguard-subset")][0]["content"]
            self.assertTrue(guided.endswith(baseline))
            self.assertIn(provenance["guidance"], guided)
            self.assertNotIn("Manual assessment rubric", guided)
            self.assertNotIn("Intentionally insecure evaluation fixture", guided)

    def test_api_rejects_unknown_paths_and_oversized_response(self):
        api = RUN.LocalApi(11473, 10)
        api.opener = Mock()
        with self.assertRaises(ValueError):
            api.call("https://example.com")
        api.opener.open.assert_not_called()
        api.opener.open.return_value = io.BytesIO(b"x" * (RUN.MAX_RESPONSE_BYTES + 1))
        with self.assertRaisesRegex(ValueError, "capture bound"):
            api.call("/api/version")

    def test_redirects_are_refused(self):
        request = urllib.request.Request("http://127.0.0.1:11473/api/version")
        with self.assertRaises(urllib.error.HTTPError):
            RUN.NoRedirect().redirect_request(request, None, 302, "redirect", {}, "https://example.com")

    def test_saved_request_encoding_matches_wire_body_for_unicode(self):
        api = RUN.LocalApi(11473, 10)
        api.opener = Mock()
        api.opener.open.return_value = io.BytesIO(b'{"version":"test"}')
        payload = {"messages": [{"role": "user", "content": "start \u2264 end"}]}
        api.call("/api/chat", payload)
        request = api.opener.open.call_args.args[0]
        self.assertEqual(request.data, RUN.encode_request(payload))

    def test_cloud_backed_model_is_rejected(self):
        api = Mock()
        api.call.side_effect = [
            {"models": [{"name": "example", "digest": "a" * 64}]},
            {"remote_host": "https://example.com"},
        ]
        with self.assertRaisesRegex(ValueError, "Cloud-backed"):
            RUN.local_model(api, "example")

    def test_incomplete_output_cannot_be_reported_as_completed(self):
        response = {"done": False, "model": "example", "message": {"content": ""}}
        with self.assertRaisesRegex(ValueError, "Incomplete"):
            RUN.response_metrics(response, "example", 4096, {"models": []})

    def test_limits_and_unknown_effective_context_remain_visible(self):
        response = {"done": True, "model": "example", "message": {"content": "partial"},
                    "prompt_eval_count": 20, "eval_count": 1024, "done_reason": "length"}
        metrics = RUN.response_metrics(response, "example", 4096, {"models": []})
        self.assertIsNone(metrics["observed_context"])
        self.assertIn("Effective context is unknown", metrics["warnings"])
        self.assertIn("Non-normal stop reason: length", metrics["warnings"])

    def test_model_output_is_written_as_data(self):
        with tempfile.TemporaryDirectory() as directory:
            marker = Path(directory) / "must-not-exist"
            output = f"__import__('pathlib').Path({str(marker)!r}).write_text('executed')"
            path = Path(directory) / "response.json"
            RUN.write_json(path, {"message": {"content": output}})
            self.assertEqual(json.loads(path.read_text())["message"]["content"], output)
            self.assertFalse(marker.exists())


if __name__ == "__main__":
    unittest.main()

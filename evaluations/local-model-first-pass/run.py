"""Capture the bounded issue #73 experiment; never execute model output."""

from __future__ import annotations

import argparse
import hashlib
import json
import platform
import re
import subprocess
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent
REPO = ROOT.parent.parent
MAX_RESPONSE_BYTES = 1024 * 1024
SECTIONS = {
    "codeguard-0-input-validation-injection": (
        "Core Strategy", "Validation Playbook", "SQL Injection Prevention"
    ),
    "codeguard-0-authorization-access-control": (
        "Core Principles", "Systemic Controls", "Preventing IDOR"
    ),
}
ORDER = (
    ("generation", "baseline"), ("generation", "codeguard-subset"),
    ("review", "codeguard-subset"), ("review", "baseline"),
)


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def encode_request(value: dict) -> bytes:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def write_json(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, indent=2, ensure_ascii=False) + "\n")


class NoRedirect(urllib.request.HTTPRedirectHandler):
    """A loopback request must never redirect to another destination."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise urllib.error.HTTPError(req.full_url, code, "Redirect refused", headers, fp)


class LocalApi:
    def __init__(self, port: int, timeout: int):
        if not 1024 <= port <= 65535 or not 1 <= timeout <= 600:
            raise ValueError("Invalid local port or timeout")
        self.base = f"http://127.0.0.1:{port}"
        self.timeout = timeout
        self.opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}), NoRedirect()
        )

    def call(self, path: str, payload: dict | None = None) -> dict:
        if path not in {"/api/version", "/api/tags", "/api/show", "/api/ps", "/api/chat"}:
            raise ValueError("Unsupported endpoint")
        data = None if payload is None else encode_request(payload)
        request = urllib.request.Request(
            self.base + path, data=data, headers={"Content-Type": "application/json"}
        )
        with self.opener.open(request, timeout=self.timeout) as response:
            raw = response.read(MAX_RESPONSE_BYTES + 1)
        if len(raw) > MAX_RESPONSE_BYTES:
            raise ValueError("Response exceeds capture bound")
        value = json.loads(raw)
        if not isinstance(value, dict) or value.get("error"):
            raise ValueError("API returned an invalid object or error")
        return value


def prepare(root: Path = ROOT, repo: Path = REPO) -> tuple[dict, dict]:
    parts, sources = [], []
    for rule_id, headings in SECTIONS.items():
        path = repo / "skills/codeguard/rules" / f"{rule_id}.md"
        raw = path.read_bytes()
        text, selected = raw.decode("utf-8"), []
        for heading in headings:
            marker = f"### {heading}\n"
            if text.count(marker) != 1:
                raise ValueError(f"Missing or ambiguous section: {rule_id}/{heading}")
            start = text.index(marker)
            stop = text.find("\n### ", start + len(marker))
            selected.append(text[start:len(text) if stop < 0 else stop].rstrip())
        parts.append(f"# {rule_id}\n\n" + "\n\n".join(selected))
        sources.append({"path": str(path.relative_to(repo)), "sha256": sha256(raw),
                        "sections": list(headings)})
    guidance = "\n\n".join(parts) + "\n"
    intro_blocks = re.findall(r"```text\n(.*?)```", (root / "README.md").read_text(), re.S)
    if len(intro_blocks) != 1:
        raise ValueError("Expected one documented guidance introduction")
    intro = intro_blocks[0].rstrip() + "\n\n"
    requests = {}
    for task, condition in ORDER:
        prompt = (root / "prompts" / f"{task}.md").read_text()
        content = prompt if condition == "baseline" else (
            intro + "<codeguard-guidance>\n" + guidance + "</codeguard-guidance>\n\n" + prompt
        )
        requests[(task, condition)] = [{"role": "user", "content": content}]
    provenance = {"rule_sources": sources, "guidance_sha256": sha256(guidance.encode()),
                  "guidance": guidance}
    return requests, provenance


def local_model(api: LocalApi, name: str) -> dict:
    matches = [m for m in api.call("/api/tags").get("models", []) if m.get("name") == name]
    if len(matches) != 1 or not re.fullmatch(r"[a-f0-9]{64}", matches[0].get("digest", "")):
        raise ValueError("Expected one installed model with a full digest")
    info = api.call("/api/show", {"model": name})
    if info.get("remote_host") or info.get("remote_model") or ":cloud" in name:
        raise ValueError("Cloud-backed models are outside this local experiment")
    return {"listing": matches[0], "show": info}


def response_metrics(response: dict, model: str, context: int, running: dict) -> dict:
    message = response.get("message")
    if response.get("done") is not True or response.get("model") != model:
        raise ValueError("Incomplete response or unexpected model identity")
    if not isinstance(message, dict) or not isinstance(message.get("content"), str):
        raise ValueError("Missing textual model output")
    loaded = [m for m in running.get("models", []) if m.get("name") == model]
    observed = loaded[0].get("context_length") if len(loaded) == 1 else None
    warnings = []
    if observed is None:
        warnings.append("Effective context is unknown")
    elif observed != context:
        warnings.append("Effective context differs from request")
    for field in ("prompt_eval_count", "eval_count"):
        count = response.get(field)
        if type(count) is not int or count < 0:
            raise ValueError(f"Missing or invalid {field}")
    if response["prompt_eval_count"] + response["eval_count"] >= context:
        warnings.append("Observed token total reaches context bound")
    reason = response.get("done_reason")
    if reason != "stop":
        warnings.append(f"Non-normal stop reason: {reason}")
    return {
        "requested_context": context, "observed_context": observed,
        "prompt_tokens": response["prompt_eval_count"], "output_tokens": response["eval_count"],
        "done_reason": reason, "warnings": warnings,
        **{field: response.get(field) for field in (
            "total_duration", "load_duration", "prompt_eval_duration", "eval_duration",
            "prompt_eval_cached_count"
        )},
    }


def capture(args) -> None:
    args.output.mkdir(parents=True, exist_ok=False)
    requests, provenance = prepare()
    guidance = provenance.pop("guidance")
    (args.output / "guidance.md").write_text(guidance)
    revision = subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=REPO, check=True, capture_output=True, text=True
    ).stdout.strip()
    manifest = {
        "status": "prepared", "repository_revision": revision,
        "started_at_utc": datetime.now(timezone.utc).isoformat(),
        "delivery": "explicit flattened subset", "sources": provenance,
        "host": {"os": platform.system(), "os_version": platform.mac_ver()[0],
                 "architecture": platform.machine(), "python": platform.python_version()},
        "options": {"temperature": 0, "seed": 73, "num_predict": 1024},
        "contexts": args.contexts, "runs": [],
        "authored_files": {
            str(path.relative_to(ROOT)): sha256(path.read_bytes())
            for path in sorted(ROOT.rglob("*"))
            if path.is_file() and "logs" not in path.relative_to(ROOT).parts
            and "__pycache__" not in path.parts
        },
    }
    for (task, condition), messages in requests.items():
        write_json(args.output / f"{task}-{condition}-template.json", {"messages": messages})
    write_json(args.output / "manifest.json", manifest)
    if args.prepare_only:
        return
    api = LocalApi(args.port, args.timeout)
    try:
        manifest["runtime"] = api.call("/api/version")
        model = local_model(api, args.model)
        digest = model["listing"]["digest"]
        manifest["model"] = model
        manifest["status"] = "running"
        for index, context in enumerate(args.contexts):
            previous_counts = [r["metrics"]["prompt_tokens"] for r in manifest["runs"]]
            if previous_counts and max(previous_counts) + 1024 >= context:
                manifest.setdefault("skipped_contexts", []).append({
                    "context": context, "reason": "Observed prompt plus output headroom does not fit"
                })
                continue
            order = ORDER if index % 2 == 0 else tuple(reversed(ORDER))
            for task, condition in order:
                if local_model(api, args.model)["listing"]["digest"] != digest:
                    raise ValueError("Installed model digest changed during experiment")
                name = f"{context}-{task}-{condition}"
                before = api.call("/api/ps")
                payload = {
                    "model": args.model, "messages": requests[(task, condition)],
                    "stream": False, "keep_alive": "5m",
                    "options": {**manifest["options"], "num_ctx": context},
                }
                raw_request = encode_request(payload)
                (args.output / f"{name}-request.json").write_bytes(raw_request)
                started = time.monotonic()
                response = api.call("/api/chat", payload)
                wall_seconds = time.monotonic() - started
                write_json(args.output / f"{name}-response.json", response)
                after = api.call("/api/ps")
                if any(m.get("digest") != digest for m in after.get("models", [])
                       if m.get("name") == args.model):
                    raise ValueError("Running model digest differs from installed model")
                metrics = response_metrics(response, args.model, context, after)
                (args.output / f"{name}-output.txt").write_text(response["message"]["content"])
                manifest["runs"].append({
                    "task": task, "condition": condition, "request_sha256": sha256(raw_request),
                    "response_sha256": sha256((args.output / f"{name}-response.json").read_bytes()),
                    "wall_seconds": wall_seconds, "running_before": before,
                    "running_after": after, "metrics": metrics,
                    "request_file": f"{name}-request.json", "response_file": f"{name}-response.json",
                })
                write_json(args.output / "manifest.json", manifest)
                print(f"{name}: {wall_seconds:.2f}s, {metrics['prompt_tokens']} input / "
                      f"{metrics['output_tokens']} output tokens, {metrics['done_reason']}", flush=True)
        manifest["runtime_after"] = api.call("/api/version")
        if manifest["runtime_after"] != manifest["runtime"]:
            raise ValueError("Runtime version changed during experiment")
        manifest["status"] = "captured-awaiting-manual-review"
    except Exception as error:
        manifest["status"] = "failed"
        manifest["error"] = f"{type(error).__name__}: {error}"
        raise
    finally:
        manifest["finished_at_utc"] = datetime.now(timezone.utc).isoformat()
        write_json(args.output / "manifest.json", manifest)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--model", default="qwen2.5-coder:7b")
    parser.add_argument("--port", type=int, default=11473)
    parser.add_argument("--timeout", type=int, default=180)
    parser.add_argument("--contexts", type=int, nargs="+", choices=(8192, 4096), default=[8192, 4096])
    parser.add_argument("--output", type=Path, required=True, help="New directory; never overwritten")
    parser.add_argument("--prepare-only", action="store_true", help="Capture inputs without model calls")
    args = parser.parse_args()
    if len(args.contexts) != len(set(args.contexts)):
        parser.error("Context lengths must be unique")
    capture(args)


if __name__ == "__main__":
    main()

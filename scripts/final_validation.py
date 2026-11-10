from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path
from urllib.error import URLError
from urllib.request import urlopen

ROOT = Path(__file__).resolve().parents[1]
BACKEND = ROOT / "backend"
FRONTEND = ROOT / "frontend"
DOCS = ROOT / "docs"
MODELS = ROOT / "models"

os.chdir(ROOT)

results: list[dict[str, object]] = []


def record(name: str, passed: bool, detail: str = "") -> None:
    results.append(
        {
            "name": name,
            "passed": bool(passed),
            "detail": detail,
        }
    )

    status = "PASS" if passed else "FAIL"
    suffix = f" — {detail}" if detail else ""
    print(f"[{status}] {name}{suffix}")


def run_command(
    name: str,
    command: list[str],
    cwd: Path = ROOT,
    timeout: int = 300,
) -> bool:
    try:
        completed = subprocess.run(
            command,
            cwd=cwd,
            text=True,
            capture_output=True,
            timeout=timeout,
        )

        if completed.returncode == 0:
            record(name, True)
            return True

        output = (
            completed.stderr.strip()
            or completed.stdout.strip()
        )

        record(
            name,
            False,
            output[-1200:],
        )
        return False

    except subprocess.TimeoutExpired:
        record(
            name,
            False,
            f"timeout after {timeout}s",
        )
        return False
    except Exception as exc:
        record(
            name,
            False,
            repr(exc),
        )
        return False


def wait_for_health(
    url: str,
    timeout: float = 20.0,
) -> bool:
    deadline = time.time() + timeout

    while time.time() < deadline:
        try:
            with urlopen(url, timeout=2) as response:
                if response.status == 200:
                    return True
        except Exception:
            time.sleep(0.5)

    return False


def read_json(path: Path) -> dict:
    return json.loads(
        path.read_text(encoding="utf-8")
    )


print()
print("=" * 72)
print("NETRA FINAL VALIDATION")
print("=" * 72)
print(f"Repository: {ROOT}")
print()


# ---------------------------------------------------------------------
# 1. Required project artifacts
# ---------------------------------------------------------------------

required_files = [
    MODELS / "netra_cicids_model.joblib",
    MODELS / "netra_label_encoder.joblib",
    MODELS / "netra_dns_model.joblib",
    DOCS / "SIH26145_RESULTS.md",
    DOCS / "SIH26145_VALIDATION.md",
    DOCS / "SIH26145_FINAL_VALIDATION.json",
]

missing = [
    str(path.relative_to(ROOT))
    for path in required_files
    if not path.exists()
]

record(
    "Required model/document artifacts",
    not missing,
    "missing: " + ", ".join(missing)
    if missing
    else "",
)


# ---------------------------------------------------------------------
# 2. Backend compilation
# ---------------------------------------------------------------------

run_command(
    "Python backend compilation",
    [
        sys.executable,
        "-m",
        "compileall",
        "-q",
        str(BACKEND),
    ],
)


# ---------------------------------------------------------------------
# 3. ML model loading + inference smoke test
# ---------------------------------------------------------------------

try:
    sys.path.insert(0, str(BACKEND))

    from app import main as backend_main  # noqa: F401
    from app.services import ml_service

    test_flow = {
        feature: 0.0
        for feature in ml_service.FEATURE_COLUMNS
    }

    prediction = ml_service.predict_threat(
        test_flow
    )

    valid_prediction = (
        isinstance(prediction, dict)
        and isinstance(
            prediction.get("threat_class"),
            str,
        )
        and 0.0
        <= float(prediction.get("confidence", -1))
        <= 100.0
    )

    record(
        "Random Forest model loading + inference",
        valid_prediction,
        json.dumps(
            prediction,
            separators=(",", ":"),
        ),
    )

except Exception as exc:
    record(
        "Random Forest model loading + inference",
        False,
        repr(exc),
    )


# ---------------------------------------------------------------------
# 4. Existing SIH validation
# ---------------------------------------------------------------------

run_command(
    "Existing SIH validation",
    [
        sys.executable,
        str(ROOT / "scripts" / "run_sih_validation.py"),
    ],
    timeout=600,
)


# ---------------------------------------------------------------------
# 5. Existing training/behavior tests
# ---------------------------------------------------------------------

test_files = [
    "training/test_netra_model.py",
    "training/test_real_flows.py",
    "training/test_stream.py",
    "training/test_dns_behavior_synthetic.py",
    "training/test_dns_model.py",
    "training/test_dns_model_v2.py",
    "training/test_tls_detector.py",
    "training/test_tqh_c2_beacon_engine.py",
    "training/test_tqh_c2_netra_integration.py",
    "training/test_unified_dns.py",
]

existing_test_files = [
    str(ROOT / item)
    for item in test_files
    if (ROOT / item).exists()
]

if existing_test_files:
    run_command(
        "NETRA pytest suite",
        [
            sys.executable,
            "-m",
            "pytest",
            "-q",
            *existing_test_files,
        ],
        timeout=900,
    )
else:
    record(
        "NETRA pytest suite",
        False,
        "no expected test files found",
    )


# ---------------------------------------------------------------------
# 6. Saved validation artifact integrity
# ---------------------------------------------------------------------

validation_path = (
    DOCS / "SIH26145_FINAL_VALIDATION.json"
)

try:
    validation = read_json(validation_path)

    behavioral = validation.get(
        "behavioral_validation",
        [],
    )

    passed_cases = sum(
        bool(item.get("passed"))
        for item in behavioral
        if isinstance(item, dict)
    )

    total_cases = len(behavioral)

    record(
        "Saved SIH validation artifact integrity",
        total_cases > 0 and passed_cases == total_cases,
        f"{passed_cases}/{total_cases} behavioral cases passed",
    )

except Exception as exc:
    record(
        "Saved SIH validation artifact integrity",
        False,
        repr(exc),
    )


# ---------------------------------------------------------------------
# 7. Passive / read-only source audit
# ---------------------------------------------------------------------

source_roots = [
    BACKEND,
    ROOT / "scripts",
    ROOT / "training",
]

source_files: list[Path] = []

for root in source_roots:
    if root.exists():
        source_files.extend(
            path
            for path in root.rglob("*.py")
            if "__pycache__" not in path.parts
            and ".venv" not in path.parts
        )

active_network_patterns = [
    r"\bsocket\.socket\s*\(",
    r"\bscapy\b",
    r"\bsendp\s*\(",
    r"\bsendto\s*\(",
    r"\bnmap\b",
    r"\bhping\b",
]

violations: list[str] = []

for path in source_files:
    try:
        text = path.read_text(
            encoding="utf-8",
            errors="ignore",
        )
    except Exception:
        continue

    for pattern in active_network_patterns:
        if re.search(
            pattern,
            text,
            flags=re.IGNORECASE,
        ):
            # Skip obvious textual references in comments/docstrings
            # only when the whole matching line is clearly explanatory.
            for line_number, line in enumerate(
                text.splitlines(),
                start=1,
            ):
                if re.search(
                    pattern,
                    line,
                    flags=re.IGNORECASE,
                ):
                    stripped = line.strip()
                    if (
                        stripped.startswith("#")
                        or stripped.startswith('"""')
                        or stripped.startswith("'''")
                    ):
                        continue

                    violations.append(
                        f"{path.relative_to(ROOT)}:"
                        f"{line_number}: {stripped}"
                    )

if violations:
    record(
        "Passive/read-only active-probing audit",
        False,
        "\n".join(violations[:12]),
    )
else:
    record(
        "Passive/read-only active-probing audit",
        True,
        "no active probing APIs detected",
    )


# ---------------------------------------------------------------------
# 8. Explicit no-decryption assertions in TLS/QUIC implementation
# ---------------------------------------------------------------------

metadata_files = [
    BACKEND
    / "app/services/tls/tls_c2_beacon.py",
    BACKEND
    / "app/services/tls/tls_detector.py",
    BACKEND
    / "app/services/quic/quic_detector.py",
]

missing_decryption_assertion = []

for path in metadata_files:
    if not path.exists():
        continue

    text = path.read_text(
        encoding="utf-8",
        errors="ignore",
    )

    if "payload_decryption" not in text:
        missing_decryption_assertion.append(
            str(path.relative_to(ROOT))
        )

record(
    "TLS/QUIC metadata-only implementation audit",
    not missing_decryption_assertion,
    "missing payload_decryption assertion in: "
    + ", ".join(missing_decryption_assertion)
    if missing_decryption_assertion
    else "payload_decryption=False evidence present",
)


# ---------------------------------------------------------------------
# 9. API health smoke test
# ---------------------------------------------------------------------

server = None

try:
    server = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "uvicorn",
            "app.main:app",
            "--host",
            "127.0.0.1",
            "--port",
            "8000",
        ],
        cwd=BACKEND,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    healthy = wait_for_health(
        "http://127.0.0.1:8000/health"
    )

    record(
        "Backend health endpoint",
        healthy,
        "http://127.0.0.1:8000/health",
    )

    if healthy:
        openapi_ok = False

        try:
            with urlopen(
                "http://127.0.0.1:8000/openapi.json",
                timeout=5,
            ) as response:
                payload = json.loads(
                    response.read().decode("utf-8")
                )

            paths = payload.get("paths", {})

            expected_paths = {
                "/threat/analyze",
                "/stream/replay",
                "/stream/dns-replay",
                "/stream/tls-replay",
                "/stream/quic-replay",
                "/analytics/summary",
            }

            openapi_ok = expected_paths.issubset(
                paths.keys()
            )

            missing_paths = sorted(
                expected_paths - set(paths.keys())
            )

            record(
                "Required OpenAPI routes",
                openapi_ok,
                "missing: " + ", ".join(missing_paths)
                if missing_paths
                else "",
            )

        except Exception as exc:
            record(
                "Required OpenAPI routes",
                False,
                repr(exc),
            )

finally:
    if server is not None:
        server.terminate()

        try:
            server.wait(timeout=5)
        except subprocess.TimeoutExpired:
            server.kill()


# ---------------------------------------------------------------------
# 10. Frontend production build
# ---------------------------------------------------------------------

run_command(
    "Frontend production build",
    [
        "npm",
        "run",
        "build",
    ],
    cwd=FRONTEND,
    timeout=600,
)


# ---------------------------------------------------------------------
# Final result
# ---------------------------------------------------------------------

passed = sum(
    bool(item["passed"])
    for item in results
)

total = len(results)

summary = {
    "project": "NETRA",
    "validation": "FINAL",
    "generated_utc": time.strftime(
        "%Y-%m-%dT%H:%M:%SZ",
        time.gmtime(),
    ),
    "passed": passed,
    "total": total,
    "status": (
        "PASS"
        if passed == total
        else "FAIL"
    ),
    "checks": results,
}

DOCS.mkdir(exist_ok=True)

json_path = DOCS / "FINAL_VALIDATION.json"
md_path = DOCS / "FINAL_VALIDATION.md"

json_path.write_text(
    json.dumps(
        summary,
        indent=2,
    ),
    encoding="utf-8",
)

lines = [
    "# NETRA Final Validation",
    "",
    f"- Generated UTC: {summary['generated_utc']}",
    f"- Passed: {passed}/{total}",
    f"- Status: **{summary['status']}**",
    "",
    "## Checks",
    "",
]

for item in results:
    status = (
        "PASS"
        if item["passed"]
        else "FAIL"
    )

    detail = (
        f" — {item['detail']}"
        if item["detail"]
        else ""
    )

    lines.append(
        f"- **{status}** {item['name']}{detail}"
    )

md_path.write_text(
    "\n".join(lines) + "\n",
    encoding="utf-8",
)

print()
print("=" * 72)
print(
    f"FINAL RESULT: "
    f"{summary['status']} "
    f"({passed}/{total} checks passed)"
)
print("=" * 72)
print()
print(f"JSON: {json_path}")
print(f"MARKDOWN: {md_path}")

sys.exit(
    0 if summary["status"] == "PASS" else 1
)

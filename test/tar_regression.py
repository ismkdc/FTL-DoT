#!/usr/bin/env python3

import os
import subprocess
import sys
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
COMPILE_LOG = Path(os.environ.get("TMPDIR", "/tmp")) / "tar_regression_cc.log"


def compile_command(binary: Path, sanitize: bool) -> list[str]:
    command = [
        os.environ.get("CC", "cc"),
        "-std=c11",
        "-Wall",
        "-Wextra",
        "-I",
        "src",
        "test/tar_regression.c",
        "src/zip/tar.c",
        "src/webserver/cJSON/cJSON.c",
    ]
    if sanitize:
        command.extend([
            "-fsanitize=address,undefined",
            "-fno-omit-frame-pointer",
        ])
    command.extend(["-o", str(binary)])
    return command


def run_env() -> dict[str, str]:
    env = os.environ.copy()
    env.setdefault("ASAN_OPTIONS", "detect_leaks=0:halt_on_error=1")
    env.setdefault("UBSAN_OPTIONS", "halt_on_error=1")
    return env


def compile_harness(binary: Path) -> None:
    if os.environ.get("TAR_REGRESSION_NO_SANITIZER") != "1":
        with COMPILE_LOG.open("wb") as log:
            result = subprocess.run(
                compile_command(binary, sanitize=True),
                cwd=ROOT,
                stdout=log,
                stderr=subprocess.STDOUT,
                check=False,
            )
        if result.returncode == 0:
            return

    subprocess.run(compile_command(binary, sanitize=False), cwd=ROOT, check=True)


def run_binary(binary: Path, args: list[str], *, capture: bool = False) -> subprocess.CompletedProcess:
    return subprocess.run(
        [str(binary), *args],
        cwd=ROOT,
        env=run_env(),
        text=True,
        stdout=subprocess.PIPE if capture else None,
        stderr=subprocess.PIPE if capture else None,
        check=False,
    )


def list_cases(binary: Path) -> list[str]:
    result = run_binary(binary, ["--list"], capture=True)
    if result.returncode != 0:
        sys.stdout.write(result.stdout or "")
        sys.stderr.write(result.stderr or "")
        raise SystemExit(result.returncode)
    return [line for line in result.stdout.splitlines() if line]


def run_cases(binary: Path, cases: list[str]) -> int:
    if cases == ["--list"]:
        for case_name in list_cases(binary):
            print(case_name)
        return 0

    if not cases:
        cases = list_cases(binary)

    status = 0
    for case_name in cases:
        print(f"running tar regression: {case_name}", flush=True)
        result = run_binary(binary, [case_name])
        if result.returncode != 0:
            status = 1
    return status


def main() -> int:
    requested_binary = os.environ.get("TAR_REGRESSION_BIN")
    if requested_binary:
        binary = Path(requested_binary)
        compile_harness(binary)
        return run_cases(binary, sys.argv[1:])

    with tempfile.TemporaryDirectory(prefix="ftl-tar-regression.") as tmpdir:
        binary = Path(tmpdir) / "tar_regression"
        compile_harness(binary)
        return run_cases(binary, sys.argv[1:])


if __name__ == "__main__":
    raise SystemExit(main())

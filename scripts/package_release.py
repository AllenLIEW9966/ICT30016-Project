"""Build native backend, backend ZIP and VSIX on the target operating system."""
import argparse
import http.client
import json
import os
from pathlib import Path
import platform
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import zipfile

import psutil


TARGETS = {
    "win32-x64": ("Windows", "x64", "codeshield-backend.exe"),
    "darwin-x64": ("Darwin", "x64", "codeshield-backend-macos"),
    "darwin-arm64": ("Darwin", "arm64", "codeshield-backend-macos"),
    "linux-x64": ("Linux", "x64", "codeshield-backend-linux"),
}
ROOT = Path(__file__).resolve().parents[1]


def run(command, cwd):
    subprocess.run(command, cwd=cwd, check=True)


def smoke_test(binary, version):
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        port = listener.getsockname()[1]
    env = dict(os.environ)
    node = shutil.which("node")
    if node:
        env["CODESHIELD_NODE_BIN"] = node
    with tempfile.TemporaryFile() as log:
        process = subprocess.Popen(
            [str(binary), "--host", "127.0.0.1", "--port", str(port)],
            stdin=subprocess.DEVNULL, stdout=log, stderr=log, env=env,
            creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0,
        )
        try:
            deadline = time.monotonic() + 60
            while process.poll() is None and time.monotonic() < deadline:
                connection = http.client.HTTPConnection("127.0.0.1", port, timeout=2)
                try:
                    connection.request("GET", "/health")
                    response = connection.getresponse()
                    if response.status == 200:
                        body = json.loads(response.read())
                        if body.get("version") != version:
                            raise RuntimeError(f"Unexpected backend version: {body}")
                        print(f"PASS packaged backend /health ({version})", flush=True)
                        return
                except (OSError, http.client.HTTPException):
                    pass
                finally:
                    connection.close()
                time.sleep(0.5)
            log.seek(0)
            raise RuntimeError("Packaged backend failed to start:\n" + log.read().decode(errors="replace"))
        finally:
            # PyInstaller one-file launchers create a child process on Windows.
            # Stop that process too, so the extracted executable is released.
            try:
                children = psutil.Process(process.pid).children(recursive=True)
            except psutil.NoSuchProcess:
                children = []
            for child in children:
                try:
                    child.terminate()
                except psutil.NoSuchProcess:
                    pass
            _, remaining = psutil.wait_procs(children, timeout=5)
            for child in remaining:
                try:
                    child.kill()
                except psutil.NoSuchProcess:
                    pass
            psutil.wait_procs(remaining, timeout=5)
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("target", choices=TARGETS)
    target = parser.parse_args().target
    system, arch, bundled_name = TARGETS[target]
    host_arch = {"amd64": "x64", "x86_64": "x64", "aarch64": "arm64"}.get(
        platform.machine().lower(), platform.machine().lower())
    if (platform.system(), host_arch) != (system, arch):
        parser.error(f"{target} requires native {system} {arch}, got {platform.system()} {host_arch}")

    extension = ROOT / "extension"
    version = json.loads((extension / "package.json").read_text(encoding="utf-8"))["version"]
    output = ROOT / "dist" / target
    output.mkdir(parents=True, exist_ok=True)
    run([sys.executable, "-m", "PyInstaller", "codeshield-backend.spec", "--noconfirm", "--clean",
         "--distpath", str(output / "backend"), "--workpath", str(ROOT / "build" / target)], ROOT / "backend")
    executable = "codeshield-backend.exe" if system == "Windows" else "codeshield-backend"
    binary = output / "backend" / executable
    if not binary.is_file():
        raise RuntimeError(f"Missing PyInstaller one-file output: {binary}")
    if os.name != "nt":
        binary.chmod(0o755)

    # The existing spec embeds Python, collected libraries and JS assets in one file.
    archive_path = output / f"codeshield-backend-{target}.zip"
    with zipfile.ZipFile(archive_path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.write(binary, executable)
    with tempfile.TemporaryDirectory(prefix="codeshield-smoke-") as directory:
        with zipfile.ZipFile(archive_path) as archive:
            archive.extractall(directory)
        extracted = Path(directory) / executable
        if os.name != "nt":
            extracted.chmod(0o755)
        smoke_test(extracted, version)

    server = extension / "server"
    server.mkdir(exist_ok=True)
    shutil.copy2(binary, server / bundled_name)
    # Ignore other platforms' binaries without deleting local build outputs.
    ignore = (extension / ".vscodeignore").read_text(encoding="utf-8")
    other_names = set(item[2] for item in TARGETS.values()) | {"codeshield-backend"}
    ignore += "\n" + "\n".join(f"server/{name}" for name in sorted(other_names - {bundled_name})) + "\n"
    vsix = output / f"secure-coding-assistant-{target}-{version}.vsix"
    with tempfile.TemporaryDirectory(prefix="codeshield-vsce-") as directory:
        ignore_path = Path(directory) / "package.ignore"
        ignore_path.write_text(ignore, encoding="utf-8")
        npx = shutil.which("npx.cmd" if os.name == "nt" else "npx")
        if not npx:
            raise RuntimeError("npx is missing. Install Node.js and run npm ci in extension first.")
        run([npx, "--no-install", "@vscode/vsce", "package", "--no-dependencies", "--target", target,
             "--ignoreFile", str(ignore_path), "--out", str(vsix)], extension)
    with zipfile.ZipFile(vsix) as archive:
        manifest = json.loads(archive.read("extension/package.json"))
        assert manifest["version"] == version, "VSIX version mismatch"
        assert f"extension/server/{bundled_name}" in archive.namelist(), "VSIX backend missing"
        for name in other_names - {bundled_name}:
            assert f"extension/server/{name}" not in archive.namelist(), "Foreign backend in VSIX"
    print(f"PASS VSIX contents for {target}\n{vsix}\n{archive_path}", flush=True)


if __name__ == "__main__":
    main()

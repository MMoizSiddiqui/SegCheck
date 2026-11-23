"""Build SegCheck.exe, the double-click launcher (scripts/launcher/SegCheck.cs), with the SegCheck icon.

    python scripts/build_launcher.py [--out <folder>]

Uses the C# compiler that ships with every Windows 10/11 (.NET Framework 4), so nothing has to be
installed. The result goes to the project folder (or --out) and must stay next to start_segcheck.py.
"""
from __future__ import annotations

import argparse
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "scripts" / "launcher" / "SegCheck.cs"
ICON = ROOT / "scripts" / "launcher" / "segcheck.ico"


def compiler() -> Path:
    windows = Path(os.environ.get("WINDIR", r"C:\Windows"))
    for folder in ("Framework64", "Framework"):
        candidate = windows / "Microsoft.NET" / folder / "v4.0.30319" / "csc.exe"
        if candidate.exists():
            return candidate
    raise SystemExit("The .NET Framework 4 C# compiler (csc.exe) was not found. It ships with Windows 10/11; "
                     "turn on '.NET Framework 4.8' in 'Turn Windows features on or off'.")


def build(out_dir: Path = ROOT) -> Path:
    if sys.platform != "win32":
        raise SystemExit("SegCheck.exe is built on Windows.")
    out_dir.mkdir(parents=True, exist_ok=True)
    target = out_dir / "SegCheck.exe"
    command = [str(compiler()), "/nologo", "/optimize+", "/target:winexe", f"/win32icon:{ICON}", f"/out:{target}",
               "/r:System.Windows.Forms.dll", str(SOURCE)]
    result = subprocess.run(command, capture_output=True, text=True)
    if result.returncode != 0:
        raise SystemExit(f"Compiling SegCheck.exe failed:\n{result.stdout}{result.stderr}")
    if out_dir == ROOT:
        STAMP.write_text(source_digest() + "\n", encoding="ascii")
    return target


STAMP = ROOT / "scripts" / "launcher" / "SegCheck.exe.built-from"


def source_digest() -> str:
    """SHA-256 of the launcher source and icon (line endings normalised), recorded at every build.

    SegCheck.exe is committed so a fresh clone works with a double-click; tests compare this digest to
    catch an exe that was not rebuilt after SegCheck.cs changed."""
    import hashlib
    digest = hashlib.sha256()
    digest.update(SOURCE.read_bytes().replace(b"\r\n", b"\n"))
    digest.update(ICON.read_bytes())
    return digest.hexdigest()


def main(argv=None):
    parser = argparse.ArgumentParser(description="Build SegCheck.exe")
    parser.add_argument("--out", default=str(ROOT))
    print(build(Path(parser.parse_args(argv).out)))
    return 0


if __name__ == "__main__":
    sys.exit(main())

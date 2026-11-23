"""SegCheck.exe ships in the repository so a fresh clone starts with a double-click."""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import build_launcher  # noqa: E402


def test_segcheck_exe_is_in_the_project_folder():
    exe = ROOT / "SegCheck.exe"
    assert exe.exists() and exe.read_bytes()[:2] == b"MZ", "Build it: python scripts/build_launcher.py"


def test_segcheck_exe_was_rebuilt_after_the_last_launcher_change():
    stamp = build_launcher.STAMP.read_text(encoding="ascii").strip()
    assert stamp == build_launcher.source_digest(), (
        "scripts/launcher/SegCheck.cs or the icon changed but SegCheck.exe was not rebuilt: python scripts/build_launcher.py")


def test_launcher_is_not_ignored_by_git():
    assert "SegCheck.exe" not in (ROOT / ".gitignore").read_text(encoding="utf-8")

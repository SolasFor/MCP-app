"""Regression tests for isolated OAuth shared notes and strict filenames."""
from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path

from backend.shared_notes import SharedNotes, check_note_name, MAX_NOTE_BYTES


class SharedNotesTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.notes = SharedNotes(Path(self.temp.name) / "notes")

    def tearDown(self):
        self.temp.cleanup()

    def test_create_read_and_list_utf8_note(self):
        self.notes.write("hello.md", "Hello Привет 你好")
        self.notes.write("todo.txt", "1. Pay bills\n2. Read")
        self.assertEqual(self.notes.read("hello.md"), "Hello Привет 你好")
        self.assertEqual(self.notes.list_names(), ["hello.md", "todo.txt"])

    def test_write_replaces_note_atomically(self):
        self.notes.write("todo.md", "old")
        self.notes.write("todo.md", "new")
        self.assertEqual(self.notes.read("todo.md"), "new")
        self.assertEqual(self.notes.list_names(), ["todo.md"])

    def test_reject_paths_and_hidden_and_reserved_names(self):
        for name in (
            "../settings.md", "a/b.md", "a\\b.md", "/etc/passwd",
            "C:\\secret.txt", ".env", ".env.md", "..md", "token.json",
            "notes.py", "CON.md", "LPT1.txt", "a..b.md",
            "тест.md", "", "x" * 80 + ".txt",
        ):
            with self.subTest(name=name), self.assertRaises(ValueError):
                check_note_name(name)

    def test_reject_symlink_into_sensitive_file(self):
        external = Path(self.temp.name) / "secret.txt"
        external.write_text("private", encoding="utf-8")
        link = self.notes.directory / "secret.txt"
        try:
            link.symlink_to(external)
        except (OSError, NotImplementedError):
            self.skipTest("Symlinks unavailable on this system")
        with self.assertRaises(ValueError):
            self.notes.read("secret.txt")
        with self.assertRaises(ValueError):
            self.notes.write("secret.txt", "overwrite")
        self.assertNotIn("secret.txt", self.notes.list_names())
        self.assertEqual(external.read_text(encoding="utf-8"), "private")

    def test_refuse_symlink_root(self):
        outside = Path(self.temp.name) / "real"
        outside.mkdir()
        link = Path(self.temp.name) / "alias"
        try:
            link.symlink_to(outside, target_is_directory=True)
        except (OSError, NotImplementedError):
            self.skipTest("Symlinks unavailable on this system")
        with self.assertRaises(ValueError):
            SharedNotes(link)

    def test_size_limits(self):
        self.notes.write("limit.md", "a" * MAX_NOTE_BYTES)
        with self.assertRaises(ValueError):
            self.notes.write("too-large.md", "a" * (MAX_NOTE_BYTES + 1))
        (self.notes.directory / "oversize.md").write_bytes(b"x" * (MAX_NOTE_BYTES + 2))
        with self.assertRaises(ValueError):
            self.notes.read("oversize.md")

    def test_invalid_utf8_fails_closed(self):
        (self.notes.directory / "broken.txt").write_bytes(b"\xff")
        with self.assertRaises(UnicodeDecodeError):
            self.notes.read("broken.txt")


if __name__ == "__main__":
    unittest.main()

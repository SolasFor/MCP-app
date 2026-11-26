"""Unit tests for BoundedOutputBuffer, OutputSpoolManager, pagination, and decoding."""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from app.core.redaction import SecretRedactor
from backend.output_stream import (
    BoundedOutputBuffer,
    OutputSpoolManager,
    decode_process_bytes,
)


class OutputStreamTests(unittest.TestCase):
    def test_memory_ring_and_spool_quotas(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            spool = OutputSpoolManager(
                Path(tmp) / "spool",
                max_total_bytes=4096,
                max_file_bytes=2048,
                max_files=2,
            )
            writer1 = spool.create_spool("run-1")
            buf = BoundedOutputBuffer(max_memory_bytes=1024, spool=writer1, stream_name="stdout")
            for i in range(100):
                buf.append(f"line-{i:03d}-".encode("ascii") + b"X" * 50 + b"\n")

            self.assertLessEqual(buf.memory_bytes_used, 1024)
            self.assertGreater(buf.dropped_memory_bytes, 0)
            self.assertLessEqual(writer1.written_bytes["stdout"], 2048)
            self.assertGreater(writer1.dropped_bytes["stdout"], 0)

            page1 = spool.read_page("run-1", "stdout", offset=0, limit=256)
            self.assertEqual(page1.returned_bytes, 256)
            self.assertTrue(page1.has_more)
            self.assertEqual(page1.next_offset, 256)
            self.assertTrue(page1.truncated_by_quota)

            page2 = spool.read_page("run-1", "stdout", offset=page1.next_offset, limit=256)
            self.assertEqual(page2.offset, 256)
            self.assertNotEqual(page1.text, page2.text)

            # Adding two more runs triggers max_files rotation
            w2 = spool.create_spool("run-2")
            w2.write("stdout", b"second-run")
            w3 = spool.create_spool("run-3")
            w3.write("stdout", b"third-run")
            self.assertFalse((Path(tmp) / "spool" / "run-1").exists())

    def test_redaction_and_encoding_fallback(self) -> None:
        redactor = SecretRedactor(["my-super-secret-value"])
        buf = BoundedOutputBuffer(max_memory_bytes=2048)
        buf.append(b"token=my-super-secret-value Bearer abcdefgh123456\n")
        rendered = buf.render(redactor=redactor)
        self.assertNotIn("my-super-secret-value", rendered)
        self.assertNotIn("abcdefgh123456", rendered)

        utf8_text = decode_process_bytes("Привет мир".encode("utf-8"))
        self.assertEqual(utf8_text, "Привет мир")
        cp866_text = decode_process_bytes("Привет".encode("cp866"), encoding_hint="cp866")
        self.assertEqual(cp866_text, "Привет")
        broken_text = decode_process_bytes(b"\xff\xfe\xfd")
        self.assertTrue(broken_text)


if __name__ == "__main__":
    unittest.main()

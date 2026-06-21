"""
Unit tests for MyCryptoPony command wrappers.
Run with:
pip install pytest
pytest

No external tools (age, minisign, etc.) are required — all subprocess
and pexpect calls are mocked.
"""

import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

# Ensure the project root is on sys.path so we can import mycryptopony
sys.path.insert(0, str(Path(__file__).parent.parent))

from mycryptopony import (
    _extract_hex_digest,
    _get_algorithm_from_extension,
    age_decrypt_file,
    age_encrypt_file,
    croc_receive,
    croc_send,
    mat2_clean_file,
    minisign_sign_file,
    minisign_verify_file,
    rhash_generate_hash,
    rhash_verify_hash,
    run_cmd,
)


# ---------------------------------------------------------------------------
# Helper function tests (pure logic, no mocks needed)
# ---------------------------------------------------------------------------
class TestExtractHexDigest:
    def test_extracts_sha512_from_rhash_output(self) -> None:
        text = "SHA512  file.txt\n" + "a" * 128 + "  file.txt\n"
        assert _extract_hex_digest(text) == "a" * 128

    def test_extracts_blake3_from_hash_file(self) -> None:
        text = "b" * 64 + "  document.pdf\n"
        assert _extract_hex_digest(text) == "b" * 64

    def test_skips_comments(self) -> None:
        text = "; comment\n# another\n" + "c" * 64 + "  file\n"
        assert _extract_hex_digest(text) == "c" * 64

    def test_returns_none_for_no_hex(self) -> None:
        assert _extract_hex_digest("no hex here\njust text\n") is None

    def test_returns_none_for_short_hex(self) -> None:
        assert _extract_hex_digest("abcdef1234567890  file.txt\n") is None


class TestGetAlgorithmFromExtension:
    def test_sha512(self) -> None:
        assert _get_algorithm_from_extension(Path("file.sha512")) == "sha512"

    def test_blake3(self) -> None:
        assert _get_algorithm_from_extension(Path("file.blake3")) == "blake3"

    def test_unsupported(self) -> None:
        assert _get_algorithm_from_extension(Path("file.md5")) is None

    def test_case_insensitive(self) -> None:
        assert _get_algorithm_from_extension(Path("file.SHA512")) == "sha512"


# ---------------------------------------------------------------------------
# run_cmd tests
# ---------------------------------------------------------------------------
class TestRunCmd:
    @patch("mycryptopony.subprocess.run")
    def test_success(self, mock_run: MagicMock) -> None:
        mock_run.return_value = MagicMock(returncode=0, stdout=b"hello\n", stderr=b"")
        code, out, err = run_cmd(["echo", "hello"])
        assert code == 0
        assert out == "hello\n"
        assert err == ""

    @patch("mycryptopony.subprocess.run")
    def test_nonzero_exit(self, mock_run: MagicMock) -> None:
        mock_run.return_value = MagicMock(returncode=1, stdout=b"", stderr=b"error msg\n")
        code, out, err = run_cmd(["false"])
        assert code == 1
        assert "error msg" in err

    @patch("mycryptopony.subprocess.run", side_effect=FileNotFoundError)
    def test_command_not_found(self, mock_run: MagicMock) -> None:
        code, out, err = run_cmd(["nonexistent_cmd"])
        assert code == 1
        assert "Command not found" in err


# ---------------------------------------------------------------------------
# age_encrypt_file tests
# ---------------------------------------------------------------------------
class TestAgeEncryptFile:
    @patch("mycryptopony.pexpect.spawn")
    def test_passphrase_success(self, mock_spawn: MagicMock) -> None:
        mock_child = MagicMock()
        mock_child.exitstatus = 0
        mock_child.before = b""
        mock_spawn.return_value = mock_child

        ok, msg = age_encrypt_file(Path("/tmp/test.txt"), passphrase="secret123")
        assert ok is True
        assert "Encrypted" in msg
        assert mock_child.sendline.call_count == 2  # Enter + Confirm

    @patch("mycryptopony.run_cmd")
    def test_recipient_success(self, mock_run_cmd: MagicMock) -> None:
        mock_run_cmd.return_value = (0, "", "")
        ok, msg = age_encrypt_file(Path("/tmp/test.txt"), recipient="age1abc...")
        assert ok is True
        assert "Encrypted" in msg

    def test_no_passphrase_no_recipient(self) -> None:
        ok, msg = age_encrypt_file(Path("/tmp/test.txt"))
        assert ok is False
        assert "Neither passphrase nor recipient" in msg

    @patch("mycryptopony.pexpect.spawn", side_effect=FileNotFoundError)
    def test_age_not_found(self, mock_spawn: MagicMock) -> None:
        ok, msg = age_encrypt_file(Path("/tmp/test.txt"), passphrase="secret")
        assert ok is False
        assert "not found" in msg


# ---------------------------------------------------------------------------
# age_decrypt_file tests
# ---------------------------------------------------------------------------
class TestAgeDecryptFile:
    @patch("mycryptopony.pexpect.spawn")
    def test_passphrase_success(self, mock_spawn: MagicMock) -> None:
        mock_child = MagicMock()
        mock_child.exitstatus = 0
        mock_child.before = b""
        mock_spawn.return_value = mock_child

        ok, msg = age_decrypt_file(Path("/tmp/test.txt.age"), passphrase="secret123")
        assert ok is True
        assert "Decrypted" in msg

    @patch("mycryptopony.run_cmd")
    def test_identity_success(self, mock_run_cmd: MagicMock) -> None:
        mock_run_cmd.return_value = (0, "", "")
        ok, msg = age_decrypt_file(Path("/tmp/test.txt.age"), identity=Path("/tmp/key.txt"))
        assert ok is True
        assert "Decrypted" in msg

    def test_no_passphrase_no_identity(self) -> None:
        ok, msg = age_decrypt_file(Path("/tmp/test.txt.age"))
        assert ok is False
        assert "Passphrase or identity file required" in msg


# ---------------------------------------------------------------------------
# minisign_sign_file tests
# ---------------------------------------------------------------------------
class TestMinisignSignFile:
    @patch("mycryptopony.pexpect.spawn")
    def test_success(self, mock_spawn: MagicMock) -> None:
        mock_child = MagicMock()
        mock_child.exitstatus = 0
        mock_child.before = b""
        mock_spawn.return_value = mock_child

        ok, msg = minisign_sign_file(
            Path("/tmp/test.txt"), sig_path=None, secret_key_path=None, passphrase="mypass"
        )
        assert ok is True
        assert "Signature created" in msg
        mock_child.sendline.assert_called_once_with("mypass")

    @patch("mycryptopony.pexpect.spawn", side_effect=FileNotFoundError)
    def test_minisign_not_found(self, mock_spawn: MagicMock) -> None:
        ok, msg = minisign_sign_file(Path("/tmp/test.txt"), None, None, "pass")
        assert ok is False
        assert "not found" in msg


# ---------------------------------------------------------------------------
# minisign_verify_file tests
# ---------------------------------------------------------------------------
class TestMinisignVerifyFile:
    @patch("mycryptopony.run_cmd")
    def test_valid_signature(self, mock_run_cmd: MagicMock) -> None:
        mock_run_cmd.return_value = (0, "", "")
        ok, msg = minisign_verify_file(
            Path("/tmp/test.txt"), Path("/tmp/test.txt.minisig"), pub_key_path=None
        )
        assert ok is True
        assert "valid" in msg

    @patch("mycryptopony.run_cmd")
    def test_invalid_signature(self, mock_run_cmd: MagicMock) -> None:
        mock_run_cmd.return_value = (1, "", "signature verification failed")
        ok, msg = minisign_verify_file(
            Path("/tmp/test.txt"), Path("/tmp/test.txt.minisig"), pub_key_path="/tmp/pub.key"
        )
        assert ok is False


# ---------------------------------------------------------------------------
# mat2_clean_file tests
# ---------------------------------------------------------------------------
class TestMat2CleanFile:
    @patch("mycryptopony.run_cmd")
    def test_success(self, mock_run_cmd: MagicMock) -> None:
        mock_run_cmd.return_value = (0, "", "")
        ok, msg = mat2_clean_file(Path("/tmp/photo.jpg"))
        assert ok is True
        assert "photo.jpg.cleaned" in msg

    @patch("mycryptopony.run_cmd")
    def test_failure(self, mock_run_cmd: MagicMock) -> None:
        mock_run_cmd.return_value = (1, "", "unsupported format")
        ok, msg = mat2_clean_file(Path("/tmp/weird.xyz"))
        assert ok is False


# ---------------------------------------------------------------------------
# rhash_generate_hash tests
# ---------------------------------------------------------------------------
class TestRhashGenerateHash:
    @patch("mycryptopony.run_cmd")
    def test_success(self, mock_run_cmd: MagicMock) -> None:
        mock_run_cmd.return_value = (0, "", "")
        ok, msg = rhash_generate_hash(Path("/tmp/doc.pdf"), "sha512")
        assert ok is True
        assert "doc.pdf.sha512" in msg

        # Verify the command was built correctly
        cmd = mock_run_cmd.call_args[0][0]
        assert "--sha512" in cmd
        assert "-o" in cmd

    @patch("mycryptopony.run_cmd")
    def test_failure(self, mock_run_cmd: MagicMock) -> None:
        mock_run_cmd.return_value = (1, "", "rhash error")
        ok, msg = rhash_generate_hash(Path("/tmp/doc.pdf"), "blake3")
        assert ok is False


# ---------------------------------------------------------------------------
# rhash_verify_hash tests
# ---------------------------------------------------------------------------
class TestRhashVerifyHash:
    @patch("mycryptopony.run_cmd")
    def test_hash_matches(self, mock_run_cmd: MagicMock, tmp_path: Path) -> None:
        expected_hash = "a" * 128
        hash_file = tmp_path / "file.txt.sha512"
        hash_file.write_text(f"{expected_hash}  file.txt\n")

        mock_run_cmd.return_value = (0, f"{expected_hash}  file.txt\n", "")

        ok, msg = rhash_verify_hash(hash_file, tmp_path / "file.txt")
        assert ok is True
        assert "matches" in msg

    @patch("mycryptopony.run_cmd")
    def test_hash_mismatch(self, mock_run_cmd: MagicMock, tmp_path: Path) -> None:
        hash_file = tmp_path / "file.txt.sha512"
        hash_file.write_text("a" * 128 + "  file.txt\n")

        mock_run_cmd.return_value = (0, "b" * 128 + "  file.txt\n", "")

        ok, msg = rhash_verify_hash(hash_file, tmp_path / "file.txt")
        assert ok is False
        assert "mismatch" in msg

    def test_unsupported_extension(self, tmp_path: Path) -> None:
        hash_file = tmp_path / "file.txt.md5"
        hash_file.write_text("abc123  file.txt\n")

        ok, msg = rhash_verify_hash(hash_file, tmp_path / "file.txt")
        assert ok is False
        assert "Unsupported" in msg

    @patch("mycryptopony.run_cmd")
    def test_target_file_actually_used(self, mock_run_cmd: MagicMock, tmp_path: Path) -> None:
        """Regression test: target_file_path must be passed to rhash."""
        hash_file = tmp_path / "file.txt.sha512"
        hash_file.write_text("a" * 128 + "  file.txt\n")

        target_file = tmp_path / "different_file.bin"
        target_file.write_bytes(b"some content")

        mock_run_cmd.return_value = (0, "a" * 128 + "  different_file.bin\n", "")

        rhash_verify_hash(hash_file, target_file)

        cmd = mock_run_cmd.call_args[0][0]
        assert str(target_file) in cmd
        assert str(hash_file) not in cmd

    @patch("mycryptopony.run_cmd")
    def test_rhash_failure(self, mock_run_cmd: MagicMock, tmp_path: Path) -> None:
        hash_file = tmp_path / "file.txt.sha512"
        hash_file.write_text("a" * 128 + "  file.txt\n")

        mock_run_cmd.return_value = (1, "", "rhash crashed")

        ok, msg = rhash_verify_hash(hash_file, tmp_path / "file.txt")
        assert ok is False

    @patch("mycryptopony.run_cmd")
    def test_unreadable_hash_file(self, mock_run_cmd: MagicMock, tmp_path: Path) -> None:
        hash_file = tmp_path / "nonexistent.sha512"
        mock_run_cmd.return_value = (0, "a" * 128 + "  file.txt\n", "")

        ok, msg = rhash_verify_hash(hash_file, tmp_path / "file.txt")
        assert ok is False
        assert "Could not read hash" in msg


# ---------------------------------------------------------------------------
# croc_send tests
# ---------------------------------------------------------------------------
class TestCrocSend:
    @patch("mycryptopony.run_cmd")
    def test_success_with_code(self, mock_run_cmd: MagicMock) -> None:
        mock_run_cmd.return_value = (0, "Code is: puma-moral-builder\n", "Sending...\n")
        ok, msg = croc_send(Path("/tmp/file.txt"))
        assert ok is True
        assert "puma-moral-builder" in msg

    @patch("mycryptopony.run_cmd")
    def test_success_without_code(self, mock_run_cmd: MagicMock) -> None:
        mock_run_cmd.return_value = (0, "Sent.\n", "")
        ok, msg = croc_send(Path("/tmp/file.txt"))
        assert ok is True
        assert "code not found" in msg

    @patch("mycryptopony.run_cmd")
    def test_failure(self, mock_run_cmd: MagicMock) -> None:
        mock_run_cmd.return_value = (1, "", "connection refused")
        ok, msg = croc_send(Path("/tmp/file.txt"))
        assert ok is False


# ---------------------------------------------------------------------------
# croc_receive tests
# ---------------------------------------------------------------------------
class TestCrocReceive:
    @patch("mycryptopony.run_cmd")
    def test_success(self, mock_run_cmd: MagicMock) -> None:
        mock_run_cmd.return_value = (0, "File received.\n", "")
        ok, msg = croc_receive("puma-moral-builder")
        assert ok is True
        assert "Received" in msg

    @patch("mycryptopony.run_cmd")
    def test_failure(self, mock_run_cmd: MagicMock) -> None:
        mock_run_cmd.return_value = (1, "", "code expired")
        ok, msg = croc_receive("bad-code")
        assert ok is False

#!/usr/bin/env python3
"""
MyCryptoPony - a terminal UI for age, minisign, mat2, rhash, and croc.
Requires: textual, pexpect, age, minisign, mat2, rhash, croc
"""
import asyncio
import re
import subprocess
from pathlib import Path

import pexpect
from textual import on
from textual.app import App, ComposeResult
from textual.containers import Container, Horizontal, ScrollableContainer, Vertical
from textual.screen import ModalScreen, Screen
from textual.widget import Widget
from textual.widgets import (
    Button,
    DirectoryTree,
    Footer,
    Header,
    Input,
    Label,
    Select,
    Static,
)

DEFAULT_CMD_TIMEOUT = 300

# ----------------------------
# Base form screen
# ----------------------------
class BaseFormScreen(Screen[None]):
    """Abstract screen with input fields and action buttons."""

    def compose(self) -> ComposeResult:
        yield Header()
        yield Container(
            ScrollableContainer(self.create_form(), id="form_container"),
            Horizontal(
                Button("Submit", variant="primary", id="submit"),
                Button("Back", variant="default", id="back"),
                id="buttons",
            ),
            id="screen_container",
        )
        yield Footer()

    def create_form(self) -> Widget:
        return Label("Form")

    @on(Button.Pressed, "#back")
    def go_back(self) -> None:
        self.app.pop_screen()

    @on(Button.Pressed, "#submit")
    async def submit(self) -> None:
        await self.on_submit()

    async def on_submit(self) -> None:
        pass

# ----------------------------
# File / folder picker modal
# ----------------------------
class FilePickerModal(ModalScreen[str | None]):
    """Modal dialog with a directory tree for picking a file or folder."""

    def __init__(self, directory_mode: bool = False) -> None:
        self.directory_mode = directory_mode
        super().__init__()

    def compose(self) -> ComposeResult:
        prompt = "Select folder:" if self.directory_mode else "Select file:"
        yield Container(
            Label(prompt),
            DirectoryTree("/", id="picker_tree"),
            Button("Cancel", variant="default", id="cancel"),
            id="modal_dialog",
        )

    @on(DirectoryTree.FileSelected)
    def select_file(self, event: DirectoryTree.FileSelected) -> None:
        self.dismiss(str(event.path))

    @on(DirectoryTree.DirectorySelected)
    def select_directory(self, event: DirectoryTree.DirectorySelected) -> None:
        if self.directory_mode:
            self.dismiss(str(event.path))

    @on(Button.Pressed, "#cancel")
    def cancel(self) -> None:
        self.dismiss(None)

# ----------------------------
# Reusable path input widget
# ----------------------------
class PathInput(Horizontal):
    """Composite widget: Input + Browse button that opens FilePickerModal."""

    DEFAULT_CSS = """
    PathInput {
        height: auto;
    }
    PathInput Input {
        width: 40;
    }
    """

    def __init__(
        self,
        *,
        input_id: str,
        placeholder: str = "",
        directory_mode: bool = False,
    ) -> None:
        super().__init__()
        self._input_id = input_id
        self._placeholder = placeholder
        self._directory_mode = directory_mode

    def compose(self) -> ComposeResult:
        yield Input(placeholder=self._placeholder, id=self._input_id)
        yield Button("Browse", variant="default", id=f"browse_{self._input_id}")

    @on(Button.Pressed)
    def _on_browse(self, event: Button.Pressed) -> None:
        if event.button.id == f"browse_{self._input_id}":
            self.app.push_screen(
                FilePickerModal(directory_mode=self._directory_mode),
                callback=self._set_path,
            )

    def _set_path(self, path: str | None) -> None:
        if path:
            self.query_one(f"#{self._input_id}", Input).value = path

# ----------------------------
# External command helpers
# ----------------------------
def run_cmd(cmd: list[str], input_data: bytes | None = None) -> tuple[int, str, str]:
    """Run a command and return (returncode, stdout, stderr)."""
    try:
        proc = subprocess.run(
            cmd,
            input=input_data,
            capture_output=True,
            check=False,
            timeout=DEFAULT_CMD_TIMEOUT,
        )
        return (
            proc.returncode,
            proc.stdout.decode("utf-8", errors="replace"),
            proc.stderr.decode("utf-8", errors="replace"),
        )
    except FileNotFoundError:
        return 1, "", f"Command not found: {cmd[0]}\nPlease install it and try again."
    except subprocess.TimeoutExpired:
        return 1, "", f"Command timed out after {DEFAULT_CMD_TIMEOUT} seconds."

def _extract_hex_digest(text: str) -> str | None:
    """Extract the first hex digest (>=64 chars) from rhash output or hash file."""
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith(";") or line.startswith("#"):
            continue
        match = re.search(r"[a-fA-F0-9]{64,}", line)
        if match:
            return match.group(0).lower()
    return None

def _get_algorithm_from_extension(hash_file_path: Path) -> str | None:
    """Map hash file extension to algorithm name."""
    ext = hash_file_path.suffix.lower()
    mapping = {".sha512": "sha512", ".blake3": "blake3"}
    return mapping.get(ext)

def age_encrypt_file(
    input_path: Path,
    output_path: Path | None = None,
    passphrase: str | None = None,
    recipient: str | None = None,
) -> tuple[bool, str]:
    if output_path is None:
        output_path = input_path.with_suffix(input_path.suffix + ".age")

    if passphrase:
        try:
            child = pexpect.spawn(
                "age",
                ["--encrypt", "-p", "--output", str(output_path), str(input_path)],
                timeout=DEFAULT_CMD_TIMEOUT,
            )
            child.expect("Enter passphrase")
            child.sendline(passphrase)
            child.expect("Confirm passphrase")
            child.sendline(passphrase)
            child.expect(pexpect.EOF)
            
            if child.exitstatus == 0:
                return True, f"Encrypted: {output_path}"
            before_text = child.before or ""
            if isinstance(before_text, bytes):
                before_text = before_text.decode("utf-8", errors="replace")
            return False, before_text
        except pexpect.ExceptionPexpect as e:
            return False, f"Interaction error with age: {e}"
        except FileNotFoundError:
            return False, "Command 'age' not found. Install via: brew install age"
            
    if recipient:
        cmd = [
            "age", "--encrypt", "--output", str(output_path),
            "--recipient", recipient, str(input_path),
        ]
        code, _, err = run_cmd(cmd)
        if code == 0:
            return True, f"Encrypted: {output_path}"
        return False, err
        
    return False, "Neither passphrase nor recipient specified"

def age_decrypt_file(
    input_path: Path,
    output_path: Path | None = None,
    passphrase: str | None = None,
    identity: Path | None = None,
) -> tuple[bool, str]:
    if output_path is None:
        output_path = (
            input_path.with_suffix("")
            if input_path.suffix == ".age"
            else input_path.with_suffix(input_path.suffix + ".dec")
        )

    if passphrase:
        try:
            child = pexpect.spawn(
                "age",
                ["--decrypt", "--output", str(output_path), str(input_path)],
                timeout=DEFAULT_CMD_TIMEOUT,
            )
            child.expect("Enter passphrase")
            child.sendline(passphrase)
            child.expect(pexpect.EOF)
            
            if child.exitstatus == 0:
                return True, f"Decrypted: {output_path}"
            before_text = child.before or ""
            if isinstance(before_text, bytes):
                before_text = before_text.decode("utf-8", errors="replace")
            return False, before_text
        except pexpect.ExceptionPexpect as e:
            return False, f"Interaction error with age: {e}"
        except FileNotFoundError:
            return False, "Command 'age' not found. Install via: brew install age"
            
    if identity:
        cmd = [
            "age", "--decrypt", "--output", str(output_path),
            "--identity", str(identity), str(input_path),
        ]
        code, _, err = run_cmd(cmd)
        if code == 0:
            return True, f"Decrypted: {output_path}"
        return False, err
        
    return False, "Passphrase or identity file required"

def minisign_sign_file(
    input_path: Path,
    sig_path: Path | None,
    secret_key_path: str | None,
    passphrase: str,
) -> tuple[bool, str]:
    if sig_path is None:
        sig_path = input_path.with_suffix(input_path.suffix + ".minisig")
    if not secret_key_path or not secret_key_path.strip():
        secret_key_path = str(Path.home() / ".minisign" / "minisign.key")

    try:
        child = pexpect.spawn(
            "minisign",
            ["-S", "-x", str(sig_path), "-s", secret_key_path, "-m", str(input_path)],
            timeout=DEFAULT_CMD_TIMEOUT,
        )
        child.expect(r"[Pp]assword:")
        child.sendline(passphrase)
        child.expect(pexpect.EOF)
        
        if child.exitstatus == 0:
            return True, f"Signature created: {sig_path}"
        before_text = child.before or ""
        if isinstance(before_text, bytes):
            before_text = before_text.decode("utf-8", errors="replace")
        return False, before_text
    except pexpect.ExceptionPexpect as e:
        return False, f"Interaction error with minisign: {e}"
    except FileNotFoundError:
        return False, "Command 'minisign' not found. Install via: brew install minisign"

def minisign_verify_file(
    input_path: Path, sig_path: Path, pub_key_path: str | None
) -> tuple[bool, str]:
    if not pub_key_path or not pub_key_path.strip():
        pub_key_path = str(Path.home() / ".minisign" / "minisign.pub")
        
    cmd = ["minisign", "-V", "-x", str(sig_path), "-p", pub_key_path, "-m", str(input_path)]
    code, _, err = run_cmd(cmd)
    if code == 0:
        return True, "Signature is valid"
    return False, err or "Signature verification failed"

def mat2_clean_file(input_path: Path) -> tuple[bool, str]:
    cmd = ["mat2", str(input_path)]
    code, _, err = run_cmd(cmd)
    if code == 0:
        cleaned_path = str(input_path) + ".cleaned"
        return True, f"Metadata cleaned. Created: {cleaned_path}"
    return False, err or "Failed to clean metadata"

def rhash_generate_hash(input_path: Path, algorithm: str) -> tuple[bool, str]:
    output_path = input_path.with_suffix(f"{input_path.suffix}.{algorithm}")
    cmd = ["rhash", f"--{algorithm}", "-o", str(output_path), str(input_path)]
    code, _, err = run_cmd(cmd)
    if code == 0:
        return True, f"Hash generated and saved to: {output_path}"
    return False, err or "Failed to generate hash"

def rhash_verify_hash(hash_file_path: Path, target_file_path: Path) -> tuple[bool, str]:
    """Verify that target_file_path matches the hash recorded in hash_file_path."""
    algo = _get_algorithm_from_extension(hash_file_path)
    if not algo:
        return False, f"Unsupported hash file extension: {hash_file_path.suffix}"

    cmd = ["rhash", f"--{algo}", str(target_file_path)]
    code, out, err = run_cmd(cmd)
    if code != 0:
        return False, err or "Failed to compute hash of target file"

    computed_hash = _extract_hex_digest(out)
    if not computed_hash:
        return False, "Could not parse hash from rhash output"

    try:
        hash_content = hash_file_path.read_text(encoding="utf-8", errors="replace")
    except OSError as e:
        return False, f"Could not read hash file: {e}"

    expected_hash = _extract_hex_digest(hash_content)
    if not expected_hash:
        return False, f"Could not read hash from {hash_file_path}"

    if computed_hash == expected_hash:
        return True, "Hash matches successfully"
    return False, "Hash mismatch: file does not match the recorded hash"

def croc_send(path: Path) -> tuple[bool, str]:
    cmd = ["croc", "--yes", "send", str(path)]
    code, out, err = run_cmd(cmd)
    combined = out + err
    if code == 0:
        match = re.search(r"Code is:\s*(\S+)", combined)
        if match:
            return True, f"Receive code: {match.group(1)}"
        return True, "Sent (code not found in output)"
    return False, err

def croc_receive(code_str: str) -> tuple[bool, str]:
    cmd = ["croc", "--yes", "--overwrite", code_str]
    code_r, _, err = run_cmd(cmd)
    if code_r == 0:
        return True, "Received successfully"
    return False, err

# ----------------------------
# Concrete screens
# ----------------------------
class EncryptScreen(BaseFormScreen):
    def create_form(self) -> Vertical:
        return Vertical(
            Label("📁 Age Encryption", classes="subtitle"),
            PathInput(input_id="input_path", placeholder="File path"),
            Input(placeholder="Passphrase (optional)", id="passphrase", password=True),
            Input(placeholder="Confirm passphrase", id="passphrase_confirm", password=True),
            Input(placeholder="Public key (if no passphrase)", id="recipient"),
            PathInput(input_id="output_path", placeholder="Output file path (optional)"),
        )

    async def on_submit(self) -> None:
        path_str = self.query_one("#input_path", Input).value
        passphrase = self.query_one("#passphrase", Input).value
        passphrase_confirm = self.query_one("#passphrase_confirm", Input).value
        recipient = self.query_one("#recipient", Input).value
        out_str = self.query_one("#output_path", Input).value

        if not path_str:
            self.notify("Please specify a file", severity="error")
            return

        in_path = Path(path_str).expanduser()
        if not in_path.is_file():
            self.notify("File not found", severity="error")
            return

        out_path = Path(out_str).expanduser() if out_str else None

        if passphrase:
            if not passphrase_confirm:
                self.notify("Please confirm the passphrase", severity="error")
                return
            if passphrase != passphrase_confirm:
                self.notify("Passphrases do not match", severity="error")
                return
            ok, msg = await asyncio.to_thread(
                age_encrypt_file, in_path, out_path, passphrase=passphrase
            )
        elif recipient:
            ok, msg = await asyncio.to_thread(
                age_encrypt_file, in_path, out_path, recipient=recipient
            )
        else:
            ok, msg = False, "Please specify a passphrase or public key"

        self.notify(msg, severity="information" if ok else "error")
        if ok:
            self.app.pop_screen()

class DecryptScreen(BaseFormScreen):
    def create_form(self) -> Vertical:
        return Vertical(
            Label("🔓 Age Decryption", classes="subtitle"),
            PathInput(input_id="input_path", placeholder="Encrypted file path (.age)"),
            Input(placeholder="Passphrase (optional)", id="passphrase", password=True),
            PathInput(input_id="identity", placeholder="Identity file path"),
            PathInput(input_id="output_path", placeholder="Output file path (optional)"),
        )

    async def on_submit(self) -> None:
        path_str = self.query_one("#input_path", Input).value
        passphrase = self.query_one("#passphrase", Input).value
        identity_str = self.query_one("#identity", Input).value
        out_str = self.query_one("#output_path", Input).value

        if not path_str:
            self.notify("Please specify a file", severity="error")
            return

        in_path = Path(path_str).expanduser()
        if not in_path.is_file():
            self.notify("File not found", severity="error")
            return

        out_path = Path(out_str).expanduser() if out_str else None

        if passphrase:
            ok, msg = await asyncio.to_thread(
                age_decrypt_file, in_path, out_path, passphrase=passphrase
            )
        elif identity_str:
            id_path = Path(identity_str).expanduser()
            if not id_path.is_file():
                self.notify("Identity file not found", severity="error")
                return
            ok, msg = await asyncio.to_thread(
                age_decrypt_file, in_path, out_path, identity=id_path
            )
        else:
            ok, msg = False, "Please specify a passphrase or identity file"

        self.notify(msg, severity="information" if ok else "error")
        if ok:
            self.app.pop_screen()

class SignScreen(BaseFormScreen):
    def create_form(self) -> Vertical:
        default_key = str(Path.home() / ".minisign" / "minisign.key")
        return Vertical(
            Label("✍️ Minisign File Signing", classes="subtitle"),
            PathInput(input_id="input_path", placeholder="File to sign path"),
            PathInput(input_id="sig_path", placeholder="Signature output path (.minisig)"),
            PathInput(
                input_id="secret_key_path",
                placeholder=f"Secret key path (default: {default_key})",
            ),
            Input(placeholder="Secret key passphrase", id="passphrase", password=True),
        )

    async def on_submit(self) -> None:
        path_str = self.query_one("#input_path", Input).value
        sig_str = self.query_one("#sig_path", Input).value
        key_str = self.query_one("#secret_key_path", Input).value
        passphrase = self.query_one("#passphrase", Input).value

        if not path_str:
            self.notify("Please specify a file", severity="error")
            return

        in_path = Path(path_str).expanduser()
        if not in_path.is_file():
            self.notify("File not found", severity="error")
            return

        sig_path = Path(sig_str).expanduser() if sig_str else None

        if not passphrase:
            self.notify("Passphrase is required for signing", severity="error")
            return

        ok, msg = await asyncio.to_thread(
            minisign_sign_file, in_path, sig_path, key_str, passphrase
        )
        self.notify(msg, severity="information" if ok else "error")
        if ok:
            self.app.pop_screen()

class VerifyScreen(BaseFormScreen):
    def create_form(self) -> Vertical:
        default_pub = str(Path.home() / ".minisign" / "minisign.pub")
        return Vertical(
            Label("✅ Minisign Signature Verification", classes="subtitle"),
            PathInput(input_id="input_path", placeholder="Original file path"),
            PathInput(input_id="sig_path", placeholder="Signature file path (.minisig)"),
            PathInput(
                input_id="pub_key_path",
                placeholder=f"Public key path (default: {default_pub})",
            ),
        )

    async def on_submit(self) -> None:
        path_str = self.query_one("#input_path", Input).value
        sig_str = self.query_one("#sig_path", Input).value
        pub_str = self.query_one("#pub_key_path", Input).value

        if not path_str or not sig_str:
            self.notify("Please specify both file and signature", severity="error")
            return

        in_path = Path(path_str).expanduser()
        sig_path = Path(sig_str).expanduser()

        if not in_path.is_file() or not sig_path.is_file():
            self.notify("File or signature not found", severity="error")
            return

        ok, msg = await asyncio.to_thread(
            minisign_verify_file, in_path, sig_path, pub_str
        )
        self.notify(msg, severity="information" if ok else "error")
        if ok:
            self.app.pop_screen()

class CleanScreen(BaseFormScreen):
    def create_form(self) -> Vertical:
        return Vertical(
            Label("🪄 Clean Metadata (mat2)", classes="subtitle"),
            PathInput(input_id="input_path", placeholder="File path (PDF, image, etc.)"),
            Label("Note: A '.cleaned' copy will be created.", classes="muted"),
        )

    async def on_submit(self) -> None:
        path_str = self.query_one("#input_path", Input).value
        if not path_str:
            self.notify("Please specify a file", severity="error")
            return

        in_path = Path(path_str).expanduser()
        if not in_path.is_file():
            self.notify("File not found", severity="error")
            return

        ok, msg = await asyncio.to_thread(mat2_clean_file, in_path)
        self.notify(msg, severity="information" if ok else "error")
        if ok:
            self.app.pop_screen()

class HashGenScreen(BaseFormScreen):
    def create_form(self) -> Vertical:
        return Vertical(
            Label("🔎 Generate Hash (rhash)", classes="subtitle"),
            PathInput(input_id="input_path", placeholder="File path"),
            Select(
                prompt="Select Algorithm",
                options=[("SHA-512", "sha512"), ("BLAKE3", "blake3")],
                id="algorithm_select",
                allow_blank=False,
            ),
            Label(
                "Note: A hash file (e.g., .sha512) will be created next to the original.",
                classes="muted",
            ),
        )

    async def on_submit(self) -> None:
        path_str = self.query_one("#input_path", Input).value
        algorithm_select = self.query_one("#algorithm_select", Select)
        algorithm_value = algorithm_select.value
        
        if not path_str:
            self.notify("Please specify a file", severity="error")
            return
        if algorithm_value is None or algorithm_value is Select.BLANK:
            self.notify("Please select an algorithm", severity="error")
            return
        
        algorithm = str(algorithm_value)

        in_path = Path(path_str).expanduser()
        if not in_path.is_file():
            self.notify("File not found", severity="error")
            return

        ok, msg = await asyncio.to_thread(rhash_generate_hash, in_path, algorithm)
        self.notify(msg, severity="information" if ok else "error", timeout=15)
        if ok:
            self.app.pop_screen()

class HashVerifyScreen(BaseFormScreen):
    def create_form(self) -> Vertical:
        return Vertical(
            Label("🔍 Verify Hash (rhash)", classes="subtitle"),
            PathInput(input_id="hash_file_path", placeholder="Hash file path (e.g., .sha512)"),
            PathInput(input_id="target_file_path", placeholder="Target file path to verify"),
        )

    async def on_submit(self) -> None:
        hash_str = self.query_one("#hash_file_path", Input).value
        target_str = self.query_one("#target_file_path", Input).value

        if not hash_str or not target_str:
            self.notify("Please specify both files", severity="error")
            return

        hash_path = Path(hash_str).expanduser()
        target_path = Path(target_str).expanduser()

        if not hash_path.is_file() or not target_path.is_file():
            self.notify("One or both files not found", severity="error")
            return

        ok, msg = await asyncio.to_thread(rhash_verify_hash, hash_path, target_path)
        self.notify(msg, severity="information" if ok else "error")
        if ok:
            self.app.pop_screen()

class SendScreen(BaseFormScreen):
    def create_form(self) -> Vertical:
        return Vertical(
            Label("📤 Send via croc", classes="subtitle"),
            PathInput(input_id="path", placeholder="File or folder path", directory_mode=True),
        )

    async def on_submit(self) -> None:
        path_str = self.query_one("#path", Input).value
        if not path_str:
            self.notify("Please specify a path", severity="error")
            return

        path = Path(path_str).expanduser()
        if not path.exists():
            self.notify("Path does not exist", severity="error")
            return

        ok, msg = await asyncio.to_thread(croc_send, path)
        self.notify(msg, severity="information" if ok else "error", timeout=10)
        if ok:
            self.app.pop_screen()

class ReceiveScreen(BaseFormScreen):
    def create_form(self) -> Vertical:
        return Vertical(
            Label("📥 Receive via croc", classes="subtitle"),
            Input(placeholder="Code (e.g., 'puma-moral-builder')", id="code"),
        )

    async def on_submit(self) -> None:
        code = self.query_one("#code", Input).value.strip()
        if not code:
            self.notify("Please enter a code", severity="error")
            return

        ok, msg = await asyncio.to_thread(croc_receive, code)
        self.notify(msg, severity="information" if ok else "error")
        if ok:
            self.app.pop_screen()

# ----------------------------
# Main screen
# ----------------------------
class MainScreen(Screen[None]):
    def compose(self) -> ComposeResult:
        yield Header()
        yield Container(
            Label("🦄 MyCryptoPony", id="title"),
            Button("📁 Encrypt file (age)", variant="primary", id="btn_encrypt"),
            Button("🔓 Decrypt file (age)", variant="primary", id="btn_decrypt"),
            Button("✍️ Sign file (minisign)", variant="primary", id="btn_sign"),
            Button("✅ Verify signature (minisign)", variant="primary", id="btn_verify"),
            Button("🪄 Clean metadata (mat2)", variant="primary", id="btn_clean"),
            Button("🔎 Generate hash (rhash)", variant="primary", id="btn_hash_gen"),
            Button("🔍 Verify hash (rhash)", variant="primary", id="btn_hash_verify"),
            Button("📤 Send via croc", variant="success", id="btn_send"),
            Button("📥 Receive via croc", variant="success", id="btn_receive"),
            Button("❌ Exit", variant="error", id="btn_exit"),
            id="main_menu",
        )
        yield Footer()

    @on(Button.Pressed, "#btn_encrypt")
    def action_encrypt(self) -> None:
        self.app.push_screen(EncryptScreen())

    @on(Button.Pressed, "#btn_decrypt")
    def action_decrypt(self) -> None:
        self.app.push_screen(DecryptScreen())

    @on(Button.Pressed, "#btn_sign")
    def action_sign(self) -> None:
        self.app.push_screen(SignScreen())

    @on(Button.Pressed, "#btn_verify")
    def action_verify(self) -> None:
        self.app.push_screen(VerifyScreen())

    @on(Button.Pressed, "#btn_clean")
    def action_clean(self) -> None:
        self.app.push_screen(CleanScreen())

    @on(Button.Pressed, "#btn_hash_gen")
    def action_hash_gen(self) -> None:
        self.app.push_screen(HashGenScreen())

    @on(Button.Pressed, "#btn_hash_verify")
    def action_hash_verify(self) -> None:
        self.app.push_screen(HashVerifyScreen())

    @on(Button.Pressed, "#btn_send")
    def action_send(self) -> None:
        self.app.push_screen(SendScreen())

    @on(Button.Pressed, "#btn_receive")
    def action_receive(self) -> None:
        self.app.push_screen(ReceiveScreen())

    @on(Button.Pressed, "#btn_exit")
    def action_exit(self) -> None:
        self.app.exit()

# ----------------------------
# Application
# ----------------------------
class MyCryptoPonyApp(App[None]):
    CSS = """
    Screen {
        background: $surface;
    }
    #title {
        color: $primary;
        text-style: bold;
        margin: 1;
        width: 100%;
        text-align: center;
    }
    .subtitle {
        color: $accent;
        text-style: bold;
        margin-bottom: 1;
    }
    .muted {
        color: $text-muted;
        margin-top: 1;
    }
    #modal_dialog {
        background: $surface;
        border: heavy $primary;
        padding: 1 2;
        width: 60%;
        height: 80%;
    }
    """

    SCREENS = {"main": MainScreen}

    def on_mount(self) -> None:
        self.push_screen("main")

def main() -> None:
    MyCryptoPonyApp().run()

if __name__ == "__main__":
    main()
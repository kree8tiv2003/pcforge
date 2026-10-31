# PCForge

A Windows PC care app: cleaner, registry cleaner, startup manager, Turbo Boost, Smart RAM, privacy sweep,
protection checks, toolbox, and an Undo & History page.

## Just want to use it?
Double-click `dist\PCForge.exe`. Click **Scan my PC** on the first screen, read the plan, untick anything you don't want,
then click **Fix ticked items**. Nothing changes until you confirm. For the most thorough scan click
**Run as administrator** (bottom-left); Windows will ask permission.

Changed your mind? **Undo & History** lists everything PCForge did and has buttons to put things back
(registry entries, quarantined files, paused programs, browser protection, the skip list).

If something unexpected happens you get a plain message and a report in `%LOCALAPPDATA%\PCForge\crash.log`.

## Updates
PCForge can update itself: **About & Updates** > *Check for updates*, or it checks once a day when it starts
(you can turn that off). When a new version exists a banner appears; one click downloads it, checks it,
swaps it in and reopens. The old version is kept as `PCForge.exe.old`.

Every update is signed with your private key (`C:\Users\<you>\PCForge-keys\update_private.key`, **back it up and
never share it**). PCForge refuses anything that is not signed by that key, or whose size/fingerprint differs.

To release a new version:
1. Change `VERSION` in `pcforge/brand.py` and rebuild the exe.
2. `python tools/publish_update.py --exe dist/PCForge.exe --version 0.2.0 --url https://<your host>/PCForge.exe --key C:\Users\<you>\PCForge-keys\update_private.key --notes "What changed"`
3. Upload `PCForge.exe` and the generated `latest.json` to your host. The address of `latest.json` must be set as
   `UPDATE_MANIFEST_URL` in `pcforge/brand.py` (rebuild once with it; after that, updates flow by themselves).

`python -m pcforge selftest` checks that signing and secure connections work in the build.

## For developers
```
pip install -r requirements.txt
python -m pcforge gui          # desktop app
python -m pcforge ai           # AI Mode in the terminal
python -m pcforge --help       # every tool; changes need --apply
python -m unittest discover -s tests
python tools/make_icon.py assets
```
Rebuild the exe:
```
python -m PyInstaller --noconfirm --onefile --windowed --name PCForge --icon assets\icon.ico --add-data "assets;assets" --distpath dist --workpath build --specpath build launcher.py
```
Name and colors live in `pcforge/brand.py`. See `PARITY.md` for how this compares with Advanced SystemCare.

| Feature | Module |
|---|---|
| Junk cleaner, shortcuts, leftover folders | `cleaner.py` |
| Registry cleaner (backs up first) | `registry_cleaner.py` |
| Startup: Run keys, folders, tasks, services | `startup.py` |
| Turbo Boost, Smart RAM | `turbo.py`, `ram.py` |
| Privacy sweep, browser hardening | `privacy.py`, `hardening.py` |
| Protection, link/email checks, folder tripwire | `protection.py` |
| Toolbox | `toolbox.py` |
| AI Mode, report | `ai_mode.py`, `report.py` |
| Undo & History | `history.py` |

## Limits
- Protection runs as a normal program: it scans and warns but can't intercept file opens like a kernel driver. Keep Windows Security or another antivirus on.
- "Fingerprint protection" reduces what sites can read; it is not an anti-detect browser.
- Shredding is best-effort on SSDs.
- The exe is not code-signed, so Windows SmartScreen may warn the first time.

# Parity with Advanced SystemCare 20.0.1

Source of the original's coverage: the strings in its own shipped `Language\English.lng` (plain text), its installer script, its service/task/driver registration, and its config files. I could not drive the original's GUI automatically, so nothing here comes from a live side-by-side scan; see "Not compared".

## Junk file clean
| Original category | PCForge |
|---|---|
| Windows temp, user temp | yes |
| Thumbnail cache | yes |
| Windows log files | yes (CBS, DISM, `C:\Windows\*.log`, older than 7 days) |
| Old Prefetch data | yes (older than 30 days, admin) |
| Memory dumps / crash dumps | yes |
| IIS logs | yes (admin) |
| Delivery Optimization files | yes (admin) |
| Microsoft Office cache | yes |
| Windows Defender scan history | yes (admin; Windows may refuse) |
| Microsoft Store app leftovers | yes (TempState, INetCache) |
| Recycle Bin | yes |
| Browser caches | yes (privacy tab) |
| Windows Font Cache, Installer Cache, Windows Installer unused files | **not done**: owned by running services / easy to break installers |
| Menu-order, tray-icon, window size/location caches | **not done**: they reset your desktop layout |
| "Keep last N days" sliders | partial: fixed 24 h / 7 d / 30 d ages; `scan_junk(keep_days_scale=)` scales them but the UI has no slider yet |
| Per-user-account scanning | not done (current user + system only) |
| DoD 5220.22-M secure deletion option | not done on cleaner; the Shredder tool exists |

Extra in PCForge: NVIDIA/AMD shader caches, Discord/Slack/Code/Teams/Spotify caches.

## Registry (original has 18 categories)
Done (11): App Paths, Software (uninstall), Startup Items, Shared Files, Fonts, Help Files, MUI Cache, Sounds, Windows Services, ActiveX/COM.
Not done (7): Registry Integrity, History Lists (covered by Privacy), Shortcuts (covered by the shortcut finder), Start Menu, Virtual Device, File Extensions, System Extensions, Firewall Settings, Registry Defrag.
Safety: `.reg` backup per key + a System Restore point (admin) before any HKLM fix. Services and COM entries are never pre-selected and never included in AI Mode.

## Startup Manager
Run keys, Startup folders, **scheduled tasks (logon/boot)** and **services** (switch Automatic to Manual). AI Mode never touches services.
Not done: the original's startup "impact" ratings from its signature databases.

## Privacy sweep
Browsers: Chrome, Edge, Brave, Vivaldi, Opera, Chromium, Firefox (the original lists Firefox, Chrome, Opera, Edge, Vivaldi, IE, Office apps).
Windows traces: recent files, jump lists, Run history, typed paths, Paint/WordPad recents, UserAssist (opt-in), DNS cache, clipboard.
Not done: Internet Explorer, Office MRU lists, "keep cookies for safe sites" list, "keep last N days of history".

## Other features
| Original | PCForge |
|---|---|
| Ignore lists | yes (`pcforge ignore --add <path>`, also honoured by every scan) |
| Rescue Center / System Restore point | restore point yes; registry `.reg` restore yes; no unified Rescue Center screen |
| Turbo Boost, Smart RAM | yes |
| Surfing/Email/Ads protection via browser extension | no extension; link + .eml checker, hosts blocking instead |
| Real-time anti-spyware (kernel filter drivers) | no; user-mode scanner + Defender wrapper |
| Homepage Advisor, Fingerprint Protection | hardening policies only; no homepage-hijack watcher |
| Reinforce (disable risky Windows services) | not done |
| Auto Care scheduler, notifications | not done |
| Software Updater, driver updater | winget software updater; no driver updater |

## Measured against the original (same PC, 2026-10-31 about 09:31, both non-destructive scans)
The original's one-click scan logs its per-module totals in `ASC.log`; PCForge numbers come from its dry-run commands.

| Module | Original | PCForge | Verdict |
|---|---|---|---|
| Junk files | 697 items, 617.2 MiB | 555 items, 621.9 MB | size within 1%; item counts differ because the original counts per file |
| Privacy traces | 14,154 items, 1.55 GiB | 41 findings, about 1.2 GB | PCForge about 25% lower; the original covers more applications. Cause not identified |
| Shortcuts | 26 | 10 (all "missing icon", none broken-target) | 16 unexplained; the ones I miss have commas in their icon file names, which suggests the original (or Windows' own COM API) splits `path,index` at the first comma. Unverified without the original's list |
| Registry | 627 (309 "ActiveX and Component") | 12 | **large gap, not closed.** Extra categories I measured (WOW6432 CLSIDs, TypeLibs, firewall rules, file associations) explain only about 13 more. The rest likely comes from its encrypted definition database (`Reg.dbd`) which I did not open |
| Startup | 7 items | 6 suggestions | close; different rules |
| Software updates | 1 | 19 (winget) | different definitions; winget reports far more |
| Spyware / security / defrag / disk check | 0 | 1 heuristic hit | not comparable |

Junk categories the original has that PCForge does not (Chkdsk file fragments were added afterwards): Installed Driver Packages (old driver-store entries), Windows Installer unused files, Visual Studio caches, per-app Store caches (PCForge uses a wildcard instead), third-party app caches (for example Avast).

## Not compared
No live run of the same inputs through both programs: the original has no command line, and REA's native-UI tools do not drive Windows windows. To close this gap, run a scan in the original and send me its result counts or a screenshot, and I will diff them against `python -m pcforge clean/registry/startup` on the same machine state.

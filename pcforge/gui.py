"""Tkinter desktop app: AI Mode dashboard, one page per tool, and an Undo & History page.

Written for people who don't read logs: plain wording, a reason for every item, a
progress bar while it works, and a friendly message (plus a saved log) if anything breaks.
"""
from __future__ import annotations

import os
import sys
import threading
import tkinter as tk
import traceback
from tkinter import filedialog, messagebox, ttk

from . import (ai_mode, brand, cleaner, hardening, history, privacy, protection, ram, registry_cleaner, report,
               safety, settings, startup, toolbox, turbo, updater)
from .safety import fmt_size, is_admin

# One plain sentence for every kind of finding, shown when you click a row.
CATEGORY_HELP = {
    "user_temp": "Temporary files that programs leave behind. Safe to remove; programs recreate what they need.",
    "win_temp": "Windows' own temporary files. Safe to remove (needs administrator).",
    "inet_cache": "Cached web pieces used by Windows and some apps. Safe; they download again if needed.",
    "d3d_cache": "Saved graphics shaders. Safe, but games may stutter briefly the first time afterwards.",
    "thumbs": "Saved picture previews. Safe; Windows rebuilds them, so folders may load a little slower once.",
    "crash": "Crash reports from programs that closed unexpectedly. Safe unless you are troubleshooting a crash.",
    "memdump": "A snapshot Windows saved after a serious crash. Large and safe to remove.",
    "livedump": "Driver crash snapshots. Safe to remove.",
    "wer": "Error reports waiting to be sent to Microsoft. Safe to remove.",
    "wu_download": "Windows Update installers that were already used. Safe to remove (needs administrator).",
    "delivery_opt": "Update pieces Windows shares with other PCs. Safe to remove.",
    "cbs_logs": "Old Windows servicing logs. Safe to remove.",
    "win_root_logs": "Old Windows log files. Safe to remove.",
    "prefetch": "Startup hints older than 30 days. Safe; Windows relearns them.",
    "chkdsk": "Fragments left by disk checks. Safe to remove.",
    "iis_logs": "Old web-server logs. Safe to remove.",
    "office_cache": "Microsoft Office's local file cache. Safe; Office refills it.",
    "defender_hist": "Old Microsoft Defender scan history. Safe to remove.",
    "store_temp": "Temporary files from Microsoft Store apps. Safe to remove.",
    "store_inet": "Cached pieces from Microsoft Store apps. Safe to remove.",
    "electron_cache": "Disposable caches from apps like Discord, Slack and VS Code. Safe; close the app first.",
    "recycle": "Items you already deleted and are still in the Recycle Bin. They can't be restored afterwards.",
    "shortcut": "A shortcut whose program no longer exists, so clicking it does nothing.",
    "shortcut-icon": "A shortcut that still works but whose picture file is missing. Not ticked by default.",
    "leftover": "A program folder with no program inside, usually left by an uninstaller. Check it before removing.",
    "browser-cache": "Saved web pages and images. Safe; sites reload a bit slower once. Close the browser first.",
    "browser-history": "Your list of visited sites. Removing it can't be undone.",
    "browser-cookies": "Site logins and settings. Removing them signs you out of websites.",
    "browser-passwords": "SAVED PASSWORDS. Removing them can't be undone. Leave unticked unless you are sure.",
    "browser-autofill": "Saved addresses and card details used for autofill. Can't be undone.",
    "win-recent": "Lists of recently opened files and programs. Safe; they build up again as you work.",
    "win-reg": "Windows' history lists (Run box, typed paths and similar). Safe.",
    "win-dns": "Windows' memory of website addresses. Safe; it refills instantly.",
    "win-clip": "Whatever you last copied. Not ticked by default.",
    "regapp": "Windows believes a program is installed at a place where it no longer is.",
    "reguninst": "An 'uninstall' entry for a program that is already gone.",
    "regrun": "A startup entry for a program that no longer exists.",
    "regdll": "A note about a shared file that is no longer there.",
    "regfont": "A font listed in Windows whose file is missing.",
    "reghelp": "A help-file location that no longer exists.",
    "regmui": "Windows' remembered name for a program that is gone.",
    "regsound": "A sound setting pointing at a missing sound file.",
    "regsvc": "A Windows service whose program is gone. Not ticked by default; needs administrator.",
    "regcom": "A component registration whose file is gone. Not ticked by default; needs administrator.",
}


def resource_path(rel: str) -> str:
    base = getattr(sys, "_MEIPASS", os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    return os.path.join(base, rel)


def run_bg(widget, fn, done):
    """Run fn on a worker thread; call done(result_or_exception) on the UI thread."""
    def work():
        try:
            res = fn()
        except Exception as e:  # shown in the UI instead of dying silently
            safety.log_action("error", "".join(traceback.format_exception(e))[-1500:])
            res = e
        try:
            widget.after(0, lambda: done(res))
        except RuntimeError:
            pass
    threading.Thread(target=work, daemon=True).start()


def friendly(err: Exception) -> str:
    return f"Something went wrong ({type(err).__name__}). Nothing was changed by this step. Details are saved in {safety.data_dir() / 'actions.log'}."


class Page(ttk.Frame):
    def __init__(self, master, title, blurb):
        super().__init__(master, style="Page.TFrame", padding=20)
        ttk.Label(self, text=title, style="H1.TLabel").pack(anchor="w")
        ttk.Label(self, text=blurb, style="Muted.TLabel", wraplength=740, justify="left").pack(anchor="w", pady=(2, 10))
        self.status = tk.StringVar()
        slot = ttk.Frame(self, style="Page.TFrame", height=10)        # reserves the spot under the heading
        slot.pack(fill="x")
        self.progress = ttk.Progressbar(slot, mode="indeterminate", length=240)
        self.log = tk.Text(self, height=6, bg=brand.PANEL, fg=brand.TEXT, relief="flat", wrap="word", state="disabled")

    def busy(self, on: bool, text: str = ""):
        if on:
            if not self.progress.winfo_manager():
                self.progress.pack(anchor="w", pady=(0, 6))
            self.progress.start(12)
        else:
            self.progress.stop()
            self.progress.pack_forget()
        if text:
            self.status.set(text)

    def say(self, text):
        self.log.configure(state="normal")
        self.log.insert("end", text + "\n")
        self.log.see("end")
        self.log.configure(state="disabled")

    def pack_log(self):
        ttk.Label(self, textvariable=self.status, style="Muted.TLabel", wraplength=740).pack(anchor="w", pady=(8, 2))
        self.log.pack(fill="both", expand=False)


class ScanFixPage(Page):
    """Scan -> read the reason -> tick items -> fix. Used for cleaner, registry, privacy, shortcuts."""

    def __init__(self, master, title, blurb, scan_fn, fix_fn, fix_label="Clean selected", show_size=True):
        super().__init__(master, title, blurb)
        self.scan_fn, self.fix_fn, self.items = scan_fn, fix_fn, []
        bar = ttk.Frame(self, style="Page.TFrame")
        bar.pack(fill="x")
        self.scan_btn = ttk.Button(bar, text="Scan", style="Accent.TButton", command=self.scan)
        self.scan_btn.pack(side="left")
        self.fix_btn = ttk.Button(bar, text=fix_label, command=self.fix, state="disabled")
        self.fix_btn.pack(side="left", padx=8)
        ttk.Button(bar, text="Tick all", command=lambda: self._set_all(True)).pack(side="left")
        ttk.Button(bar, text="Untick all", command=lambda: self._set_all(False)).pack(side="left", padx=4)
        self.ignore_btn = ttk.Button(bar, text="Always skip highlighted", command=self.ignore_selected)
        self.ignore_btn.pack(side="right")
        cols = ("sel", "what", "where") + (("size",) if show_size else ())
        self.tree = ttk.Treeview(self, columns=cols, show="tree headings", height=11)
        self.tree.column("#0", width=26, stretch=False)
        for c, w, t in (("sel", 36, ""), ("what", 300, "What it is"), ("where", 380, "Where"), ("size", 90, "Size")):
            if c in cols:
                self.tree.heading(c, text=t)
                self.tree.column(c, width=w, anchor="w")
        self.tree.pack(fill="both", expand=True, pady=8)
        self.groups: dict[str, list[int]] = {}
        self.tree.bind("<Button-1>", self._toggle)
        self.tree.bind("<<TreeviewSelect>>", self._explain)
        self.why = tk.StringVar(value="Click Scan. Nothing is changed until you click the button next to it and confirm.")
        ttk.Label(self, textvariable=self.why, style="Why.TLabel", wraplength=740, justify="left").pack(anchor="w")
        self.pack_log()

    def _first(self, iid: str):
        return self.items[self.groups[iid][0]] if iid.startswith("g") else self.items[int(iid)]

    def _explain(self, _ev=None):
        sel = self.tree.selection()
        if sel:
            f = self._first(sel[0])
            self.why.set(CATEGORY_HELP.get(f.category, "") + (" Needs administrator." if f.needs_admin else ""))

    def _box(self, idxs: list[int]) -> str:
        ticked = sum(self.items[i].selected for i in idxs)
        return "☑" if ticked == len(idxs) else "☐" if ticked == 0 else "◪"

    def _refresh_boxes(self):
        for gid, idxs in self.groups.items():
            self.tree.set(gid, "sel", self._box(idxs))
            for i in idxs:
                self.tree.set(str(i), "sel", "☑" if self.items[i].selected else "☐")

    def _set_all(self, value: bool):
        for f in self.items:
            f.selected = value
        self._refresh_boxes()

    def _toggle(self, ev):
        if self.tree.identify_region(ev.x, ev.y) != "cell" or self.tree.identify_column(ev.x) != "#1":
            return
        row = self.tree.identify_row(ev.y)
        if not row:
            return
        if row.startswith("g"):
            idxs = self.groups[row]
            new = self._box(idxs) != "☑"
            for i in idxs:
                self.items[i].selected = new
        else:
            f = self.items[int(row)]
            f.selected = not f.selected
        self._refresh_boxes()

    def ignore_selected(self):
        sel = self.tree.selection()
        if not sel:
            return messagebox.showinfo(brand.NAME, "Click a row first, then choose this to always skip it in future scans.")
        picked = [i for iid in sel for i in (self.groups[iid] if iid.startswith("g") else [int(iid)])]
        for i in picked:
            safety.add_ignore(self.items[i].path)
        self.say(f"{len(picked)} item(s) will be skipped from now on. Undo this in Undo & History.")
        self.scan()

    def scan(self):
        self.scan_btn.configure(state="disabled")
        self.busy(True, "Looking… (this only reads, it changes nothing)")
        run_bg(self, self.scan_fn, self._scanned)

    def _scanned(self, res):
        self.scan_btn.configure(state="normal")
        self.busy(False)
        if isinstance(res, Exception):
            self.status.set(friendly(res))
            return
        self.items = res
        self.tree.delete(*self.tree.get_children())
        self.groups = {}
        order: list[str] = []
        for i, f in enumerate(res):
            if f.label not in self.groups:
                order.append(f.label)
            self.groups.setdefault(f.label, []).append(i)
        by_label, self.groups = self.groups, {}
        has_size = "size" in self.tree["columns"]
        for gi, label in enumerate(order):
            idxs, gid = by_label[label], f"g{gi}"
            self.groups[gid] = idxs
            gsize = sum(res[i].size for i in idxs)
            lock = " 🔒" if any(res[i].needs_admin for i in idxs) else ""
            vals = (self._box(idxs), f"{label}  ({len(idxs)})" + lock, "click the arrow to see each one")
            self.tree.insert("", "end", iid=gid, open=False, values=vals + ((fmt_size(gsize) if gsize else "",) if has_size else ()))
            for i in idxs:
                f = res[i]
                v = ("☑" if f.selected else "☐", f.label + (" 🔒" if f.needs_admin else ""), f.path)
                self.tree.insert(gid, "end", iid=str(i), values=v + ((fmt_size(f.size),) if has_size else ()))
        self.why.set("Click a row to see what it is and whether it's safe. Click the arrow on the left to open a group.")
        total = sum(f.size for f in res)
        self.status.set((f"{len(res)} item(s)" + (f", {fmt_size(total)}" if total else "") if res else "Nothing found. This area is clean.")
                        + ("   (🔒 needs administrator: use the button at the bottom-left)" if any(f.needs_admin for f in res) else ""))
        self.fix_btn.configure(state="normal" if res else "disabled")

    def fix(self):
        pick = [f for f in self.items if f.selected]
        if not pick:
            return messagebox.showinfo(brand.NAME, "Nothing is ticked.")
        size = sum(f.size for f in pick)
        if not messagebox.askyesno(brand.NAME, f"Apply to {len(pick)} ticked item(s)" + (f" ({fmt_size(size)})" if size else "") +
                                   "?\n\nRegistry changes are backed up first. Deleted files usually can't be brought back."):
            return
        self.fix_btn.configure(state="disabled")
        self.busy(True, "Working…")
        run_bg(self, lambda: self.fix_fn(pick, False), self._fixed)

    def _fixed(self, res):
        self.busy(False)
        if isinstance(res, Exception):
            self.status.set(friendly(res))
            return
        for p, why in res.skipped[:20]:
            self.say(f"skipped {p}: {why}")
        messagebox.showinfo(brand.NAME, f"Done. {res.removed} item(s) handled, {fmt_size(res.freed)} freed"
                            + (f", {len(res.skipped)} skipped (listed below)." if res.skipped else "."))
        self.scan()


class Dashboard(Page):
    def __init__(self, master):
        super().__init__(master, f"{brand.NAME} AI Mode", "One scan across cleaning, registry, startup, browsers, memory and protection. "
                         "You see the plan, tick what you want, and nothing changes until you click Fix.")
        top = ttk.Frame(self, style="Page.TFrame")
        top.pack(fill="x")
        self.score = tk.StringVar(value="--")
        ttk.Label(top, textvariable=self.score, style="Score.TLabel").pack(side="left")
        self.verdict = tk.StringVar(value="Not scanned yet")
        ttk.Label(top, textvariable=self.verdict, style="H1.TLabel").pack(side="left", padx=16)
        self.disks = ttk.Frame(top, style="Page.TFrame")
        self.disks.pack(side="right")
        bar = ttk.Frame(self, style="Page.TFrame")
        bar.pack(fill="x", pady=6)
        self.scan_btn = ttk.Button(bar, text="Scan my PC", style="Accent.TButton", command=self.scan)
        self.scan_btn.pack(side="left")
        self.fix_btn = ttk.Button(bar, text="Fix ticked items", command=self.fix, state="disabled")
        self.fix_btn.pack(side="left", padx=8)
        self.save_btn = ttk.Button(bar, text="Save report…", command=self.save_report, state="disabled")
        self.save_btn.pack(side="left")
        self.tree = ttk.Treeview(self, columns=("sel", "what", "detail", "pts"), show="headings", height=7)
        for c, w, t in (("sel", 36, ""), ("what", 300, "What I will do"), ("detail", 360, "Details"), ("pts", 70, "Score")):
            self.tree.heading(c, text=t)
            self.tree.column(c, width=w, anchor="w")
        self.tree.pack(fill="x", pady=8)
        self.tree.bind("<Button-1>", self._toggle)
        self.rep, self.chosen = None, []
        self.pack_log()
        self._draw_disks()

    def _draw_disks(self):
        for w in self.disks.winfo_children():
            w.destroy()
        for d in toolbox.disk_summary()[:4]:
            row = ttk.Frame(self.disks, style="Page.TFrame")
            row.pack(anchor="e")
            ttk.Label(row, text=f"{d['drive']}  {fmt_size(d['free'])} free", style="Muted.TLabel", width=22).pack(side="left")
            ttk.Progressbar(row, maximum=100, value=d["percent"], length=110).pack(side="left", pady=1)

    def _toggle(self, ev):
        row = self.tree.identify_row(ev.y)
        if row and self.tree.identify_column(ev.x) == "#1":
            self.chosen[int(row)] = not self.chosen[int(row)]
            self.tree.set(row, "sel", "☑" if self.chosen[int(row)] else "☐")

    def scan(self):
        self.scan_btn.configure(state="disabled")
        self.busy(True, "Scanning…")
        run_bg(self, lambda: ai_mode.analyze(lambda s: self.after(0, self.status.set, f"{s}…")), self._scanned)

    def _scanned(self, rep):
        self.scan_btn.configure(state="normal")
        self.busy(False)
        if isinstance(rep, Exception):
            self.status.set(friendly(rep))
            return
        self.rep = rep
        self.chosen = [True] * len(rep.steps)
        self.score.set(str(rep.score))
        self.verdict.set("Excellent" if rep.score >= 90 else "Good" if rep.score >= 75 else "Needs attention" if rep.score >= 50 else "Poor")
        self.tree.delete(*self.tree.get_children())
        for i, s in enumerate(rep.steps):
            self.tree.insert("", "end", iid=str(i), values=("☑", s.name, s.detail, f"+{s.impact}"))
        self.log.configure(state="normal")
        self.log.delete("1.0", "end")
        self.log.configure(state="disabled")
        for n in rep.notes:
            self.say("• " + n)
        self.status.set("Plan ready. Untick anything you don't want." if rep.steps else "Nothing to fix. Nice.")
        self.fix_btn.configure(state="normal" if rep.steps else "disabled")
        self.save_btn.configure(state="normal")
        self._draw_disks()

    def fix(self):
        steps = [s for s, c in zip(self.rep.steps, self.chosen) if c]
        if not steps:
            return messagebox.showinfo(brand.NAME, "Nothing is ticked.")
        if not messagebox.askyesno(brand.NAME, f"Run {len(steps)} step(s)?\n\nRegistry changes are backed up first, "
                                   "startup items are only switched off (not deleted)."):
            return
        self.fix_btn.configure(state="disabled")
        self.busy(True, "Fixing…")
        picked = ai_mode.Report(steps=steps)
        run_bg(self, lambda: ai_mode.execute(picked, False), self._fixed)

    def _fixed(self, res):
        self.busy(False)
        if isinstance(res, Exception):
            self.status.set(friendly(res))
            return
        for line in res:
            self.say("✓ " + line)
        messagebox.showinfo(brand.NAME, "All done. You can see what changed (and undo it) in Undo & History.")
        self.scan()

    def save_report(self):
        p = filedialog.asksaveasfilename(defaultextension=".txt", initialfile=f"{brand.NAME}-report.txt",
                                         filetypes=[("Text file", "*.txt")])
        if p:
            with open(p, "w", encoding="utf-8") as fh:
                fh.write(report.build_report(self.rep))
            self.say(f"Report saved to {p}")


class HistoryPage(Page):
    def __init__(self, master):
        super().__init__(master, "Undo & History", "Everything PCForge changes is listed here in plain words. "
                         "Use the buttons to put things back.")
        bar = ttk.Frame(self, style="Page.TFrame")
        bar.pack(fill="x")
        ttk.Button(bar, text="Refresh", style="Accent.TButton", command=self.refresh).pack(side="left")
        for text, fn in (("Undo registry cleaning…", self.undo_registry), ("Restore a quarantined file…", self.undo_quarantine),
                         ("Wake paused programs", self.undo_turbo), ("Undo tracking protection", self.undo_hardening),
                         ("Edit skip list…", self.skip_list)):
            ttk.Button(bar, text=text, command=fn).pack(side="left", padx=4)
        self.tree = ttk.Treeview(self, columns=("when", "what", "undo"), show="headings", height=13)
        for c, w, t in (("when", 130, "When"), ("what", 520, "What happened"), ("undo", 110, "Can undo")):
            self.tree.heading(c, text=t)
            self.tree.column(c, width=w, anchor="w")
        self.tree.pack(fill="both", expand=True, pady=8)
        self.pack_log()
        self.refresh()

    def refresh(self):
        self.tree.delete(*self.tree.get_children())
        for i, r in enumerate(history.recent_actions()):
            self.tree.insert("", "end", iid=str(i), values=(r.when, r.text, "yes" if r.undoable else ""))
        self.status.set("Nothing has been changed yet." if not self.tree.get_children() else "")

    def undo_registry(self):
        backs = history.registry_backups()
        if not backs:
            return messagebox.showinfo(brand.NAME, "There are no registry backups yet.")
        newest = backs[0]
        if messagebox.askyesno(brand.NAME, f"Put back the registry entries removed on {newest.name[:8]} at {newest.name[9:11]}:{newest.name[11:13]}?"):
            self.say(f"Restored {history.undo_registry(newest)} backup file(s).")
            self.refresh()

    def undo_quarantine(self):
        items = history.quarantined()
        if not items:
            return messagebox.showinfo(brand.NAME, "No files are in quarantine.")
        it = items[0]
        if messagebox.askyesno(brand.NAME, f"Restore this file to where it was?\n\n{it['original']}"):
            self.say("Restored." if history.restore_quarantined(it) else "Could not restore (something is already at that location).")
            self.refresh()

    def undo_turbo(self):
        self.say(f"Woke {history.undo_turbo()} paused program(s).")

    def undo_hardening(self):
        self.say(f"Undone: {history.undo_hardening()}")
        self.refresh()

    def skip_list(self):
        items = safety.load_ignore()
        if not items:
            return messagebox.showinfo(brand.NAME, "Nothing is on your skip list.")
        if messagebox.askyesno(brand.NAME, "Things currently skipped:\n\n" + "\n".join(items[:12]) + "\n\nClear the whole list?"):
            for i in items:
                safety.remove_ignore(i)
            self.say("Skip list cleared.")


class StartupPage(Page):
    def __init__(self, master):
        super().__init__(master, "Startup Optimizer", "Choose what starts with Windows. Switching something off never deletes it; "
                         "switch it back on any time. Highlight a row, then click the button.")
        self.items = []
        bar = ttk.Frame(self, style="Page.TFrame")
        bar.pack(fill="x")
        ttk.Button(bar, text="Refresh", style="Accent.TButton", command=self.refresh).pack(side="left")
        ttk.Button(bar, text="Switch on/off highlighted", command=self.toggle).pack(side="left", padx=8)
        self.tree = ttk.Treeview(self, columns=("state", "name", "source", "hint"), show="headings", height=14)
        for c, w, t in (("state", 60, "State"), ("name", 280, "Name"), ("source", 160, "Kind"), ("hint", 220, "Suggestion")):
            self.tree.heading(c, text=t)
            self.tree.column(c, width=w)
        self.tree.pack(fill="both", expand=True, pady=8)
        self.pack_log()
        self.refresh()

    def refresh(self):
        self.busy(True, "Reading startup items…")
        run_bg(self, startup.list_startup, self._loaded)

    def _loaded(self, res):
        self.busy(False)
        if isinstance(res, Exception):
            self.status.set(friendly(res))
            return
        self.items = res
        self.tree.delete(*self.tree.get_children())
        for i, it in enumerate(self.items):
            hint = "usually safe to switch off" if it.enabled and it.recommend_disable else ("needs administrator" if it.needs_admin else "")
            self.tree.insert("", "end", iid=str(i), values=("ON" if it.enabled else "off", it.name, it.source, hint))
        self.status.set(f"{sum(1 for i in self.items if i.enabled)} of {len(self.items)} items are on.")

    def toggle(self):
        sel = self.tree.selection()
        if not sel:
            return messagebox.showinfo(brand.NAME, "Click a row first.")
        for iid in sel:
            it = self.items[int(iid)]
            if not startup.set_enabled(it, not it.enabled):
                self.say(f"Couldn't change {it.name}. It may need administrator rights.")
        self.refresh()


class TurboPage(Page):
    def __init__(self, master):
        super().__init__(master, "Turbo Boost", "Pauses background updaters, launchers and sync apps so your game or work gets more power. "
                         "Only your own windowless programs from a safe list. 'Restore' wakes them all.")
        self.mode = tk.StringVar(value="work")
        row = ttk.Frame(self, style="Page.TFrame")
        row.pack(fill="x")
        ttk.Radiobutton(row, text="Work mode", variable=self.mode, value="work").pack(side="left")
        ttk.Radiobutton(row, text="Game mode", variable=self.mode, value="game").pack(side="left", padx=12)
        ttk.Button(row, text="Preview", command=self.preview).pack(side="left", padx=8)
        ttk.Button(row, text="Turn on", style="Accent.TButton", command=self.on).pack(side="left")
        ttk.Button(row, text="Restore", command=self.off).pack(side="left", padx=8)
        self.log.configure(height=12)
        self.pack_log()
        self.status.set(f"{turbo.active_count()} program(s) currently paused")

    def preview(self):
        done = turbo.enable(self.mode.get(), dry_run=True)
        self.say(("Would pause: " + ", ".join(sorted({d['name'] for d in done}))) if done else "Nothing needs pausing right now.")

    def on(self):
        done = turbo.enable(self.mode.get())
        self.say(f"Paused {len(done)} program(s).")
        self.status.set(f"{turbo.active_count()} paused")

    def off(self):
        self.say(f"Woke {turbo.restore()} program(s).")
        self.status.set("0 paused")


class RamPage(Page):
    def __init__(self, master):
        super().__init__(master, "Smart RAM", "Watches memory and asks Windows to move idle memory out of the way when it gets full. Nothing is closed.")
        self.bar = ttk.Progressbar(self, maximum=100, length=420)
        self.bar.pack(anchor="w")
        self.auto = tk.BooleanVar()
        row = ttk.Frame(self, style="Page.TFrame")
        row.pack(fill="x", pady=8)
        ttk.Button(row, text="Free memory now", style="Accent.TButton", command=self.now).pack(side="left")
        ttk.Checkbutton(row, text="Do it automatically above 80%", variable=self.auto, command=self.toggle_auto).pack(side="left", padx=12)
        self.smart = ram.SmartRam(80, on_trim=lambda r: self.after(0, self.say, f"Automatically freed {fmt_size(r['freed'])}"))
        self.log.configure(height=12)
        self.pack_log()
        self.tick()

    def tick(self):
        u = ram.usage()
        self.bar["value"] = u["percent"]
        self.status.set(f"{fmt_size(u['used'])} of {fmt_size(u['total'])} in use ({u['percent']:.0f}%)")
        self.after(2000, self.tick)

    def now(self):
        run_bg(self, ram.trim_working_sets, lambda r: self.say(f"Freed {fmt_size(r['freed'])} from {r['processes']} programs")
               if isinstance(r, dict) else self.say(friendly(r)))

    def toggle_auto(self):
        self.smart.start() if self.auto.get() else self.smart.stop()


class ProtectionPage(Page):
    def __init__(self, master):
        super().__init__(master, "Protection", "Looks for suspicious files, checks links and emails, and watches a folder for tampering. "
                         "It warns you; it does not replace your antivirus. Keep Windows Security or Avast on.")
        self.guard = None
        row = ttk.Frame(self, style="Page.TFrame")
        row.pack(fill="x")
        for text, fn in (("Scan for threats", self.scan), ("Is my antivirus on?", self.av), ("Quick scan with Windows Security", self.dscan)):
            ttk.Button(row, text=text, command=fn).pack(side="left", padx=(0, 8))
        ttk.Label(self, text="Paste a link to check before you click it:", style="Muted.TLabel").pack(anchor="w", pady=(12, 2))
        row2 = ttk.Frame(self, style="Page.TFrame")
        row2.pack(fill="x")
        self.url = tk.StringVar()
        ttk.Entry(row2, textvariable=self.url, width=62).pack(side="left")
        ttk.Button(row2, text="Check link", command=self.check_url).pack(side="left", padx=8)
        ttk.Button(row2, text="Check a saved email (.eml)…", command=self.check_eml).pack(side="left")
        ttk.Button(self, text="Guard a folder against tampering…", command=self.guard_folder).pack(anchor="w", pady=8)
        self.log.configure(height=14)
        self.pack_log()

    def scan(self):
        self.busy(True, "Scanning Downloads, Desktop, Temp and Startup…")
        run_bg(self, lambda: protection.scan_threats() + protection.unsigned_autorun_targets(), self._threats)

    def _threats(self, r):
        self.busy(False)
        if isinstance(r, Exception):
            return self.say(friendly(r))
        self.say(f"{len(r)} thing(s) worth a look. Nothing was changed." if r else "Nothing suspicious found.")
        for f in r:
            self.say(f"[{f.risk}] {f.path}\n      {f.label}")

    def av(self):
        def done(_r):
            names = protection.antivirus_products()
            st = protection.defender_status()
            self.say("Antivirus registered with Windows: " + (", ".join(names) or "none found"))
            self.say(f"Windows Security real-time protection: {'on' if st.get('RealTimeProtectionEnabled') else 'off'}")
        run_bg(self, lambda: None, done)

    def dscan(self):
        self.busy(True, "Windows Security quick scan running… this can take a few minutes")
        run_bg(self, protection.defender_quick_scan, lambda r: (self.busy(False), self.say(str(r) if not isinstance(r, Exception) else friendly(r))))

    def check_url(self):
        r = protection.check_url(self.url.get())
        self.say(f"{self.url.get()}  ->  {r['verdict'].upper()} ({r['score']}/100): " + "; ".join(r["reasons"]))

    def check_eml(self):
        p = filedialog.askopenfilename(filetypes=[("E-mail", "*.eml")])
        if p:
            r = protection.check_eml(p)
            self.say(f"{os.path.basename(p)}  ->  {r['verdict'].upper()} ({r['score']}/100): " + "; ".join(r["reasons"]))

    def guard_folder(self):
        d = filedialog.askdirectory()
        if d:
            if self.guard:
                self.guard.stop()
            self.guard = protection.FolderGuard([d], lambda m: self.after(0, lambda: (self.say("ALERT: " + m), messagebox.showwarning(brand.NAME, m))))
            self.guard.start()
            self.say(f"Now guarding {d}. A hidden decoy file was added; if it is touched you'll get an alert.")


class PrivacyHardenPage(ScanFixPage):
    def __init__(self, master):
        super().__init__(master, "Privacy Sweep", "Browser caches are ticked. History, cookies, passwords and autofill are NOT; tick them only if you mean it. "
                         "Close your browser first.",
                         lambda: privacy.scan_browsers() + privacy.scan_windows_traces(), privacy.sweep, "Sweep ticked items")
        row = ttk.Frame(self, style="Page.TFrame")
        row.pack(fill="x", before=self.tree)
        ttk.Label(row, text="Tracking protection for your browsers:", style="Muted.TLabel").pack(side="left")
        ttk.Button(row, text="Turn on", command=lambda: self.say(f"Firefox profiles: {hardening.apply_firefox()}, "
                                                                f"Chrome/Edge settings: {hardening.apply_chromium()}")).pack(side="left", padx=6)
        ttk.Button(row, text="Turn off", command=lambda: self.say(str(hardening.revert()))).pack(side="left")


class ToolboxPage(Page):
    def __init__(self, master):
        super().__init__(master, "Toolbox", "Find big files, shred a private file, test your internet's DNS speed, update your programs, check Windows health.")
        grid = ttk.Frame(self, style="Page.TFrame")
        grid.pack(fill="x")
        for i, (text, fn) in enumerate((("Find big files", self.large), ("Shred a file…", self.shred), ("Test internet DNS speed", self.dns),
                                        ("Flush DNS", lambda: self.say("Done." if toolbox.flush_dns() else "Failed.")),
                                        ("Check for program updates", self.updates), ("Check Windows health", self.dism),
                                        ("Show disk space", self.disks))):
            ttk.Button(grid, text=text, command=fn).grid(row=i // 3, column=i % 3, sticky="ew", padx=4, pady=4)
        self.log.configure(height=18)
        self.pack_log()

    def large(self):
        self.busy(True, "Searching your user folder for files over 100 MB…")
        run_bg(self, lambda: toolbox.find_large_files([r"C:\Users"], 100, 25),
               lambda r: [self.busy(False), *([self.say(f"{fmt_size(s):>10}  {p}") for s, p in r] if not isinstance(r, Exception) else [self.say(friendly(r))])])

    def shred(self):
        p = filedialog.askopenfilename(title="File to destroy for good")
        if p and messagebox.askyesno(brand.NAME, f"Permanently destroy this file?\n\n{p}\n\nIt cannot be recovered. (On SSDs this is best-effort.)"):
            self.say(("Shredded " if toolbox.shred_file(p, dry_run=False) else "Could not shred ") + p)

    def dns(self):
        self.busy(True, "Testing…")
        run_bg(self, toolbox.dns_benchmark, lambda r: [self.busy(False), *([self.say(f"{l:<12} {ip:<16} {'no answer' if ms is None else f'{ms:.0f} ms'}")
                                                                          for l, ip, ms in r] if not isinstance(r, Exception) else [])])

    def updates(self):
        if not toolbox.winget_available():
            return self.say("The Windows package manager (winget) isn't available on this PC.")
        self.busy(True, "Checking…")
        run_bg(self, toolbox.outdated_software, lambda r: [self.busy(False), *([self.say(f"{x['name']}  {x['version']} -> {x['available']}") for x in r]
                                                                              if not isinstance(r, Exception) else [])])

    def dism(self):
        self.busy(True, "Checking Windows health…")
        run_bg(self, toolbox.dism_check, lambda r: [self.busy(False), self.say(str(r)[-600:])])

    def disks(self):
        for d in toolbox.disk_summary():
            self.say(f"{d['drive']}  {fmt_size(d['free'])} free of {fmt_size(d['total'])}")


class UpdatesPage(Page):
    """Check for a newer PCForge, read what changed, and install it with one click."""

    def __init__(self, master, shared):
        super().__init__(master, "About & Updates", f"You have {brand.NAME} {brand.VERSION}. Updates are checked against a signed list, "
                         "downloaded only over a secure connection, and verified before anything is replaced.")
        self.shared = shared
        shared["page"] = self
        row = ttk.Frame(self, style="Page.TFrame")
        row.pack(fill="x")
        ttk.Button(row, text="Check for updates", style="Accent.TButton", command=self.check).pack(side="left")
        self.install_btn = ttk.Button(row, text="Install update and restart", command=self.install, state="disabled")
        self.install_btn.pack(side="left", padx=8)
        self.skip_btn = ttk.Button(row, text="Skip this version", command=self.skip, state="disabled")
        self.skip_btn.pack(side="left")
        s = settings.load()
        self.auto_check = tk.BooleanVar(value=s["auto_check"])
        self.auto_dl = tk.BooleanVar(value=s["auto_download"])
        ttk.Checkbutton(self, text="Check for updates when PCForge starts (at most once a day; sends no personal information)",
                        variable=self.auto_check, command=lambda: settings.set_("auto_check", self.auto_check.get())).pack(anchor="w", pady=(14, 2))
        ttk.Checkbutton(self, text="Download updates in the background (you still choose when to restart)",
                        variable=self.auto_dl, command=lambda: settings.set_("auto_download", self.auto_dl.get())).pack(anchor="w")
        self.log.configure(height=14)
        self.pack_log()
        if not brand.UPDATE_MANIFEST_URL:
            self.status.set("Updates aren't switched on yet: no update address has been set up for this copy.")
        self.refresh_buttons()

    def refresh_buttons(self):
        have = self.shared.get("info") or self.shared.get("ready")
        self.install_btn.configure(state="normal" if have else "disabled")
        self.skip_btn.configure(state="normal" if self.shared.get("info") else "disabled")

    def check(self):
        self.busy(True, "Checking…")
        run_bg(self, updater.check, self._checked)

    def _checked(self, res):
        self.busy(False)
        if isinstance(res, updater.UpdateError):
            self.status.set(str(res))
        elif isinstance(res, Exception):
            self.status.set(friendly(res))
        elif res is None:
            self.status.set(f"You're up to date ({brand.VERSION}).")
        else:
            self.shared["announce"](res)
            self.status.set(f"Version {res.version} is available ({fmt_size(res.size)}).")
            self.say(f"What's new in {res.version}:\n{res.notes or '(no notes)'}")
        self.refresh_buttons()

    def skip(self):
        info = self.shared.get("info")
        if info:
            settings.set_("skipped_version", info.version)
            self.shared["clear"]()
            self.status.set(f"Okay, version {info.version} will not be offered again.")
            self.refresh_buttons()

    def install(self):
        if not getattr(sys, "frozen", False):
            return messagebox.showinfo(brand.NAME, "You're running PCForge from its source code. Updates install into the packaged PCForge.exe only.")
        if not messagebox.askyesno(brand.NAME, "Install the update now?\n\nPCForge will close, swap in the new version and reopen by itself. "
                                   "Your old version is kept as PCForge.exe.old in case something goes wrong."):
            return
        ready = self.shared.get("ready")
        if ready:
            return self._apply(ready)
        info = self.shared["info"]
        self.busy(True, "Downloading…")
        self.install_btn.configure(state="disabled")

        def prog(got, total):
            self.after(0, self.status.set, f"Downloading… {got * 100 // max(total, 1)}%")
        run_bg(self, lambda: updater.download(info, prog), lambda r: self._downloaded(r))

    def _downloaded(self, res):
        self.busy(False)
        if isinstance(res, Exception):
            self.status.set(str(res) if isinstance(res, updater.UpdateError) else friendly(res))
            return self.refresh_buttons()
        self._apply(res)

    def _apply(self, path):
        try:
            updater.apply_and_restart(path)
        except updater.UpdateError as e:
            return self.status.set(str(e))
        self.status.set("Restarting…")
        self.winfo_toplevel().after(400, self.winfo_toplevel().destroy)


def relaunch_as_admin(root):
    """Restart this program elevated (Windows shows its normal permission prompt)."""
    import ctypes
    exe, params = (sys.executable, "") if getattr(sys, "frozen", False) else (sys.executable, "-m pcforge gui")
    if ctypes.windll.shell32.ShellExecuteW(None, "runas", exe, params, None, 1) > 32:
        root.destroy()


def _welcome(root):
    flag = safety.data_dir() / "welcome_done"
    if flag.exists():
        return
    messagebox.showinfo(f"Welcome to {brand.NAME}",
                        "Three things to know:\n\n"
                        "1. Nothing changes until you click a button AND confirm.\n"
                        "2. Registry fixes are backed up first, and startup items are only switched off, never deleted.\n"
                        "3. Everything is listed in Undo & History.\n\n"
                        "Tip: click 'Run as administrator' (bottom-left) for the most thorough scan.", parent=root)
    flag.write_text("1", encoding="utf-8")


def _install_crash_handler(root):
    def handler(exc, val, tb):
        text = "".join(traceback.format_exception(exc, val, tb))
        safety.log_action("crash", text[-2000:])
        crash = safety.data_dir() / "crash.log"
        crash.write_text(text, encoding="utf-8")
        messagebox.showerror(brand.NAME, f"Something unexpected happened, but nothing was changed by it.\n\nA report was saved to:\n{crash}")
    root.report_callback_exception = handler


def run():
    root = tk.Tk()
    root.title(f"{brand.NAME} {brand.VERSION}" + ("" if is_admin() else "  (not administrator)"))
    root.geometry("1100x720")
    root.minsize(980, 640)
    root.configure(bg=brand.BG)
    try:
        root.iconphoto(True, tk.PhotoImage(file=resource_path(os.path.join("assets", "icon.png"))))
    except tk.TclError:
        pass
    _install_crash_handler(root)
    st = ttk.Style(root)
    st.theme_use("clam")
    st.configure("Page.TFrame", background=brand.BG)
    st.configure("Nav.TFrame", background=brand.PANEL)
    st.configure("H1.TLabel", background=brand.BG, foreground=brand.TEXT, font=("Segoe UI Semibold", 18))
    st.configure("Muted.TLabel", background=brand.BG, foreground=brand.MUTED, font=("Segoe UI", 10))
    st.configure("Why.TLabel", background=brand.BG, foreground=brand.WARN, font=("Segoe UI", 10))
    st.configure("Score.TLabel", background=brand.BG, foreground=brand.ACCENT, font=("Segoe UI Semibold", 44))
    st.configure("TButton", padding=8, background="#252c3b", foreground=brand.TEXT, borderwidth=0, focuscolor="#252c3b")
    st.map("TButton", background=[("active", "#323b4f"), ("disabled", "#1a1f2b")], foreground=[("disabled", "#5b6475")])
    st.configure("Accent.TButton", background=brand.ACCENT, foreground="white", borderwidth=0, focuscolor=brand.ACCENT)
    st.map("Accent.TButton", background=[("active", brand.ACCENT_DARK), ("disabled", "#5a3a1f")], foreground=[("disabled", "#b9a58f")])
    st.configure("Nav.TButton", background=brand.PANEL, foreground=brand.TEXT, anchor="w", padding=(14, 10), borderwidth=0)
    st.map("Nav.TButton", background=[("active", brand.BG)])
    st.configure("TRadiobutton", background=brand.BG, foreground=brand.TEXT)
    st.configure("TCheckbutton", background=brand.BG, foreground=brand.TEXT)
    st.configure("Treeview", background=brand.PANEL, fieldbackground=brand.PANEL, foreground=brand.TEXT, rowheight=26, borderwidth=0)
    st.configure("Treeview.Heading", background=brand.PANEL, foreground=brand.MUTED, relief="flat", borderwidth=0,
                 font=("Segoe UI Semibold", 10), padding=6)
    st.map("Treeview.Heading", background=[("active", "#232a38")])
    st.map("Treeview", background=[("selected", brand.ACCENT_DARK)], foreground=[("selected", "white")])
    st.configure("Vertical.TScrollbar", background="#252c3b", troughcolor=brand.PANEL, borderwidth=0, arrowcolor=brand.MUTED)
    st.configure("Horizontal.TProgressbar", background=brand.ACCENT, troughcolor=brand.PANEL)

    nav = ttk.Frame(root, style="Nav.TFrame", width=210)
    nav.pack(side="left", fill="y")
    ttk.Label(nav, text=brand.NAME, background=brand.PANEL, foreground=brand.ACCENT, font=("Segoe UI Semibold", 16)).pack(padx=14, pady=(16, 2), anchor="w")
    ttk.Label(nav, text=brand.TAGLINE, background=brand.PANEL, foreground=brand.MUTED).pack(padx=14, pady=(0, 14), anchor="w")
    body = ttk.Frame(root, style="Page.TFrame")
    body.pack(side="left", fill="both", expand=True)

    pages = {
        "AI Mode": Dashboard,
        "Junk Cleaner": lambda m: ScanFixPage(m, "Junk Cleaner", "Temp files, caches, crash dumps, update leftovers and the Recycle Bin.", cleaner.scan_junk, cleaner.clean),
        "Registry": lambda m: ScanFixPage(m, "Registry Cleaner", "Entries that point at files which no longer exist. Each one is backed up before it is removed.",
                                          registry_cleaner.scan_registry, registry_cleaner.fix_registry, "Fix ticked items", show_size=False),
        "Shortcuts": lambda m: ScanFixPage(m, "Broken Shortcuts", "Desktop and Start Menu shortcuts whose program or icon is gone.",
                                           cleaner.scan_shortcuts, cleaner.clean_shortcuts, "Delete ticked"),
        "Leftovers": lambda m: ScanFixPage(m, "Leftover Folders", "Program folders with no program inside. Check each one before you delete it.",
                                           cleaner.scan_leftover_folders, cleaner.clean_leftovers, "Delete ticked"),
        "Startup": StartupPage, "Turbo Boost": TurboPage, "Smart RAM": RamPage,
        "Privacy": PrivacyHardenPage, "Protection": ProtectionPage, "Toolbox": ToolboxPage,
        "Undo & History": HistoryPage,
        "About & Updates": lambda m: UpdatesPage(m, shared),
    }
    live: dict[str, ttk.Frame] = {}
    shared: dict = {"info": None, "ready": None, "page": None}
    current: list = []

    # --- "update available" strip across the top of the content area
    banner = tk.Frame(body, bg=brand.ACCENT_DARK)
    banner_text = tk.StringVar()
    tk.Label(banner, textvariable=banner_text, bg=brand.ACCENT_DARK, fg="white", font=("Segoe UI Semibold", 10)).pack(side="left", padx=14, pady=8)
    ttk.Button(banner, text="See details", style="Accent.TButton", command=lambda: show("About & Updates")).pack(side="right", padx=10, pady=4)

    def announce(info, path=None):
        """info = UpdateInfo. With path, the update is already downloaded and verified (ready to install)."""
        shared["info"] = None if path else info
        shared["ready"] = path
        banner_text.set(f"PCForge {info.version} is downloaded: open the details to restart and finish." if path
                        else f"PCForge {info.version} is available.")
        if not banner.winfo_manager():
            banner.pack(fill="x", before=current[0]) if current else banner.pack(fill="x")
        if shared["page"]:
            shared["page"].refresh_buttons()

    def clear():
        shared["info"] = shared["ready"] = None
        banner.pack_forget()

    shared["announce"], shared["clear"] = announce, clear

    def show(name):
        for p in live.values():
            p.pack_forget()
        if name not in live:
            live[name] = pages[name](body)
        elif name == "Undo & History":
            live[name].refresh()
        live[name].pack(fill="both", expand=True)
        current[:] = [live[name]]

    def background_update_check():
        waiting = updater.downloaded_update()          # downloaded earlier but not installed yet
        if waiting:
            announce(updater.UpdateInfo(waiting[0], "", "", 0), path=waiting[1])
            return
        if not (brand.UPDATE_MANIFEST_URL and updater.due()):
            return

        def found(info):
            if isinstance(info, Exception) or info is None or info.version == settings.get("skipped_version"):
                return
            if settings.get("auto_download"):
                run_bg(root, lambda: updater.download(info),
                       lambda p: announce(info) if isinstance(p, Exception) else announce(info, path=p))
            else:
                announce(info)
        run_bg(root, updater.check, found)

    for name in pages:
        ttk.Button(nav, text=name, style="Nav.TButton", command=lambda n=name: show(n)).pack(fill="x")
    if not is_admin():
        ttk.Button(nav, text="Run as administrator", style="Accent.TButton", command=lambda: relaunch_as_admin(root)
                   ).pack(side="bottom", fill="x", padx=10, pady=12)
    show("AI Mode")
    root.after(300, lambda: _welcome(root))
    root.after(2500, background_update_check)
    outcome = updater.last_result()
    if outcome:
        root.after(900, lambda: messagebox.showinfo(brand.NAME, f"PCForge was updated to version {brand.VERSION}." if outcome == "ok"
                                                    else "The update couldn't be installed, so your previous version is still in use."))
    root.mainloop()

#!/usr/bin/env python3
"""Host-side Git + Docker Compose auto-updater daemon for Northstar IT."""

import json
import os
import socket
import subprocess
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.request import urlopen

INSTALL_DIR = Path(os.environ.get("NORTHSTAR_INSTALL_DIR", "/opt/northstar-it"))
RUN_DIR = Path(os.environ.get("NORTHSTAR_UPDATER_RUN", "/run/northstar-updater"))
SOCK_PATH = RUN_DIR / "updater.sock"
STATUS_PATH = RUN_DIR / "status.json"
SOURCE_HINT = INSTALL_DIR / ".source-repo"
GIT_CACHE = INSTALL_DIR / ".git-updater-cache"

_lock = threading.Lock()
_worker = None


def now_iso():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def read_status():
    if STATUS_PATH.exists():
        try:
            return json.loads(STATUS_PATH.read_text(encoding="utf-8"))
        except Exception:
            pass
    return {
        "state": "idle",
        "progress": 0,
        "step": "Idle",
        "message": "Ready to check for updates.",
        "commit": current_commit(),
        "branch": current_branch(),
        "repoUrl": detect_repo_url(),
        "updatedAt": "",
        "logs": [],
        "error": "",
    }


def write_status(**updates):
    with _lock:
        cur = read_status()
        logs = list(cur.get("logs", []))
        log_msg = updates.pop("append_log", None)
        if log_msg:
            logs.append(f"[{time.strftime('%H:%M:%S')}] {log_msg}")
            logs = logs[-80:]
        cur.update(updates)
        cur["logs"] = logs
        cur["timestamp"] = now_iso()
        RUN_DIR.mkdir(parents=True, exist_ok=True)
        tmp = STATUS_PATH.with_suffix(".tmp")
        tmp.write_text(json.dumps(cur, indent=2), encoding="utf-8")
        os.chmod(tmp, 0o644)
        tmp.replace(STATUS_PATH)
        return cur


def run_cmd(cmd, cwd=None, timeout=900):
    proc = subprocess.run(
        cmd,
        cwd=str(cwd) if cwd else None,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        timeout=timeout,
    )
    out = (proc.stdout or "").strip()
    if proc.returncode != 0:
        raise RuntimeError(f"Command {' '.join(cmd)} failed ({proc.returncode}): {out[-1200:]}")
    return out


def repo_dir():
    if SOURCE_HINT.exists():
        hint = SOURCE_HINT.read_text(encoding="utf-8").strip()
        if hint and (Path(hint) / ".git").exists():
            return Path(hint)
    if (INSTALL_DIR / ".git").exists():
        return INSTALL_DIR
    if (GIT_CACHE / ".git").exists():
        return GIT_CACHE
    return None


def safe_git_dir(path: Path):
    try:
        run_cmd(["git", "config", "--global", "--add", "safe.directory", str(path)], timeout=15)
    except Exception:
        pass


def detect_repo_url():
    r = repo_dir()
    if not r:
        return ""
    safe_git_dir(r)
    try:
        return run_cmd(["git", "remote", "get-url", "origin"], cwd=r, timeout=15)
    except Exception:
        return ""


def current_branch():
    r = repo_dir()
    if not r:
        return "main"
    safe_git_dir(r)
    try:
        b = run_cmd(["git", "rev-parse", "--abbrev-ref", "HEAD"], cwd=r, timeout=15)
        return b if b and b != "HEAD" else "main"
    except Exception:
        return "main"


def current_commit():
    r = repo_dir()
    if not r:
        return ""
    safe_git_dir(r)
    try:
        return run_cmd(["git", "rev-parse", "--short", "HEAD"], cwd=r, timeout=15)
    except Exception:
        return ""


def ensure_git_workspace(repo_url="", branch="main"):
    r = repo_dir()
    url = (repo_url or "").strip()
    br = (branch or "main").strip() or "main"
    if not r:
        if not url:
            raise RuntimeError("No Git repository configured. Enter your GitHub HTTPS repository URL in Settings -> Software Update.")
        GIT_CACHE.parent.mkdir(parents=True, exist_ok=True)
        if GIT_CACHE.exists():
            run_cmd(["rm", "-rf", str(GIT_CACHE)], timeout=60)
        run_cmd(["git", "clone", "--branch", br, url, str(GIT_CACHE)], timeout=300)
        SOURCE_HINT.write_text(str(GIT_CACHE), encoding="utf-8")
        r = GIT_CACHE
    safe_git_dir(r)
    if url:
        existing_url = ""
        try:
            existing_url = run_cmd(["git", "remote", "get-url", "origin"], cwd=r, timeout=15)
        except Exception:
            pass
        if existing_url != url:
            if existing_url:
                run_cmd(["git", "remote", "set-url", "origin", url], cwd=r, timeout=15)
            else:
                run_cmd(["git", "remote", "add", "origin", url], cwd=r, timeout=15)
    return r, br


def check_remote(repo_url="", branch="main"):
    r, br = ensure_git_workspace(repo_url, branch)
    run_cmd(["git", "fetch", "origin", br], cwd=r, timeout=120)
    local_sha = run_cmd(["git", "rev-parse", "--short", "HEAD"], cwd=r, timeout=15)
    remote_sha = run_cmd(["git", "rev-parse", "--short", "FETCH_HEAD"], cwd=r, timeout=15)
    behind = run_cmd(["git", "rev-list", "--count", "HEAD..FETCH_HEAD"], cwd=r, timeout=15)
    commits_behind = int(behind or "0")
    summary = ""
    if commits_behind > 0:
        summary = run_cmd(["git", "log", "--oneline", "-n", "5", "HEAD..FETCH_HEAD"], cwd=r, timeout=15)
    return {
        "ok": True,
        "commit": local_sha,
        "remoteCommit": remote_sha,
        "branch": br,
        "repoUrl": detect_repo_url(),
        "commitsBehind": commits_behind,
        "updateAvailable": commits_behind > 0,
        "changes": summary,
    }


def do_update(repo_url="", branch="main"):
    global _worker
    try:
        write_status(
            state="running", progress=10, step="Checking Git repository",
            message="Connecting to Git remote and checking latest version...",
            error="", logs=[], append_log="Starting software update...",
        )
        r, br = ensure_git_workspace(repo_url, branch)
        run_cmd(["git", "fetch", "origin", br], cwd=r, timeout=180)
        before_sha = run_cmd(["git", "rev-parse", "--short", "HEAD"], cwd=r, timeout=15)

        write_status(
            progress=25, step="Pulling latest code",
            message=f"Downloading updates from {br}...",
            append_log=f"Fetched {br} (current commit: {before_sha})",
        )
        run_cmd(["git", "checkout", br], cwd=r, timeout=30)
        try:
            pull_out = run_cmd(["git", "pull", "--ff-only", "origin", br], cwd=r, timeout=180)
        except Exception:
            pull_out = run_cmd(["git", "reset", "--hard", "FETCH_HEAD"], cwd=r, timeout=120)
        after_sha = run_cmd(["git", "rev-parse", "--short", "HEAD"], cwd=r, timeout=15)
        write_status(append_log=f"Repository updated to {after_sha}: {pull_out[:240]}")

        write_status(
            progress=40, step="Syncing files & normalizing scripts",
            message="Applying new files while keeping database, .env & uploads safe...",
        )
        if r.resolve() != INSTALL_DIR.resolve():
            run_cmd([
                "bash", "-c",
                "tar -C \"$1\" --exclude='./.git' --exclude='./.env' --exclude='./secrets' "
                "--exclude='./uploads' --exclude='./backups' --exclude='./__pycache__' -cf - . "
                "| tar -C \"$2\" -xf -",
                "_", str(r), str(INSTALL_DIR),
            ], timeout=120)
        run_cmd(["bash", "-c", "chmod +x \"$1\"/*.sh \"$1\"/northstar-updater.py || true", "_", str(INSTALL_DIR)], timeout=30)

        write_status(
            progress=52, step="Running pre-update safety backup",
            message="Creating database and attachments snapshot before rebuild...",
            append_log="Creating pre-update backup...",
        )
        try:
            run_cmd(["bash", str(INSTALL_DIR / "backup.sh"), "pre-update"], cwd=INSTALL_DIR, timeout=600)
            write_status(append_log="Pre-update backup completed.")
        except Exception as b_err:
            write_status(append_log=f"Backup note: {b_err}")

        write_status(
            progress=68, step="Building updated Docker containers",
            message="Rebuilding app & scanner images with latest code...",
            append_log="Building app and scanner Docker images...",
        )
        run_cmd(["docker", "compose", "build", "app", "scanner"], cwd=INSTALL_DIR, timeout=900)

        write_status(
            progress=85, step="Restarting Northstar containers",
            message="Swapping containers with updated version...",
            append_log="Restarting Docker Compose stack...",
        )
        run_cmd(["docker", "compose", "up", "-d"], cwd=INSTALL_DIR, timeout=300)
        run_cmd(["docker", "compose", "up", "-d", "--force-recreate", "web"], cwd=INSTALL_DIR, timeout=180)

        write_status(
            progress=95, step="Verifying service health",
            message="Waiting for web portal to come online...",
        )
        healthy = False
        for _ in range(30):
            try:
                with urlopen("http://127.0.0.1:18000/api/login-branding", timeout=3) as resp:
                    if resp.status == 200:
                        healthy = True
                        break
            except Exception:
                time.sleep(1.5)

        write_status(
            state="completed",
            progress=100,
            step="Update complete!",
            message=f"Updated cleanly to commit {after_sha}. Refreshing app...",
            commit=after_sha,
            branch=br,
            repoUrl=detect_repo_url(),
            updatedAt=now_iso(),
            error="",
            append_log=f"Update complete ({after_sha}); health={'OK' if healthy else 'timeout'}",
        )
    except Exception as exc:
        write_status(
            state="error",
            step="Update failed",
            message=str(exc)[:300],
            error=str(exc)[:1000],
            append_log=f"ERROR: {exc}",
        )
    finally:
        with _lock:
            _worker = None


def handle_conn(conn):
    try:
        raw = b""
        while True:
            chunk = conn.recv(4096)
            if not chunk:
                break
            raw += chunk
            if b"\n" in raw or len(raw) > 65536:
                break
        req = json.loads(raw.decode("utf-8").strip() or "{}")
        action = req.get("action", "status")
        repo_url = req.get("repoUrl", "")
        branch = req.get("branch", "main")
        if action == "status":
            cur = read_status()
            cur.setdefault("commit", current_commit())
            cur.setdefault("branch", current_branch())
            cur.setdefault("repoUrl", detect_repo_url())
            resp = cur
        elif action == "check":
            info = check_remote(repo_url, branch)
            cur = write_status(commit=info["commit"], branch=info["branch"], repoUrl=info["repoUrl"])
            resp = {**cur, **info}
        elif action == "start":
            global _worker
            with _lock:
                if _worker and _worker.is_alive():
                    resp = {"ok": True, "alreadyRunning": True, **read_status()}
                else:
                    _worker = threading.Thread(target=do_update, args=(repo_url, branch), daemon=True)
                    _worker.start()
                    resp = {"ok": True, "started": True, **read_status()}
        else:
            resp = {"ok": False, "error": "Unsupported updater action."}
    except Exception as exc:
        resp = {"ok": False, "error": str(exc)}
    try:
        conn.sendall((json.dumps(resp) + "\n").encode("utf-8"))
    except Exception:
        pass
    finally:
        conn.close()


def main():
    RUN_DIR.mkdir(parents=True, exist_ok=True)
    os.chmod(RUN_DIR, 0o755)
    if SOCK_PATH.exists():
        SOCK_PATH.unlink()
    write_status(
        state="idle", progress=0, step="Idle",
        message="Updater service ready.",
        commit=current_commit(), branch=current_branch(), repoUrl=detect_repo_url(),
    )
    srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    srv.bind(str(SOCK_PATH))
    os.chmod(SOCK_PATH, 0o666)
    srv.listen(16)
    while True:
        conn, _ = srv.accept()
        threading.Thread(target=handle_conn, args=(conn,), daemon=True).start()


if __name__ == "__main__":
    main()

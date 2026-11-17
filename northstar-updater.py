#!/usr/bin/env python3
"""Host-side Git + Docker Compose auto-updater daemon for Northstar IT."""

import ipaddress
import json
import os
import re
import shutil
import socket
import subprocess
import tempfile
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


_HOST_TOKEN_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$")
HOST_NGINX_CONF = Path("/etc/nginx/conf.d/northstar-shree.conf")


def _parse_site_tokens(site_name):
    tokens = []
    for part in re.split(r"[\s,]+", str(site_name or "")):
        p = part.strip().lower().strip(".")
        if not p:
            continue
        if "://" in p:
            p = p.split("://", 1)[1]
        p = p.split("/", 1)[0].split("?", 1)[0].split(":", 1)[0].strip(".")
        if not p:
            continue
        try:
            ipaddress.ip_address(p)
            continue
        except ValueError:
            pass
        if _HOST_TOKEN_RE.match(p):
            tokens.append(p)
    tokens = list(dict.fromkeys(tokens))
    mdns_hosts = []
    short_names = []
    for tok in tokens:
        lbl = tok.split(".")[0]
        if tok.endswith(".local"):
            mdns_hosts.append(tok)
        elif lbl and lbl not in ("localhost", "www"):
            mdns_hosts.append(f"{lbl}.local")
        if lbl and len(lbl) >= 2 and lbl not in ("localhost", "www"):
            short_names.append(lbl)
    return tokens, list(dict.fromkeys(mdns_hosts)), list(dict.fromkeys(short_names))


def _detect_server_lan_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        if ip and not ip.startswith("127.") and not ip.startswith("172.17."):
            return ip
    except OSError:
        pass
    try:
        out = subprocess.check_output(["hostname", "-I"], text=True, timeout=3)
        for tok in out.split():
            if re.match(r"^\d+\.\d+\.\d+\.\d+$", tok) and not tok.startswith("127.") and not tok.startswith("172.17."):
                return tok
    except Exception:
        pass
    return ""


def _all_server_lan_ips():
    ips = []
    try:
        out = subprocess.check_output(["hostname", "-I"], text=True, timeout=3)
        for tok in out.split():
            if re.match(r"^\d+\.\d+\.\d+\.\d+$", tok) and not tok.startswith("127."):
                ips.append(tok)
    except Exception:
        pass
    primary = _detect_server_lan_ip()
    if primary and primary not in ips:
        ips.insert(0, primary)
    return list(dict.fromkeys(ips))


def _update_managed_hosts_block(path_obj, lines_to_add):
    if not path_obj.parent.exists():
        return False
    begin_marker = "# BEGIN NORTHSTAR-MANAGED"
    end_marker = "# END NORTHSTAR-MANAGED"
    existing = ""
    if path_obj.exists():
        existing = path_obj.read_text(encoding="utf-8", errors="ignore")
    out_lines = []
    in_block = False
    for line in existing.splitlines():
        s = line.strip()
        if s == begin_marker:
            in_block = True
            continue
        if s == end_marker:
            in_block = False
            continue
        if not in_block:
            out_lines.append(line)
    while out_lines and not out_lines[-1].strip():
        out_lines.pop()
    if lines_to_add:
        out_lines.append("")
        out_lines.append(begin_marker)
        out_lines.extend(lines_to_add)
        out_lines.append(end_marker)
    content = "\n".join(out_lines) + "\n"
    tmp = path_obj.with_suffix(path_obj.suffix + ".northstar.tmp")
    tmp.write_text(content, encoding="utf-8")
    os.chmod(tmp, 0o644)
    tmp.replace(path_obj)
    return True


def _sync_avahi_and_etc_hosts(tokens, mdns_hosts, short_names):
    lan_ip = _detect_server_lan_ip()
    if not lan_ip:
        return False
    avahi_updated = False
    avahi_hosts = Path("/etc/avahi/hosts")
    if Path("/etc/avahi").is_dir():
        try:
            entries = [f"{lan_ip} {h}" for h in mdns_hosts]
            _update_managed_hosts_block(avahi_hosts, entries)
            for cmd in (["systemctl", "reload", "avahi-daemon"], ["avahi-daemon", "-r"]):
                try:
                    run_cmd(cmd, timeout=10)
                    break
                except Exception:
                    pass
            avahi_updated = True
        except Exception:
            pass
    try:
        all_etc = list(dict.fromkeys(tokens + mdns_hosts + short_names))
        etc_entries = [f"{lan_ip} {' '.join(all_etc)}"] if all_etc else []
        _update_managed_hosts_block(Path("/etc/hosts"), etc_entries)
    except Exception:
        pass
    return avahi_updated


def _regenerate_leaf_cert(app_fqdn, tokens, mdns_hosts, short_names):
    secrets_dir = INSTALL_DIR / "secrets"
    ca_crt = secrets_dir / "ca.crt"
    ca_key = secrets_dir / "ca.key"
    nginx_crt = secrets_dir / "nginx.crt"
    nginx_key = secrets_dir / "nginx.key"
    if not (ca_crt.is_file() and ca_key.is_file() and shutil.which("openssl")):
        return False
    sans = []
    if app_fqdn:
        try:
            ipaddress.ip_address(app_fqdn)
            sans.append(f"IP:{app_fqdn}")
        except ValueError:
            sans.append(f"DNS:{app_fqdn}")
    sans.extend(["DNS:localhost", "IP:127.0.0.1"])
    for ip in _all_server_lan_ips():
        sans.append(f"IP:{ip}")
    for h in list(dict.fromkeys(tokens + mdns_hosts + short_names)):
        sans.append(f"DNS:{h}")
    san_line = ",".join(dict.fromkeys(sans))
    tmp_dir = Path(tempfile.mkdtemp(prefix="ns-cert-"))
    try:
        if not nginx_key.is_file() or nginx_key.stat().st_size == 0:
            run_cmd(["openssl", "genrsa", "-out", str(nginx_key), "2048"], timeout=30)
            os.chmod(nginx_key, 0o600)
        csr = tmp_dir / "server.csr"
        ext = tmp_dir / "leaf.ext"
        leaf = tmp_dir / "leaf.crt"
        cn = (tokens[0] if tokens else app_fqdn or "localhost")[:64]
        run_cmd(["openssl", "req", "-new", "-key", str(nginx_key), "-out", str(csr), "-subj", f"/CN={cn}/O=Shree IT"], timeout=20)
        ext.write_text(
            "basicConstraints=critical,CA:FALSE\n"
            "keyUsage=critical,digitalSignature,keyEncipherment\n"
            "extendedKeyUsage=serverAuth\n"
            "subjectKeyIdentifier=hash\n"
            "authorityKeyIdentifier=keyid,issuer\n"
            f"subjectAltName={san_line}\n",
            encoding="utf-8",
        )
        run_cmd([
            "openssl", "x509", "-req", "-in", str(csr),
            "-CA", str(ca_crt), "-CAkey", str(ca_key), "-CAcreateserial",
            "-out", str(leaf), "-days", "365", "-sha256", "-extfile", str(ext),
        ], timeout=20)
        fullchain = leaf.read_text(encoding="utf-8") + ca_crt.read_text(encoding="utf-8")
        tmp_crt = secrets_dir / "nginx.crt.tmp"
        tmp_crt.write_text(fullchain, encoding="utf-8")
        os.chmod(tmp_crt, 0o644)
        tmp_crt.replace(nginx_crt)
        srl = secrets_dir / "ca.srl"
        if srl.exists():
            srl.unlink()
        return True
    except Exception:
        return False
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)


def regenerate_fresh_root_ca_and_leaf(site_name=""):
    if not shutil.which("openssl"):
        return {"ok": False, "error": "openssl is not available on this host."}
    secrets_dir = INSTALL_DIR / "secrets"
    secrets_dir.mkdir(parents=True, exist_ok=True)
    ca_crt = secrets_dir / "ca.crt"
    ca_key = secrets_dir / "ca.key"
    ca_crt_tmp = secrets_dir / "ca.crt.tmp"
    ca_key_tmp = secrets_dir / "ca.key.tmp"
    try:
        run_cmd([
            "openssl", "req", "-x509", "-nodes", "-days", "3650", "-newkey", "rsa:2048",
            "-keyout", str(ca_key_tmp), "-out", str(ca_crt_tmp),
            "-subj", "/CN=Shree IT Root CA/O=Shree IT Asset Intelligence",
            "-addext", "basicConstraints=critical,CA:TRUE,pathlen:0",
            "-addext", "keyUsage=critical,keyCertSign,cRLSign",
            "-addext", "subjectKeyIdentifier=hash",
        ], timeout=30)
        os.chmod(ca_key_tmp, 0o600)
        os.chmod(ca_crt_tmp, 0o644)
        ca_key_tmp.replace(ca_key)
        ca_crt_tmp.replace(ca_crt)
    except Exception as exc:
        for f in (ca_crt_tmp, ca_key_tmp):
            if f.exists():
                f.unlink()
        return {"ok": False, "error": str(exc)[:200]}

    env_file = INSTALL_DIR / ".env"
    lines = env_file.read_text(encoding="utf-8").splitlines() if env_file.exists() else []
    app_fqdn, env_site, http_port = "", site_name, 8848
    for line in lines:
        s = line.strip()
        if s.startswith("APP_FQDN="):
            app_fqdn = _unquote_env(s.split("=", 1)[1])
        elif s.startswith("SITE_NAME=") and not env_site:
            env_site = _unquote_env(s.split("=", 1)[1])
        elif s.startswith("HTTP_PORT="):
            try:
                http_port = int(_unquote_env(s.split("=", 1)[1]))
            except ValueError:
                pass
    tokens, mdns_hosts, short_names = _parse_site_tokens(env_site)
    leaf_ok = _regenerate_leaf_cert(app_fqdn, tokens, mdns_hosts, short_names)
    if not leaf_ok:
        return {"ok": False, "error": "Root CA created, but leaf certificate generation failed."}
    host_nginx = _configure_host_nginx(tokens, mdns_hosts, short_names, http_port)
    reloaded = False
    try:
        run_cmd(["docker", "compose", "exec", "-T", "web", "nginx", "-s", "reload"], cwd=INSTALL_DIR, timeout=30)
        reloaded = True
    except Exception:
        try:
            run_cmd(["docker", "compose", "kill", "-s", "HUP", "web"], cwd=INSTALL_DIR, timeout=30)
            reloaded = True
        except Exception:
            pass
    return {
        "ok": True,
        "reloaded": reloaded,
        "hostNginxApplied": bool(host_nginx.get("applied")),
        "message": "Fresh Root CA & 365-day Server SSL Certificate generated and reloaded cleanly!",
    }


def _host_nginx_is_active():
    if not Path("/etc/nginx").is_dir() or not shutil.which("nginx"):
        return False
    for cmd in (["systemctl", "is-active", "--quiet", "nginx"], ["pgrep", "-x", "nginx"]):
        try:
            proc = subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=3)
            if proc.returncode == 0:
                return True
        except Exception:
            pass
    return False


def _iter_other_nginx_files():
    files = []
    for folder in (Path("/etc/nginx/conf.d"), Path("/etc/nginx/sites-enabled")):
        if not folder.is_dir():
            continue
        for p in sorted(folder.iterdir()):
            if p.resolve() == HOST_NGINX_CONF.resolve() if HOST_NGINX_CONF.exists() else p == HOST_NGINX_CONF:
                continue
            if p.name == HOST_NGINX_CONF.name:
                continue
            if p.is_file():
                files.append(p)
    return files


def _claimed_other_nginx_server_names():
    claimed = set()
    for p in _iter_other_nginx_files():
        try:
            txt = p.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        clean_lines = [line.split("#", 1)[0] for line in txt.splitlines()]
        joined = " ".join(clean_lines)
        for m in re.finditer(r"\bserver_name\s+([^;]+);", joined):
            for tok in m.group(1).split():
                t = tok.strip().lower()
                if t and t not in ("_", "localhost"):
                    claimed.add(t)
    return claimed


def _cert_covers_domains(cert_path, domains):
    if not domains or not shutil.which("openssl"):
        return False
    try:
        out = subprocess.check_output(
            ["openssl", "x509", "-in", str(cert_path), "-noout", "-ext", "subjectAltName"],
            text=True, stderr=subprocess.DEVNULL, timeout=5,
        )
    except Exception:
        return False
    sans = [m.group(1).strip().lower() for m in re.finditer(r"DNS:([^\s,]+)", out)]
    if not sans:
        return False
    for d in domains:
        d = d.lower()
        ok = False
        for s in sans:
            if s == d:
                ok = True
                break
            if s.startswith("*.") and d.count(".") == s.count(".") and d.endswith(s[1:]):
                ok = True
                break
        if ok:
            return True
    return False


def _find_matching_host_ssl_cert(domains):
    pairs = []
    le_dir = Path("/etc/letsencrypt/live")
    if le_dir.is_dir():
        for d in sorted(le_dir.iterdir()):
            crt = d / "fullchain.pem"
            key = d / "privkey.pem"
            if crt.is_file() and key.is_file():
                pairs.append((crt, key))
    for p in _iter_other_nginx_files():
        try:
            txt = p.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        certs = re.findall(r"^\s*ssl_certificate\s+([^;\s]+)\s*;", txt, re.M)
        keys = re.findall(r"^\s*ssl_certificate_key\s+([^;\s]+)\s*;", txt, re.M)
        for c_str, k_str in zip(certs, keys):
            c_path, k_path = Path(c_str), Path(k_str)
            if c_path.is_file() and k_path.is_file():
                pairs.append((c_path, k_path))
    for crt, key in pairs:
        if _cert_covers_domains(crt, domains):
            return str(crt), str(key), "trusted-host-cert"
    return str(INSTALL_DIR / "secrets" / "nginx.crt"), str(INSTALL_DIR / "secrets" / "nginx.key"), "self-signed"


def _configure_host_nginx(tokens, mdns_hosts, short_names, http_port):
    if not _host_nginx_is_active():
        return {"active": False, "applied": False, "domains": [], "certType": ""}
    claimed = _claimed_other_nginx_server_names()
    candidates = [d for d in dict.fromkeys(tokens + mdns_hosts + short_names) if d not in claimed]
    prev_exists = HOST_NGINX_CONF.exists()
    prev_text = HOST_NGINX_CONF.read_text(encoding="utf-8", errors="ignore") if prev_exists else None

    if not candidates:
        if prev_exists:
            try:
                HOST_NGINX_CONF.unlink()
                run_cmd(["nginx", "-t"], timeout=15)
                run_cmd(["systemctl", "reload", "nginx"], timeout=15)
            except Exception:
                if prev_text is not None:
                    HOST_NGINX_CONF.write_text(prev_text, encoding="utf-8")
        return {"active": True, "applied": False, "domains": [], "certType": ""}

    cert_path, key_path, cert_type = _find_matching_host_ssl_cert(tokens or candidates)
    has_ssl = Path(cert_path).is_file() and Path(key_path).is_file()
    server_line = " ".join(candidates)
    ssl_block = (
        f"    listen 443 ssl;\n"
        f"    ssl_certificate {cert_path};\n"
        f"    ssl_certificate_key {key_path};\n"
        f"    ssl_protocols TLSv1.2 TLSv1.3;\n"
    ) if has_ssl else ""
    conf = (
        "# Auto-managed by Shree IT (northstar-updater). Existing host Nginx configs are untouched.\n"
        "server {\n"
        "    listen 80;\n"
        f"{ssl_block}"
        f"    server_name {server_line};\n\n"
        "    client_max_body_size 1g;\n"
        "    client_body_timeout 3600s;\n\n"
        "    location ~ ^/api/(public/)?live-stream$ {\n"
        f"        proxy_pass http://127.0.0.1:{http_port};\n"
        "        proxy_http_version 1.1;\n"
        "        proxy_buffering off;\n"
        "        proxy_cache off;\n"
        "        chunked_transfer_encoding off;\n"
        '        proxy_set_header Connection "";\n'
        "        proxy_set_header Host $http_host;\n"
        "        proxy_set_header X-Forwarded-Host $http_host;\n"
        "        proxy_set_header X-Real-IP $remote_addr;\n"
        "        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;\n"
        "        proxy_set_header X-Forwarded-Proto $scheme;\n"
        "        proxy_read_timeout 3600s;\n"
        "        proxy_send_timeout 3600s;\n"
        "    }\n\n"
        "    location / {\n"
        f"        proxy_pass http://127.0.0.1:{http_port};\n"
        "        proxy_http_version 1.1;\n"
        "        proxy_set_header Upgrade $http_upgrade;\n"
        '        proxy_set_header Connection "upgrade";\n'
        "        proxy_set_header Host $http_host;\n"
        "        proxy_set_header X-Forwarded-Host $http_host;\n"
        "        proxy_set_header X-Real-IP $remote_addr;\n"
        "        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;\n"
        "        proxy_set_header X-Forwarded-Proto $scheme;\n"
        "        proxy_read_timeout 3600s;\n"
        "        proxy_send_timeout 3600s;\n"
        "    }\n"
        "}\n"
    )
    try:
        HOST_NGINX_CONF.parent.mkdir(parents=True, exist_ok=True)
        HOST_NGINX_CONF.write_text(conf, encoding="utf-8")
        run_cmd(["nginx", "-t"], timeout=15)
        run_cmd(["systemctl", "reload", "nginx"], timeout=15)
        return {"active": True, "applied": True, "domains": candidates, "certType": cert_type if has_ssl else "http-only"}
    except Exception as exc:
        if prev_text is not None:
            HOST_NGINX_CONF.write_text(prev_text, encoding="utf-8")
        elif HOST_NGINX_CONF.exists():
            HOST_NGINX_CONF.unlink()
        return {"active": True, "applied": False, "domains": [], "certType": "", "error": str(exc)[:200]}


def _unquote_env(v):
    v = v.strip()
    if len(v) >= 2 and ((v[0] == "'" and v[-1] == "'") or (v[0] == '"' and v[-1] == '"')):
        return v[1:-1]
    return v


def _host_nginx_status():
    active = _host_nginx_is_active()
    domains = []
    if HOST_NGINX_CONF.exists():
        txt = HOST_NGINX_CONF.read_text(encoding="utf-8", errors="ignore")
        m = re.search(r"\bserver_name\s+([^;]+);", txt)
        if m:
            domains = m.group(1).split()
    return {
        "ok": True,
        "serverLanIp": _detect_server_lan_ip(),
        "hostNginxActive": active,
        "hostNginxApplied": bool(active and domains),
        "hostNginxDomains": domains,
        "avahiActive": Path("/etc/avahi/hosts").exists(),
    }


def apply_network_config(site_name, http_port, https_port):
    tokens, mdns_hosts, short_names = _parse_site_tokens(site_name)
    clean_site_name = " ".join(tokens)

    env_file = INSTALL_DIR / ".env"
    if not env_file.exists() and Path(".env").exists():
        env_file = Path(".env")
    lines = env_file.read_text(encoding="utf-8").splitlines() if env_file.exists() else []
    old_http_port, old_https_port, app_fqdn = 8848, 8849, ""
    for line in lines:
        s = line.strip()
        if s.startswith("HTTP_PORT="):
            try:
                old_http_port = int(_unquote_env(s.split("=", 1)[1]))
            except ValueError:
                pass
        elif s.startswith("HTTPS_PORT="):
            try:
                old_https_port = int(_unquote_env(s.split("=", 1)[1]))
            except ValueError:
                pass
        elif s.startswith("APP_FQDN="):
            app_fqdn = _unquote_env(s.split("=", 1)[1])

    keys_set = set()
    new_lines = []
    for line in lines:
        stripped = line.strip()
        if stripped.startswith("HTTP_PORT="):
            new_lines.append(f"HTTP_PORT={http_port}")
            keys_set.add("HTTP_PORT")
        elif stripped.startswith("HTTPS_PORT="):
            new_lines.append(f"HTTPS_PORT={https_port}")
            keys_set.add("HTTPS_PORT")
        elif stripped.startswith("SITE_NAME="):
            new_lines.append(f"SITE_NAME='{clean_site_name}'")
            keys_set.add("SITE_NAME")
        else:
            new_lines.append(line)
    if "HTTP_PORT" not in keys_set:
        new_lines.append(f"HTTP_PORT={http_port}")
    if "HTTPS_PORT" not in keys_set:
        new_lines.append(f"HTTPS_PORT={https_port}")
    if "SITE_NAME" not in keys_set:
        new_lines.append(f"SITE_NAME='{clean_site_name}'")
    try:
        tmp_env = env_file.with_suffix(".tmp")
        tmp_env.write_text("\n".join(new_lines) + "\n", encoding="utf-8")
        tmp_env.replace(env_file)
    except Exception:
        pass

    for rule in (f"{http_port}/tcp", f"{https_port}/tcp", "5353/udp", "5355/udp", "137/udp"):
        try:
            run_cmd(["ufw", "allow", rule], timeout=10)
        except Exception:
            pass

    _regenerate_leaf_cert(app_fqdn, tokens, mdns_hosts, short_names)
    avahi_updated = _sync_avahi_and_etc_hosts(tokens, mdns_hosts, short_names)
    host_nginx = _configure_host_nginx(tokens, mdns_hosts, short_names, http_port)
    lan_ip = _detect_server_lan_ip()

    ports_changed = (old_http_port != http_port) or (old_https_port != https_port)
    reloaded_web = False
    if ports_changed:
        # Recreate web container asynchronously after HTTP response flushes so the caller does not hit a 502 drop.
        def _bg_recreate_web():
            time.sleep(1.2)
            try:
                run_cmd(["docker", "compose", "up", "-d", "--force-recreate", "web"], cwd=INSTALL_DIR, timeout=120)
            except Exception:
                pass
        threading.Thread(target=_bg_recreate_web, daemon=True).start()
        reloaded_web = True
    else:
        try:
            run_cmd(["docker", "compose", "exec", "-T", "web", "nginx", "-s", "reload"], cwd=INSTALL_DIR, timeout=30)
            reloaded_web = True
        except Exception:
            try:
                run_cmd(["docker", "compose", "kill", "-s", "HUP", "web"], cwd=INSTALL_DIR, timeout=30)
                reloaded_web = True
            except Exception:
                pass

    parts = [f"HTTP {http_port} / HTTPS {https_port} {'scheduled for reload' if ports_changed else ('reloaded cleanly' if reloaded_web else 'saved')}"]
    if host_nginx.get("applied"):
        parts.append(f"Host Nginx Port 80/443 virtual host active for {', '.join(host_nginx['domains'])} ({host_nginx['certType']})")
    if avahi_updated:
        parts.append(f"LAN mDNS (.local) publishing -> {lan_ip}")

    return {
        "ok": True,
        "siteName": clean_site_name,
        "httpPort": http_port,
        "httpsPort": https_port,
        "recreated": reloaded_web,
        "serverLanIp": lan_ip,
        "avahiUpdated": avahi_updated,
        "hostNginxActive": bool(host_nginx.get("active")),
        "hostNginxApplied": bool(host_nginx.get("applied")),
        "hostNginxDomains": host_nginx.get("domains") or [],
        "hostNginxCertType": str(host_nginx.get("certType") or ""),
        "message": " | ".join(parts),
    }


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
        elif action == "set_network_config":
            site_name = str(req.get("siteName") or "").strip()[:120]
            try:
                http_port = int(req.get("httpPort") or 8848)
                https_port = int(req.get("httpsPort") or 8849)
            except Exception:
                http_port, https_port = 8848, 8849
            resp = apply_network_config(site_name, http_port, https_port)
        elif action == "get_network_status":
            resp = _host_nginx_status()
        elif action == "regenerate_ssl":
            resp = regenerate_fresh_root_ca_and_leaf(str(req.get("siteName") or "").strip()[:120])
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

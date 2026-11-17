"""Host-network scanner companion for the Northstar on-premise application."""
import concurrent.futures
import datetime
from email.message import EmailMessage
import ipaddress
import json
import os
import platform
import re
import smtplib
import ssl
import socket
import struct
import subprocess
import threading
import time
import urllib.error
import urllib.request


BASE_URL = os.getenv("SCANNER_URL", "http://127.0.0.1:8000").rstrip("/")
TOKEN = os.getenv("APP_SECRET", "")
POLL_SECONDS = 2
SNMP_COUNTERS = {}

_LAN_NAME_LOCK = threading.Lock()
_LAN_NAMES = {"mdns": set(), "llmnr": set()}
_HOST_TOKEN_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*$")


def update_lan_hostnames(raw_site_name):
    mdns_set = set()
    llmnr_set = set()
    combined = f"{raw_site_name or ''} {os.getenv('APP_FQDN', '')}"
    for part in re.split(r"[\s,]+", combined):
        tok = part.strip().lower().strip(".")
        if not tok or not _HOST_TOKEN_RE.match(tok):
            continue
        try:
            ipaddress.ip_address(tok)
            continue
        except ValueError:
            pass
        if tok in ("localhost", "www", "http", "https"):
            continue
        first_label = tok.split(".")[0]
        if tok.endswith(".local"):
            mdns_set.add(tok)
            if first_label and len(first_label) >= 2 and first_label not in ("localhost",):
                llmnr_set.add(first_label)
        elif "." not in tok:
            llmnr_set.add(tok)
            mdns_set.add(f"{tok}.local")
        else:
            llmnr_set.add(tok)
            if first_label and len(first_label) >= 2 and first_label not in ("localhost", "www"):
                llmnr_set.add(first_label)
                mdns_set.add(f"{first_label}.local")
    with _LAN_NAME_LOCK:
        changed = (mdns_set != _LAN_NAMES["mdns"]) or (llmnr_set != _LAN_NAMES["llmnr"])
        _LAN_NAMES["mdns"] = mdns_set
        _LAN_NAMES["llmnr"] = llmnr_set
    if changed and (mdns_set or llmnr_set):
        print(f"LAN Zero-Config responder active -> mDNS: {sorted(mdns_set)} | LLMNR/NetBIOS: {sorted(llmnr_set)}", flush=True)


def _get_lan_ipv4s():
    ips = []
    if platform.system().lower() != "windows":
        try:
            res = subprocess.run(["ip", "-o", "-4", "addr", "show", "up"], capture_output=True, text=True, timeout=3, check=False)
            for line in res.stdout.splitlines():
                m = re.search(r"\binet\s+(\d+\.\d+\.\d+\.\d+)/", line)
                if m:
                    ip = m.group(1)
                    if not ip.startswith("127.") and not ip.startswith("169.254.") and not ip.startswith("172.17."):
                        ips.append(ip)
        except Exception:
            pass
    if not ips:
        try:
            for ip in socket.gethostbyname_ex(socket.gethostname())[2]:
                if not ip.startswith("127.") and not ip.startswith("169.254."):
                    ips.append(ip)
        except OSError:
            pass
    return list(dict.fromkeys(ips))


def _pick_lan_ip_for_peer(peer_ip):
    for target in (peer_ip, "8.8.8.8"):
        if not target:
            continue
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect((target, 9))
            ip = s.getsockname()[0]
            s.close()
            if ip and not ip.startswith("127.") and not ip.startswith("169.254."):
                return ip
        except OSError:
            pass
    ips = _get_lan_ipv4s()
    return ips[0] if ips else ""


def _encode_dns_name(name):
    out = bytearray()
    for part in name.strip(".").split("."):
        if part:
            b = part.encode("idna")[:63]
            out.append(len(b))
            out.extend(b)
    out.append(0)
    return bytes(out)


def _decode_dns_name(packet, offset):
    labels = []
    jumped = False
    orig_offset = offset
    seen = 0
    n = len(packet)
    while offset < n and seen < 32:
        seen += 1
        length = packet[offset]
        if length == 0:
            offset += 1
            break
        if (length & 0xC0) == 0xC0:
            if offset + 1 >= n:
                return None, orig_offset
            ptr = ((length & 0x3F) << 8) | packet[offset + 1]
            if not jumped:
                orig_offset = offset + 2
                jumped = True
            offset = ptr
            continue
        if (length & 0xC0) != 0:
            return None, orig_offset
        offset += 1
        if offset + length > n:
            return None, orig_offset
        labels.append(packet[offset:offset + length].decode("utf-8", errors="ignore"))
        offset += length
    return ".".join(labels).lower(), (orig_offset if jumped else offset)


def _build_dns_response(packet, peer_addr, mode):
    if len(packet) < 12:
        return None
    txid, flags, qdcount, _ancount, nscount, _arcount = struct.unpack("!HHHHHH", packet[:12])
    if flags & 0x8000:  # Response packet
        return None
    if mode == "mdns" and nscount > 0:  # Ignore RFC 6762 startup probes
        return None
    if qdcount == 0 or qdcount > 8:
        return None

    with _LAN_NAME_LOCK:
        active = set(_LAN_NAMES.get(mode, ()))
    if not active:
        return None

    offset = 12
    matched = None
    for _ in range(qdcount):
        q_start = offset
        qname, q_end = _decode_dns_name(packet, offset)
        if not qname or q_end + 4 > len(packet):
            return None
        qtype, qclass = struct.unpack("!HH", packet[q_end:q_end + 4])
        offset = q_end + 4
        cls = qclass & 0x7FFF
        if qtype in (1, 255) and cls in (1, 255) and qname in active:
            matched = (qname, qtype, cls, bool(qclass & 0x8000))
            break

    if not matched:
        return None
    qname, m_qtype, m_cls, is_qu = matched
    lan_ip = _pick_lan_ip_for_peer(peer_addr[0])
    if not lan_ip:
        return None
    ip_bytes = socket.inet_aton(lan_ip)

    if mode == "llmnr" or (mode == "mdns" and peer_addr[1] != 5353):
        resp_flags = 0x8000 if mode == "llmnr" else 0x8400
        ttl = 30 if mode == "llmnr" else 10
        header = struct.pack("!HHHHHH", txid, resp_flags, 1, 1, 0, 0)
        q_section = _encode_dns_name(qname) + struct.pack("!HH", m_qtype, 1 if m_cls == 255 else m_cls)
        ans = b"\xC0\x0C" + struct.pack("!HHIH", 1, 1, ttl, 4) + ip_bytes
        return header + q_section + ans, peer_addr, lan_ip

    header = struct.pack("!HHHHHH", 0, 0x8400, 0, 1, 0, 0)
    ans = _encode_dns_name(qname) + struct.pack("!HHIH", 1, 0x0001, 120, 4) + ip_bytes
    dest = peer_addr if is_qu else ("224.0.0.251", 5353)
    return header + ans, dest, lan_ip


def _join_multicast_all(sock, mcast_group, joined_ips):
    new_ips = set(_get_lan_ipv4s())
    for ip in new_ips - joined_ips:
        try:
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, socket.inet_aton(mcast_group) + socket.inet_aton(ip))
            joined_ips.add(ip)
        except OSError:
            pass
    if not joined_ips:
        try:
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, socket.inet_aton(mcast_group) + socket.inet_aton("0.0.0.0"))
            joined_ips.add("0.0.0.0")
        except OSError:
            pass


def _run_mcast_responder(mode, mcast_group, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        if hasattr(socket, "SO_REUSEPORT"):
            try:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
            except OSError:
                pass
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 255)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_LOOP, 0)
        sock.bind(("", port))
        sock.settimeout(5.0)
    except OSError as exc:
        print(f"LAN {mode} listener unavailable on port {port}: {exc}", flush=True)
        return

    joined_ips = set()
    _join_multicast_all(sock, mcast_group, joined_ips)
    last_refresh = time.monotonic()

    while True:
        try:
            if time.monotonic() - last_refresh >= 60:
                _join_multicast_all(sock, mcast_group, joined_ips)
                last_refresh = time.monotonic()
            data, peer_addr = sock.recvfrom(4096)
        except socket.timeout:
            continue
        except OSError:
            time.sleep(2)
            continue
        try:
            built = _build_dns_response(data, peer_addr, mode)
            if not built:
                continue
            payload, dest, lan_ip = built
            if dest[0] == mcast_group:
                try:
                    sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(lan_ip))
                except OSError:
                    pass
            sock.sendto(payload, dest)
        except Exception:
            pass


def _decode_nb_name(raw32):
    if len(raw32) != 32:
        return ""
    chars = []
    for i in range(0, 32, 2):
        hi = raw32[i] - 65
        lo = raw32[i + 1] - 65
        if not (0 <= hi <= 15 and 0 <= lo <= 15):
            return ""
        chars.append(chr((hi << 4) | lo))
    if ord(chars[15]) not in (0x00, 0x20):
        return ""
    return "".join(chars[:15]).rstrip().lower()


def _run_nbns_responder(port=137):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock.bind(("", port))
        sock.settimeout(5.0)
    except OSError as exc:
        print(f"LAN NetBIOS listener skipped on port {port}: {exc}", flush=True)
        return

    while True:
        try:
            data, peer_addr = sock.recvfrom(1024)
        except socket.timeout:
            continue
        except OSError:
            time.sleep(2)
            continue
        try:
            if len(data) < 50:
                continue
            txid, flags, qdcount, _an, _ns, _ar = struct.unpack("!HHHHHH", data[:12])
            if (flags & 0x8000) or qdcount != 1 or data[12] != 0x20 or data[45] != 0x00:
                continue
            qtype, qclass = struct.unpack("!HH", data[46:50])
            if qtype != 0x0020 or qclass != 0x0001:
                continue
            nb_name = _decode_nb_name(data[13:45])
            if not nb_name:
                continue
            with _LAN_NAME_LOCK:
                if nb_name not in _LAN_NAMES["llmnr"]:
                    continue
            lan_ip = _pick_lan_ip_for_peer(peer_addr[0])
            if not lan_ip:
                continue
            resp = (
                struct.pack("!HHHHHH", txid, 0x8500, 0, 1, 0, 0)
                + data[12:46]
                + struct.pack("!HHIHH", 0x0020, 0x0001, 120, 6, 0x0000)
                + socket.inet_aton(lan_ip)
            )
            sock.sendto(resp, peer_addr)
        except Exception:
            pass


def request_json(path, payload=None, timeout=5):
    data = None if payload is None else json.dumps(payload).encode("utf-8")
    headers = {"X-Northstar-Scanner": TOKEN, "X-Requested-With": "NorthstarIT"}
    if data is not None:
        headers["Content-Type"] = "application/json"
    request = urllib.request.Request(BASE_URL + path, data=data, headers=headers)
    with urllib.request.urlopen(request, timeout=timeout) as response:
        if response.status == 204:
            return None
        raw = response.read()
        return json.loads(raw) if raw else None


def neighbor_mac(ip):
    try:
        if platform.system().lower() == "windows":
            result = subprocess.run(["arp", "-a", ip], capture_output=True, text=True, timeout=2, check=False)
            match = re.search(r"([0-9a-f]{2}(?:-[0-9a-f]{2}){5})", result.stdout, re.I)
            return match.group(1).replace("-", ":").lower() if match else ""
        result = subprocess.run(["ip", "neigh", "show", ip], capture_output=True, text=True, timeout=2, check=False)
        match = re.search(r"\blladdr\s+([0-9a-f:]{17})\b", result.stdout, re.I)
        return match.group(1).lower() if match else ""
    except (OSError, subprocess.TimeoutExpired):
        return ""


def probe(ip):
    command = ["ping", "-n", "-c", "1", "-W", "1", str(ip)] if platform.system().lower() != "windows" else ["ping", "-n", "1", "-w", "1000", str(ip)]
    started = time.monotonic()
    try:
        result = subprocess.run(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=2, check=False)
        if result.returncode:
            return None
        try:
            hostname = socket.gethostbyaddr(str(ip))[0]
        except (OSError, socket.herror):
            hostname = ""
        time.sleep(0.05)
        return {"ip":str(ip), "mac":neighbor_mac(str(ip)), "hostname":hostname, "status":"Online", "latency_ms":round((time.monotonic()-started)*1000), "last_seen":datetime.datetime.now(datetime.timezone.utc).isoformat()}
    except (OSError, subprocess.TimeoutExpired):
        return None


def ping_reachable(ip):
    """Fast status-only probe; avoid DNS and neighbor-table delays per device."""
    command = ["ping", "-n", "-c", "1", "-W", "1", str(ip)] if platform.system().lower() != "windows" else ["ping", "-n", "1", "-w", "1000", str(ip)]
    try:
        result = subprocess.run(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=2, check=False)
        return result.returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


def arp_sweep(network):
    """Return L2-visible hosts when the Ubuntu scanner shares their subnet."""
    if platform.system().lower() == "windows":
        return {}
    try:
        first_host = next(network.hosts())
        route = subprocess.run(["ip", "-4", "route", "get", str(first_host)], capture_output=True, text=True, timeout=3, check=False)
        route_text = route.stdout.strip()
        interface_match = re.search(r"\bdev\s+(\S+)", route_text)
        if route.returncode or not interface_match or re.search(r"\bvia\s+", route_text):
            return {}
        result = subprocess.run(
            ["arp-scan", "--interface=" + interface_match.group(1), "--retry=1", "--timeout=250", str(network)],
            capture_output=True, text=True, timeout=max(10, min(90, network.num_addresses * 0.08)), check=False,
        )
        found = {}
        for line in result.stdout.splitlines():
            match = re.match(r"\s*(\d{1,3}(?:\.\d{1,3}){3})\s+([0-9a-f]{2}(?::[0-9a-f]{2}){5})\s*(.*)?$", line, re.I)
            if match:
                try:
                    ip = ipaddress.ip_address(match.group(1))
                except ValueError:
                    continue
                if ip in network:
                    found[str(ip)] = {"mac": match.group(2).lower(), "hostname": (match.group(3) or "").strip()}
        return found
    except (OSError, subprocess.TimeoutExpired):
        return {}


def run_task(task):
    scan_id = task["id"]
    networks = [ipaddress.ip_network(value, strict=True) for value in task.get("ranges", [])]
    hosts = [host for network in networks for host in network.hosts()]
    results = []
    progress = 0
    try:
        arp_hosts = {}
        for network in networks:
            arp_hosts.update(arp_sweep(network))
        with concurrent.futures.ThreadPoolExecutor(max_workers=64) as pool:
            futures = {pool.submit(probe, ip): ip for ip in hosts}
            for future in concurrent.futures.as_completed(futures):
                scanned_ip = str(futures[future])
                row = future.result()
                if row and scanned_ip in arp_hosts:
                    row["mac"] = arp_hosts[scanned_ip]["mac"]
                if row:
                    results.append(row)
                progress += 1
                if progress % 512 == 0 or progress == len(hosts):
                    results.sort(key=lambda row:tuple(int(part) for part in row["ip"].split(".")))
                    request_json("/api/internal/scanner-progress", {"id":scan_id, "status":"running", "progress":progress, "results":results}, timeout=10)
        results.sort(key=lambda row:tuple(int(part) for part in row["ip"].split(".")))
        request_json("/api/internal/scanner-progress", {"id":scan_id, "status":"completed", "progress":progress, "results":results}, timeout=10)
        print(f"Scan {scan_id} complete: {len(results)} responsive devices", flush=True)
    except Exception as exc:
        print(f"Scan {scan_id} failed: {type(exc).__name__}", flush=True)
        try:
            request_json("/api/internal/scanner-progress", {"id":scan_id, "status":"failed", "progress":progress, "results":results, "error":True}, timeout=10)
        except Exception:
            pass


def run_ip_status_task(task):
    task_id = task.get("id", "")
    targets = task.get("ips", [])
    online = []
    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=128) as pool:
            futures = {pool.submit(ping_reachable, ipaddress.ip_address(value)): value for value in targets}
            for future in concurrent.futures.as_completed(futures):
                if future.result():
                    online.append(futures[future])
        request_json("/api/internal/ip-status-results", {"id":task_id, "online":online}, timeout=20)
        print(f"IP status check complete: {len(online)} of {len(targets)} online", flush=True)
    except Exception as exc:
        print(f"IP status check failed: {type(exc).__name__}", flush=True)


def _snmp_walk(profile, oid):
    command = [
        "snmpwalk", "-On", "-t", "3", "-r", "0", "-v3", "-l", "authPriv",
        "-u", str(profile["username"]), "-a", str(profile["authProtocol"]), "-A", str(profile["authSecret"]),
        "-x", str(profile["privacyProtocol"]), "-X", str(profile["privacySecret"]),
        f"udp:{profile['host']}:{int(profile.get('port', 161))}", oid,
    ]
    result = subprocess.run(command, capture_output=True, text=True, timeout=8, check=False)
    if result.returncode != 0:
        raise RuntimeError("SNMP query failed; check route, SNMPv3 credentials and UDP 161 access")
    return result.stdout


def _snmp_table_values(output, table_oid, numeric=False):
    values = {}
    prefix = "." + table_oid.lstrip(".") + "."
    for line in output.splitlines():
        left, sep, right = line.partition("=")
        left = left.strip()
        if not sep or not left.startswith(prefix):
            continue
        suffix = left[len(prefix):].split(".", 1)[0]
        if not suffix.isdigit():
            continue
        value = right.strip().split(":", 1)[-1].strip()
        value = value.strip('"')
        if numeric:
            match = re.search(r"\d+", value)
            if not match:
                continue
            value = int(match.group(0))
        values[int(suffix)] = value
    return values


def poll_snmp_profile(profile):
    profile_id = str(profile.get("id", ""))
    try:
        names = _snmp_table_values(_snmp_walk(profile, ".1.3.6.1.2.1.31.1.1.1.1"), ".1.3.6.1.2.1.31.1.1.1.1")
        if not names:
            names = _snmp_table_values(_snmp_walk(profile, ".1.3.6.1.2.1.2.2.1.2"), ".1.3.6.1.2.1.2.2.1.2")
        incoming = _snmp_table_values(_snmp_walk(profile, ".1.3.6.1.2.1.31.1.1.1.6"), ".1.3.6.1.2.1.31.1.1.1.6", True)
        outgoing = _snmp_table_values(_snmp_walk(profile, ".1.3.6.1.2.1.31.1.1.1.10"), ".1.3.6.1.2.1.31.1.1.1.10", True)
        counter_bits = 64
        if not incoming or not outgoing:
            incoming = _snmp_table_values(_snmp_walk(profile, ".1.3.6.1.2.1.2.2.1.10"), ".1.3.6.1.2.1.2.2.1.10", True)
            outgoing = _snmp_table_values(_snmp_walk(profile, ".1.3.6.1.2.1.2.2.1.16"), ".1.3.6.1.2.1.2.2.1.16", True)
            counter_bits = 32
        if not names or not incoming or not outgoing:
            raise RuntimeError("No IF-MIB interface counters returned; check SNMP permissions and supported OIDs")
        selected = str(profile.get("interfaceIndex", "")).strip()
        now = time.monotonic()
        current = {i: (incoming[i], outgoing[i]) for i in incoming.keys() & outgoing.keys()
                   if not selected or str(i) == selected}
        previous = SNMP_COUNTERS.get(profile_id, {})
        elapsed = max(0.1, now - previous.get("at", now))
        samples = []
        for index, (rx, tx) in current.items():
            old = previous.get("values", {}).get(index)
            if old:
                rx_delta, tx_delta = rx - old[0], tx - old[1]
                if previous.get("bits") == 32 and counter_bits == 32:
                    if rx_delta < 0 and old[0] > 0xF0000000:
                        rx_delta += 1 << 32
                    if tx_delta < 0 and old[1] > 0xF0000000:
                        tx_delta += 1 << 32
                # A counter reset/reboot starts a new baseline; never publish a negative rate.
                if rx_delta >= 0 and tx_delta >= 0:
                    samples.append({"interfaceIndex": index, "interfaceName": str(names.get(index, f"if{index}")),
                                    "rxBps": round(rx_delta * 8 / elapsed, 2),
                                    "txBps": round(tx_delta * 8 / elapsed, 2)})
        SNMP_COUNTERS[profile_id] = {"at": now, "values": current, "bits": counter_bits}
        request_json("/api/internal/snmp-results", {"id": profile_id, "ok": True, "samples": samples}, timeout=10)
        print(f"SNMP poll {profile.get('name', profile_id)}: {len(current)} interfaces", flush=True)
    except Exception as exc:
        SNMP_COUNTERS.pop(profile_id, None)
        request_json("/api/internal/snmp-results", {"id": profile_id, "ok": False,
                     "error": str(exc)[:180], "samples": []}, timeout=10)
        print(f"SNMP poll {profile_id} failed: {type(exc).__name__}", flush=True)


def send_notification(job):
    channel = job.get("channel")
    status = str(job.get("status", ""))
    asset = str(job.get("asset", "Managed device"))
    tag = str(job.get("tag", ""))
    ip = str(job.get("ip", "Not recorded")) or "Not recorded"
    factory = str(job.get("factory", "Not recorded")) or "Not recorded"
    if channel == "email":
        host = os.getenv("SMTP_HOST", "").strip()
        sender = os.getenv("SMTP_FROM", "").strip()
        if not host or not sender:
            raise RuntimeError("Email SMTP settings are missing")
        message = EmailMessage()
        message["Subject"] = f"IT asset {status.lower()}: {asset} ({tag})"
        message["From"] = sender
        message["To"] = str(job.get("destination", ""))
        message.set_content(
            f"IT asset status changed.\n\nDevice: {asset}\nAsset tag: {tag}\n"
            f"Category: {job.get('category', '')}\nStatus: {job.get('previous', '')} → {status}\n"
            f"IP address: {ip}\nFactory: {factory}\nChecked at: {job.get('checkedAt', '')}\n"
        )
        port = int(os.getenv("SMTP_PORT", "587"))
        timeout = 15
        username = os.getenv("SMTP_USERNAME", "")
        password = os.getenv("SMTP_PASSWORD", "")
        if os.getenv("SMTP_SSL", "false").lower() == "true":
            with smtplib.SMTP_SSL(host, port, timeout=timeout, context=ssl.create_default_context()) as smtp:
                if username:
                    smtp.login(username, password)
                smtp.send_message(message)
        else:
            with smtplib.SMTP(host, port, timeout=timeout) as smtp:
                smtp.ehlo()
                if os.getenv("SMTP_STARTTLS", "true").lower() == "true":
                    smtp.starttls(context=ssl.create_default_context())
                    smtp.ehlo()
                if username:
                    smtp.login(username, password)
                smtp.send_message(message)
        return
    if channel == "whatsapp":
        token = os.getenv("WHATSAPP_ACCESS_TOKEN", "").strip()
        phone_number_id = os.getenv("WHATSAPP_PHONE_NUMBER_ID", "").strip()
        version = os.getenv("WHATSAPP_API_VERSION", "").strip()
        template_name = os.getenv("WHATSAPP_TEMPLATE_NAME", "").strip()
        language = os.getenv("WHATSAPP_TEMPLATE_LANGUAGE", "en_US").strip() or "en_US"
        if not all((token, phone_number_id, version, template_name)):
            raise RuntimeError("WhatsApp Cloud API settings are missing")
        recipient = re.sub(r"\D", "", str(job.get("destination", "")))
        if not recipient or len(recipient) < 8:
            raise RuntimeError("Recipient WhatsApp number must include country code")
        payload = {
            "messaging_product": "whatsapp", "to": recipient, "type": "template",
            "template": {"name": template_name, "language": {"code": language}, "components": [{
                "type": "body", "parameters": [
                    {"type": "text", "text": asset[:160]},
                    {"type": "text", "text": tag[:100]},
                    {"type": "text", "text": status[:20]},
                    {"type": "text", "text": ip[:45]},
                ]
            }]}
        }
        request = urllib.request.Request(
            f"https://graph.facebook.com/{version}/{phone_number_id}/messages",
            data=json.dumps(payload).encode("utf-8"),
            headers={"Authorization": "Bearer " + token, "Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(request, timeout=15) as response:
            result = json.loads(response.read() or b"{}")
            if response.status < 200 or response.status >= 300 or not result.get("messages"):
                raise RuntimeError("WhatsApp API did not accept the template message")
        return
    raise RuntimeError("Unsupported notification channel")


def run_notification_task(task):
    job = task.get("job") or {}
    if not job:
        return
    ok, error = True, ""
    try:
        send_notification(job)
    except Exception as exc:
        ok, error = False, type(exc).__name__
    request_json("/api/internal/notification-result", {"id": job.get("id", ""), "ok": ok, "error": error}, timeout=10)
    print(f"Notification {job.get('channel', '')} {'sent' if ok else 'failed'} ({error or 'accepted'})", flush=True)


def main():
    if len(TOKEN) < 40:
        raise SystemExit("APP_SECRET must be configured before the scanner agent starts")
    print("Northstar host-network scanner agent started", flush=True)
    update_lan_hostnames(os.getenv("SITE_NAME", ""))
    threading.Thread(target=_run_mcast_responder, args=("mdns", "224.0.0.251", 5353), daemon=True).start()
    threading.Thread(target=_run_mcast_responder, args=("llmnr", "224.0.0.252", 5355), daemon=True).start()
    threading.Thread(target=_run_nbns_responder, args=(137,), daemon=True).start()
    last_heartbeat = 0
    while True:
        try:
            if time.monotonic() - last_heartbeat >= 6:
                hb = request_json("/api/internal/scanner-heartbeat", payload={}, timeout=5)
                if isinstance(hb, dict) and "siteName" in hb:
                    update_lan_hostnames(hb.get("siteName", ""))
                last_heartbeat = time.monotonic()
            notification = request_json("/api/internal/notification-task", timeout=5)
            if notification:
                run_notification_task(notification)
            snmp_task = request_json("/api/internal/snmp-task", timeout=5)
            if snmp_task:
                with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
                    futures = [pool.submit(poll_snmp_profile, profile) for profile in snmp_task.get("items", [])]
                    for future in concurrent.futures.as_completed(futures):
                        future.result()
                continue
            task = request_json("/api/internal/scanner-task", timeout=5)
            if task:
                print(f"Starting authorized scan {task['id']} over {task.get('total', 0)} addresses", flush=True)
                run_task(task)
                continue
            status_task = request_json("/api/internal/ip-status-task", timeout=5)
            if status_task:
                run_ip_status_task(status_task)
            else:
                time.sleep(POLL_SECONDS)
        except (urllib.error.URLError, TimeoutError, OSError, ValueError) as exc:
            print(f"Northstar app unavailable: {type(exc).__name__}", flush=True)
            time.sleep(POLL_SECONDS)


if __name__ == "__main__":
    main()

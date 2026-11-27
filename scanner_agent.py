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


_EMBEDDED_OUI = {
    "000c29": "VMware", "005056": "VMware", "000569": "VMware",
    "00155d": "Microsoft Hyper-V", "525400": "QEMU / KVM", "080027": "Oracle VirtualBox",
    "001b21": "Intel", "001e67": "Intel", "3c970e": "Intel", "8086f2": "Intel", "a4bf01": "Intel", "d4bed9": "Dell",
    "001422": "Dell", "180373": "Dell", "24b6fd": "Dell", "549f35": "Dell", "b083fe": "Dell", "f8bc12": "Dell", "00219b": "Dell",
    "001b78": "Hewlett Packard", "0025b3": "Hewlett Packard", "3c4a92": "Hewlett Packard Enterprise", "9457a5": "Hewlett Packard",
    "d4c9ef": "HP", "ec9a74": "HP", "0001e6": "HP", "00215a": "HP",
    "000b86": "Aruba / HPE", "204c03": "Aruba / HPE", "24de9a": "Aruba / HPE", "94b40f": "Aruba / HPE", "ac1702": "Aruba / HPE", "d8c7c8": "Aruba / HPE",
    "001122": "Cisco", "000e83": "Cisco", "001bd5": "Cisco", "0026cb": "Cisco", "68bc0c": "Cisco", "f4cf e2": "Cisco",
    "001a8c": "Sophos", "005018": "Sophos", "c84f86": "Sophos", "7c5a1c": "Sophos",
    "00090f": "Fortinet", "085b0e": "Fortinet", "704ca5": "Fortinet", "906cac": "Fortinet",
    "18e829": "Ubiquiti", "24a43c": "Ubiquiti", "44d9e7": "Ubiquiti", "7483c2": "Ubiquiti", "802aa8": "Ubiquiti", "b4fbe4": "Ubiquiti", "dc9fdb": "Ubiquiti", "fc ecda": "Ubiquiti",
    "000c42": "MikroTik", "4c5e0c": "MikroTik", "64d154": "MikroTik", "d4ca6d": "MikroTik", "dc2c6e": "MikroTik", "b869f4": "MikroTik",
    "14cc20": "TP-Link", "50c7bf": "TP-Link", "60e327": "TP-Link", "98da c4": "TP-Link", "b0be76": "TP-Link", "c025e9": "TP-Link", "d807b6": "TP-Link", "e8de27": "TP-Link",
    "000d88": "D-Link", "1c7ee5": "D-Link", "28107b": "D-Link", "c8d3a3": "D-Link",
    "00095b": "Netgear", "204e7f": "Netgear", "a021b7": "Netgear", "c03f0e": "Netgear",
    "001132": "Synology", "0011d8": "Synology", "245ebe": "QNAP",
    "1868cb": "Hikvision", "2857be": "Hikvision", "4419b6": "Hikvision", "4cb d8f": "Hikvision", "54c415": "Hikvision", "8c e748": "Hikvision", "a41437": "Hikvision", "c056e3": "Hikvision", "c42f90": "Hikvision",
    "14a78b": "Dahua", "3c ef8c": "Dahua", "4c11bf": "Dahua", "9002a9": "Dahua", "a0bd1d": "Dahua", "e0508b": "Dahua",
    "48ea63": "Uniview (UNV)", "6c f17e": "Uniview (UNV)", "c47905": "Uniview (UNV)",
    "00408c": "Axis", "accc8e": "Axis", "b8a44f": "Axis",
    "00105a": "Lenovo", "00215c": "Lenovo", "28d244": "Lenovo", "503eaa": "Lenovo", "98fa9b": "Lenovo", "c85b76": "Lenovo",
    "001e8c": "ASUS", "1c872c": "ASUS", "2c4d54": "ASUS", "38d547": "ASUS", "d850e6": "ASUS",
    "0013d4": "Realtek", "00e04c": "Realtek", "485b39": "Realtek", "52544c": "Realtek", "98e7f4": "Realtek",
    "001f81": "Canon", "000085": "Canon", "180c ac": "Canon", "f48139": "Canon",
    "000048": "Epson", "0026ab": "Epson", "44d244": "Epson", "64eb8c": "Epson",
    "001ba9": "Brother", "008077": "Brother", "30055c": "Brother", "b42200": "Brother",
    "000074": "Ricoh", "002673": "Ricoh", "001599": "Samsung", "0000f0": "Samsung",
    "002590": "Supermicro", "0c c47a": "Supermicro", "3cecef": "Supermicro", "ac1f6b": "Supermicro",
    "b827eb": "Raspberry Pi", "dc a632": "Raspberry Pi", "e45f01": "Raspberry Pi", "28cdc1": "Raspberry Pi",
    "000393": "Apple", "3c0754": "Apple", "a45e60": "Apple", "f01898": "Apple",
}
_OUI_CACHE = None
_OUI_LOCK = threading.Lock()


def _load_oui_db():
    global _OUI_CACHE
    with _OUI_LOCK:
        if _OUI_CACHE is not None:
            return _OUI_CACHE
        db = {k.replace(" ", "").lower(): v for k, v in _EMBEDDED_OUI.items()}
        for path in (
            "/usr/share/ieee-data/oui.txt",
            "/usr/share/arp-scan/ieee-oui.txt",
            "/usr/share/misc/oui.txt",
            "/etc/ieee-oui.txt",
        ):
            if not os.path.isfile(path):
                continue
            try:
                with open(path, "r", encoding="utf-8", errors="ignore") as fh:
                    for line in fh:
                        line_s = line.strip()
                        if not line_s or line_s.startswith("#"):
                            continue
                        m_hex = re.match(r"^([0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2})\s*\(hex\)\s+(.+)$", line_s)
                        if m_hex:
                            prefix = re.sub(r"[^0-9a-f]", "", m_hex.group(1).lower())
                            vendor = m_hex.group(2).strip()[:80]
                            if len(prefix) == 6 and vendor:
                                db.setdefault(prefix, vendor)
                            continue
                        m_tab = re.match(r"^([0-9A-Fa-f]{6})\s+(.+)$", line_s)
                        if m_tab:
                            prefix = m_tab.group(1).lower()
                            vendor = m_tab.group(2).strip()[:80]
                            if vendor:
                                db.setdefault(prefix, vendor)
            except OSError:
                continue
        _OUI_CACHE = db
        return _OUI_CACHE


def lookup_mac_vendor(mac):
    cleaned = re.sub(r"[^0-9a-f]", "", str(mac or "").lower())
    if len(cleaned) < 6:
        return ""
    vendor = _load_oui_db().get(cleaned[:6], "")
    if vendor:
        return vendor
    # Check locally-administered randomized/virtual MAC bit only as fallback note when not in OUI table
    return ""


def _local_interface_subnets():
    subnets = []
    if platform.system().lower() != "windows":
        try:
            res = subprocess.run(["ip", "-o", "-4", "addr", "show", "up"], capture_output=True, text=True, timeout=3, check=False)
            for line in res.stdout.splitlines():
                m_if = re.match(r"^\d+:\s+(\S+)\s+inet\s+(\d+\.\d+\.\d+\.\d+/\d+)", line.strip())
                if not m_if:
                    continue
                ifname, cidr = m_if.group(1), m_if.group(2)
                if ifname == "lo" or ifname.startswith("docker") or ifname.startswith("br-") or ifname.startswith("veth"):
                    continue
                try:
                    net = ipaddress.ip_network(cidr, strict=False)
                except ValueError:
                    continue
                if net.version == 4 and net.is_private and not net.is_loopback and not net.is_link_local:
                    s = str(net)
                    if s not in subnets:
                        subnets.append(s)
        except Exception:
            pass
    return subnets


def _default_gateway_ip():
    if platform.system().lower() != "windows":
        try:
            res = subprocess.run(["ip", "-4", "route", "show", "default"], capture_output=True, text=True, timeout=2, check=False)
            m = re.search(r"\bvia\s+(\d+\.\d+\.\d+\.\d+)", res.stdout)
            if m:
                return m.group(1)
        except Exception:
            pass
    return ""


def _tcp_reachability_probe(ip_str, ports=(80, 443, 445, 139, 3389, 22, 554, 9100), timeout=0.35):
    """Fast non-blocking parallel TCP SYN check for cross-VLAN hosts that block ICMP."""
    import select
    socks = []
    started = time.monotonic()
    try:
        for port in ports:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.setblocking(False)
                err = s.connect_ex((ip_str, port))
                if err == 0:
                    for x, _ in socks:
                        x.close()
                    s.close()
                    return f"TCP:{port}", round((time.monotonic() - started) * 1000)
                socks.append((s, port))
            except OSError:
                pass
        if not socks:
            return "", None
        _, writable, _ = select.select([], [s for s, _ in socks], [], timeout)
        for s in writable:
            err = s.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)
            # err == 0 (connected) or 111/10061 ECONNREFUSED on a non-routed firewall RST confirms host up?
            # Strictly treat err == 0 (open port) as Online to avoid router-generated RST false positives!
            if err == 0:
                port = next((p for x, p in socks if x is s), 80)
                return f"TCP:{port}", round((time.monotonic() - started) * 1000)
    except Exception:
        pass
    finally:
        for x, _ in socks:
            try:
                x.close()
            except OSError:
                pass
    return "", None


def _probe_netbios(ip_str, timeout=0.38):
    """Query UDP/137 NBSTAT to extract both Windows/NAS Device Name and MAC address across L3 VLANs."""
    txid = os.urandom(2)
    # Query for wildcard '*' (0x2A + 15x0x00) encoded per RFC 1001 ('CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA')
    pkt = txid + b"\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x20CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x00\x00\x21\x00\x01"
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.settimeout(timeout)
        s.sendto(pkt, (ip_str, 137))
        data, _ = s.recvfrom(1024)
        if len(data) < 57 or data[:2] != txid:
            return "", ""
        num_names = data[56]
        offset = 57
        hostname = ""
        for _ in range(num_names):
            if offset + 18 > len(data):
                break
            raw_name = data[offset:offset + 15].decode("ascii", errors="ignore").strip()
            suffix = data[offset + 15]
            flags = struct.unpack("!H", data[offset + 16:offset + 18])[0]
            offset += 18
            if raw_name and suffix in (0x00, 0x20) and not (flags & 0x8000):
                if not raw_name.startswith("MSBROWSE") and not raw_name.startswith("__"):
                    hostname = raw_name
                    break
        mac = ""
        if offset + 6 <= len(data):
            unit = data[offset:offset + 6]
            if any(b != 0 for b in unit):
                mac = ":".join(f"{b:02x}" for b in unit)
        return hostname, mac
    except OSError:
        return "", ""
    finally:
        s.close()


_BRAND_HINTS = (
    ("sophos", "Sophos"), ("aruba", "Aruba / HPE"), ("hewlett", "HP / HPE"), ("hp ", "HP"),
    ("laserjet", "HP"), ("dell", "Dell"), ("lenovo", "Lenovo"), ("hikvision", "Hikvision"),
    ("dahua", "Dahua"), ("uniview", "Uniview (UNV)"), ("unv", "Uniview (UNV)"), ("cp plus", "CP Plus"),
    ("fortinet", "Fortinet"), ("fortigate", "Fortinet"), ("cisco", "Cisco"), ("mikrotik", "MikroTik"),
    ("ubiquiti", "Ubiquiti"), ("unifi", "Ubiquiti"), ("tp-link", "TP-Link"), ("d-link", "D-Link"),
    ("netgear", "Netgear"), ("synology", "Synology"), ("qnap", "QNAP"), ("canon", "Canon"),
    ("epson", "Epson"), ("brother", "Brother"), ("ricoh", "Ricoh"), ("kyocera", "Kyocera"),
    ("xerox", "Xerox"), ("axis", "Axis"), ("proxmox", "Proxmox"), ("vmware", "VMware"),
)


def _infer_vendor_from_text(*parts):
    joined = " ".join(str(p or "") for p in parts).lower()
    if not joined.strip():
        return ""
    for needle, brand in _BRAND_HINTS:
        if needle in joined:
            return brand
    return ""


def _probe_http_tls_hint(ip_str, timeout=0.45):
    """Best-effort TLS CN/Org or HTTP Title/Server lookup to identify non-NetBIOS appliances."""
    name_hint, vendor_hint = "", ""
    # Try HTTPS cert first
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((ip_str, 443), timeout=timeout) as raw_sock:
            with ctx.wrap_socket(raw_sock, server_hostname=ip_str) as tls_sock:
                cert = tls_sock.getpeercert(binary_form=False) or {}
                for tup in cert.get("subject", ()):
                    for k, v in tup:
                        if k == "commonName" and v and not name_hint and not v.replace(".", "").isdigit():
                            name_hint = str(v)[:120]
                        elif k == "organizationName" and v and not vendor_hint:
                            vendor_hint = str(v)[:80]
    except Exception:
        pass
    if name_hint and vendor_hint:
        return name_hint, (_infer_vendor_from_text(vendor_hint, name_hint) or vendor_hint)
    # Fallback brief HTTP GET / HEAD on port 80
    try:
        with socket.create_connection((ip_str, 80), timeout=timeout) as s:
            s.settimeout(timeout)
            s.sendall(b"GET / HTTP/1.0\r\nHost: " + ip_str.encode("ascii") + b"\r\nConnection: close\r\n\r\n")
            chunks = s.recv(4096).decode("utf-8", errors="ignore")
            srv_m = re.search(r"^Server:\s*([^\r\n]+)", chunks, re.I | re.M)
            title_m = re.search(r"<title[^>]*>\s*([^<]{2,120}?)\s*</title>", chunks, re.I | re.S)
            srv_txt = srv_m.group(1).strip() if srv_m else ""
            ttl_txt = re.sub(r"\s+", " ", title_m.group(1)).strip() if title_m else ""
            if ttl_txt and not name_hint and not ttl_txt.lower().startswith(("401 ", "403 ", "404 ", "index of")):
                name_hint = ttl_txt[:120]
            v = _infer_vendor_from_text(ttl_txt, srv_txt, vendor_hint, name_hint)
            if v:
                vendor_hint = v
    except Exception:
        pass
    return name_hint, vendor_hint


def _parse_snmp_mac(raw_val):
    cleaned = raw_val.strip().strip('"')
    # Hex-STRING: 00 11 22 33 44 55  or  STRING: "0:11:22:33:44:55"  or 6-byte hex
    bytes_hex = re.findall(r"[0-9a-f]{2}", cleaned, re.I) if ":" in cleaned or " " in cleaned else []
    if not bytes_hex:
        # Handle dotted/short hex like 0:1a:8c:1:2:3
        parts = [p for p in re.split(r"[:\-\s]+", cleaned) if re.fullmatch(r"[0-9a-f]{1,2}", p, re.I)]
        if len(parts) == 6:
            return ":".join(f"{int(p, 16):02x}" for p in parts)
    if len(bytes_hex) == 6:
        return ":".join(b.lower() for b in bytes_hex)
    return ""


def fetch_snmp_arp_table(collectors, default_community=""):
    """Collect IP -> MAC across ALL routed VLANs from L3 switches / firewall / router ARP tables."""
    ip_to_mac = {}
    items = list(collectors or [])
    if default_community and not items:
        gw = _default_gateway_ip()
        if gw:
            items.append({"host": gw, "version": "2c", "community": default_community, "port": 161})
    for c in items:
        host = str(c.get("host") or "").strip()
        if not host:
            continue
        port = int(c.get("port") or 161)
        ver = str(c.get("version") or ("3" if c.get("username") else "2c")).strip()
        base_cmd = ["snmpwalk", "-On", "-t", "3", "-r", "0"]
        if ver == "3" and c.get("username"):
            base_cmd += [
                "-v3", "-l", "authPriv",
                "-u", str(c["username"]),
                "-a", str(c.get("authProtocol") or "SHA"), "-A", str(c.get("authSecret") or ""),
                "-x", str(c.get("privacyProtocol") or "AES"), "-X", str(c.get("privacySecret") or ""),
            ]
        else:
            comm = str(c.get("community") or default_community or "").strip()
            if not comm:
                continue
            base_cmd += ["-v2c", "-c", comm]
        target = f"udp:{host}:{port}"
        for oid in (".1.3.6.1.2.1.4.22.1.2", ".1.3.6.1.2.1.4.35.1.4"):
            try:
                res = subprocess.run(base_cmd + [target, oid], capture_output=True, text=True, timeout=12, check=False)
                if res.returncode != 0 or not res.stdout:
                    continue
                for line in res.stdout.splitlines():
                    left, sep, right = line.partition("=")
                    if not sep:
                        continue
                    val = right.split(":", 1)[-1]
                    mac = _parse_snmp_mac(val)
                    if not mac or mac == "00:00:00:00:00:00" or mac == "ff:ff:ff:ff:ff:ff":
                        continue
                    # ipNetToMediaPhysAddress.<ifIndex>.<a>.<b>.<c>.<d>
                    m4 = re.search(r"\.(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s*$", left.strip())
                    if m4:
                        ip_s = m4.group(1)
                        try:
                            ip_obj = ipaddress.ip_address(ip_s)
                            if ip_obj.version == 4 and ip_obj.is_private:
                                ip_to_mac.setdefault(str(ip_obj), mac)
                        except ValueError:
                            pass
            except Exception:
                continue
    return ip_to_mac


def _probe_snmp_sys(ip_str, community, timeout=1):
    if not community or platform.system().lower() == "windows":
        return "", ""
    try:
        res = subprocess.run(
            ["snmpget", "-Oqv", "-t", str(timeout), "-r", "0", "-v2c", "-c", community, f"udp:{ip_str}:161",
             ".1.3.6.1.2.1.1.5.0", ".1.3.6.1.2.1.1.1.0"],
            capture_output=True, text=True, timeout=3, check=False,
        )
        if res.returncode != 0 or not res.stdout:
            return "", ""
        lines = [x.strip().strip('"') for x in res.stdout.splitlines() if x.strip()]
        sys_name = lines[0][:120] if len(lines) >= 1 and "no such" not in lines[0].lower() else ""
        sys_desc = lines[1][:180] if len(lines) >= 2 and "no such" not in lines[1].lower() else ""
        return sys_name, _infer_vendor_from_text(sys_desc, sys_name)
    except Exception:
        return "", ""


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
        mac = neighbor_mac(str(ip))
        return {"ip":str(ip), "mac":mac, "vendor":lookup_mac_vendor(mac), "hostname":hostname, "status":"Online", "latency_ms":round((time.monotonic()-started)*1000), "last_seen":datetime.datetime.now(datetime.timezone.utc).isoformat()}
    except (OSError, subprocess.TimeoutExpired):
        return None


def ping_reachable(ip):
    """Fast status-only probe with 1 verification retry on packet drop to prevent Overview Online/Offline flicker."""
    command = ["ping", "-n", "-c", "1", "-W", "1", str(ip)] if platform.system().lower() != "windows" else ["ping", "-n", "1", "-w", "900", str(ip)]
    for attempt in range(2):
        try:
            result = subprocess.run(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=2, check=False)
            if result.returncode == 0:
                return True
        except (OSError, subprocess.TimeoutExpired):
            pass
    return False


def arp_sweep(network):
    """Return L2-visible hosts when the Ubuntu scanner shares their subnet."""
    if platform.system().lower() == "windows" or network.prefixlen < 22:
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
            capture_output=True, text=True, timeout=max(10, min(60, network.num_addresses * 0.08)), check=False,
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
                    mac_s = match.group(2).lower()
                    tail = (match.group(3) or "").strip()
                    found[str(ip)] = {"mac": mac_s, "hostname": "", "vendor": lookup_mac_vendor(mac_s) or tail}
        return found
    except (OSError, subprocess.TimeoutExpired):
        return {}


_SCAN_LOCK = threading.Lock()
_SCAN_THREAD = None


def _fast_probe(ip, skip_rdns=False, arp_hosts=None, snmp_arp=None, snmp_community=""):
    ip_s = str(ip)
    command = ["ping", "-n", "-c", "1", "-W", "1", ip_s] if platform.system().lower() != "windows" else ["ping", "-n", "1", "-w", "700", ip_s]
    started = time.monotonic()
    method = ""
    latency_ms = None
    try:
        result = subprocess.run(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=1.5, check=False)
        if result.returncode == 0:
            method = "ICMP"
            latency_ms = round((time.monotonic() - started) * 1000)
    except (OSError, subprocess.TimeoutExpired):
        pass

    arp_entry = (arp_hosts or {}).get(ip_s)
    snmp_mac = (snmp_arp or {}).get(ip_s, "")

    if not method:
        # Cross-VLAN firewalls often drop ICMP; verify via common management/device TCP ports
        method, tcp_lat = _tcp_reachability_probe(ip_s)
        if method:
            latency_ms = tcp_lat
        elif arp_entry:
            method = "ARP"
            latency_ms = 1
        else:
            return None

    mac = (arp_entry or {}).get("mac") or neighbor_mac(ip_s) or snmp_mac or ""
    nb_name, nb_mac = _probe_netbios(ip_s)
    if not mac and nb_mac:
        mac = nb_mac

    hostname = nb_name or (arp_entry or {}).get("hostname") or ""
    if not hostname and not skip_rdns:
        try:
            hostname = socket.gethostbyaddr(ip_s)[0]
        except (OSError, socket.herror):
            hostname = ""

    vendor = lookup_mac_vendor(mac) or (arp_entry or {}).get("vendor") or ""
    if (not hostname or not vendor) and snmp_community:
        s_name, s_ven = _probe_snmp_sys(ip_s, snmp_community)
        if s_name and not hostname:
            hostname = s_name
        if s_ven and not vendor:
            vendor = s_ven

    if not hostname or not vendor:
        h_name, h_ven = _probe_http_tls_hint(ip_s)
        if h_name and not hostname:
            hostname = h_name
        if h_ven and not vendor:
            vendor = h_ven

    return {
        "ip": ip_s,
        "mac": mac,
        "vendor": vendor[:120],
        "hostname": hostname[:255],
        "via": method or "ICMP",
        "status": "Online",
        "latency_ms": latency_ms if latency_ms is not None else round((time.monotonic() - started) * 1000),
        "last_seen": datetime.datetime.now(datetime.timezone.utc).isoformat(),
    }


def run_task(task):
    scan_id = task["id"]
    networks = []
    for value in task.get("ranges", []):
        try:
            net = ipaddress.ip_network(str(value).strip(), strict=False)
            if net.version == 4 and net.prefixlen >= 16:
                networks.append(net)
        except ValueError:
            continue
    total_hosts = sum(n.num_addresses - (2 if n.prefixlen < 31 else 0) for n in networks)
    results = []
    progress = 0
    step = max(256, min(2048, (total_hosts // 40) or 256))
    workers = min(256, max(64, total_hosts // 64))
    skip_rdns = total_hosts > 4096
    collectors = task.get("arpCollectors") or []
    snmp_community = str(task.get("snmpCommunity") or "").strip()
    try:
        arp_hosts = {}
        for network in networks:
            arp_hosts.update(arp_sweep(network))
        snmp_arp = fetch_snmp_arp_table(collectors, default_community=snmp_community)

        def host_iter():
            for network in networks:
                for host in network.hosts():
                    yield host

        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
            pending = {}
            it = host_iter()
            exhausted = False
            while not exhausted or pending:
                while not exhausted and len(pending) < workers * 4:
                    try:
                        ip = next(it)
                    except StopIteration:
                        exhausted = True
                        break
                    pending[pool.submit(_fast_probe, ip, skip_rdns, arp_hosts, snmp_arp, snmp_community)] = str(ip)
                if not pending:
                    break
                done, _ = concurrent.futures.wait(pending.keys(), return_when=concurrent.futures.FIRST_COMPLETED)
                for future in done:
                    scanned_ip = pending.pop(future)
                    row = future.result()
                    if row and scanned_ip in arp_hosts:
                        if not row.get("mac"):
                            row["mac"] = arp_hosts[scanned_ip]["mac"]
                        if not row.get("vendor"):
                            row["vendor"] = arp_hosts[scanned_ip].get("vendor", "") or lookup_mac_vendor(row["mac"])
                        if not row.get("hostname") and arp_hosts[scanned_ip].get("hostname"):
                            row["hostname"] = arp_hosts[scanned_ip]["hostname"]
                    if row and not row.get("vendor") and row.get("mac"):
                        row["vendor"] = lookup_mac_vendor(row["mac"])
                    if row:
                        results.append(row)
                    progress += 1
                    if progress % step == 0 or (exhausted and not pending):
                        results.sort(key=lambda r: tuple(int(part) for part in r["ip"].split(".")))
                        request_json("/api/internal/scanner-progress", {"id":scan_id, "status":"running", "progress":progress, "results":results}, timeout=15)
        results.sort(key=lambda row:tuple(int(part) for part in row["ip"].split(".")))
        request_json("/api/internal/scanner-progress", {"id":scan_id, "status":"completed", "progress":progress, "results":results}, timeout=15)
        print(f"Scan {scan_id} complete: {len(results)} responsive devices across {total_hosts} addresses (L2-ARP={len(arp_hosts)}, SNMP-ARP={len(snmp_arp)})", flush=True)
    except Exception as exc:
        print(f"Scan {scan_id} failed: {type(exc).__name__}", flush=True)
        try:
            request_json("/api/internal/scanner-progress", {"id":scan_id, "status":"failed", "progress":progress, "results":results, "error":True}, timeout=15)
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
                hb = request_json("/api/internal/scanner-heartbeat", payload={"hostSubnets": _local_interface_subnets(), "gateway": _default_gateway_ip()}, timeout=5)
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
            if not _SCAN_THREAD or not _SCAN_THREAD.is_alive():
                task = request_json("/api/internal/scanner-task", timeout=5)
                if task:
                    print(f"Starting authorized scan {task['id']} over {task.get('total', 0)} addresses", flush=True)
                    _SCAN_THREAD = threading.Thread(target=run_task, args=(task,), daemon=True)
                    _SCAN_THREAD.start()
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

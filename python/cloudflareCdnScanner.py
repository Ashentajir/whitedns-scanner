import os
import sys
import subprocess
import time
import socket
import ssl
import threading
import ipaddress
from urllib.parse import urlparse
from datetime import datetime
from collections import deque
import json
import dns.message
import dns.query
import dns.exception
from functools import partial
import concurrent.futures
import multiprocessing

# ==========================================
# 1. AUTO-DEPENDENCY MANAGER
# ==========================================
def ensure_dependencies():
    # Map pip package names to their import module names.
    packages = [
        ("aiohttp", "aiohttp"),
        ("questionary", "questionary"),
        ("rich", "rich"),
        ("dnspython", "dns"),
    ]
    for pkg, import_name in packages:
        try:
            __import__(import_name)
        except ImportError:
            print(f"[*] Missing library '{pkg}'. Installing automatically...")
            subprocess.check_call([sys.executable, "-m", "pip", "install", pkg])

ensure_dependencies()

import asyncio
import aiohttp
import random
import questionary
from rich.console import Console, Group
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.progress import Progress, BarColumn, TextColumn, TimeElapsedColumn, TimeRemainingColumn
from rich.live import Live

# ==========================================
# 2. GLOBAL CONFIGURATION & STATE
# ==========================================
def _base_dir() -> str:
    if getattr(sys, "frozen", False):
        return os.path.dirname(sys.executable)
    return os.path.dirname(os.path.abspath(__file__))


BASE_DIR = _base_dir()


def _abs(filename: str) -> str:
    if os.path.isabs(filename):
        return filename
    return os.path.join(BASE_DIR, filename)


TIMEOUT_SECS     = 5
# Default concurrent connections used when user doesn't supply a value
DEFAULT_CONCURRENT = 500
# Historical MAX_CONCURRENT kept for reference; no hard cap enforced now
MAX_CONCURRENT   = 10000000
RETRY_COUNT      = 0
LAST_PASSED_FILE = _abs("last_passed.txt")
STREAMING_SCAN_THRESHOLD = 50000

scanner_state = "RUNNING"
stats = {"done": 0, "total": 0, "open": 0, "dead": 0}
scan_phase = "Initializing"
recent_hits = deque(maxlen=8)

HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/124.0.0.0 Safari/537.36"
    ),
    "Accept":          "text/html,application/xhtml+xml,*/*;q=0.9",
    "Accept-Language": "en-US,en;q=0.5",
    "Accept-Encoding": "gzip, deflate",
    "Connection":      "close",
}

# Light-weight UA and language rotation to reduce fingerprinting when stealth
# mode is enabled. Keep the lists small to avoid large binary growth.
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.4 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
]

ACCEPT_LANGUAGES = [
    "en-US,en;q=0.9",
    "en-GB,en;q=0.9",
    "en-US;q=0.8,en;q=0.6",
]

def _build_request_headers(host: str, stealth: bool) -> dict:
    h = dict(HEADERS)
    if stealth:
        h["User-Agent"] = random.choice(USER_AGENTS)
        h["Accept-Language"] = random.choice(ACCEPT_LANGUAGES)
        # Vary Accept slightly
        h["Accept"] = random.choice([
            "text/html,application/xhtml+xml,*/*;q=0.9",
            "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        ])
        # Occasionally include a Referer that resembles a browser
        if random.random() < 0.35:
            h["Referer"] = f"https://{host}/"
        # Mix connection header to look less uniform
        h["Connection"] = "keep-alive" if random.random() < 0.8 else "close"
    return h

# ==========================================
# 3. KEYBOARD LISTENER
# ==========================================
def kb_listener():
    """Listens for keyboard input natively without blocking the async loop."""
    global scanner_state
    if sys.platform == "win32":
        import msvcrt
        while scanner_state != "STOPPED":
            if msvcrt.kbhit():
                try:
                    char = msvcrt.getch().decode('utf-8', 'ignore').lower()
                    if char == 'q': scanner_state = "STOPPED"
                    elif char == 'p': scanner_state = "PAUSED"
                    elif char == 'r': scanner_state = "RUNNING"
                except Exception:
                    pass
            time.sleep(0.05)
    else:
        import tty, termios, select
        fd = sys.stdin.fileno()
        old_settings = termios.tcgetattr(fd)
        try:
            tty.setcbreak(fd)
            while scanner_state != "STOPPED":
                if select.select([sys.stdin], [], [], 0.1)[0]:
                    char = sys.stdin.read(1).lower()
                    if char == 'q': scanner_state = "STOPPED"
                    elif char == 'p': scanner_state = "PAUSED"
                    elif char == 'r': scanner_state = "RUNNING"
        finally:
            termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)

def _parse_line(raw: str):
    line = raw.strip()
    if not line or line.startswith("#"):
        return []

    lbl = ""
    val = line

    if "|" in line:
        lbl, val = line.split("|", 1)
        lbl = lbl.strip()
        val = val.strip()

    val = val.strip("'\"")

    if "/" in val and not val.startswith("http"):
        try:
            network = ipaddress.ip_network(val, strict=False)
            out = []
            for ip in network.hosts():
                ip_str = str(ip)
                t_lbl = f"{lbl} {ip_str}".strip() if lbl else ip_str
                out.append((t_lbl, f"https://{ip_str}"))
            return out
        except ValueError:
            pass

    if val.startswith("http://") or val.startswith("https://"):
        url = val
        final_lbl = lbl if lbl else url.split("//", 1)[1].split("/")[0]
    else:
        url = "https://" + val
        final_lbl = lbl if lbl else val

    return [(final_lbl, url)]


def _count_scannable_lines(path: str) -> int:
    if not path or not os.path.exists(path):
        return 0
    count = 0
    with open(path, "r", encoding="utf-8") as f:
        for raw in f:
            line = raw.strip()
            if line and not line.startswith("#"):
                count += 1
    return count


def parse_ports_string(s: str) -> list[int]:
    out = []
    if not s:
        return out
    # allow comma separated values and ranges like 8000-8010
    parts = [p.strip() for p in s.split(",") if p.strip()]
    for p in parts:
        if "-" in p:
            try:
                a, b = p.split("-", 1)
                a = int(a); b = int(b)
                if a > b: a, b = b, a
                out.extend(list(range(a, b + 1)))
            except Exception:
                continue
        else:
            try:
                out.append(int(p))
            except Exception:
                continue
    # dedupe and sort
    return sorted(set([x for x in out if 1 <= x <= 65535]))


def _iter_parse_input(path: str):
    if not path or not os.path.exists(path):
        return

    cpu = max(2, multiprocessing.cpu_count() or 4)
    with open(path, "r", encoding="utf-8") as f:
        if cpu > 1:
            with multiprocessing.Pool(processes=cpu) as pool:
                for group in pool.imap(_parse_line, f, chunksize=128):
                    for target in group:
                        yield target
        else:
            for line in f:
                for target in _parse_line(line):
                    yield target


def parse_input(path: str) -> list[tuple[str, str]]:
    return list(_iter_parse_input(path) or [])


def _iter_scanned_targets(paths, scan_all_ports: bool, dns_mode: bool):
    for path in paths:
        for lbl, url in _iter_parse_input(path) or []:
            if scan_all_ports:
                parsed = urlparse(url)
                host = parsed.hostname
                if not host:
                    continue
                base_label = lbl
                cf_https_ports = [443, 2053, 2083, 2087, 2096, 8443]
                cf_http_ports = [80, 8080, 8880, 2052, 2082, 2086, 2095]
                for p in cf_https_ports:
                    yield f"{base_label}:{p}", f"https://{host}:{p}"
                for p in cf_http_ports:
                    yield f"{base_label}:{p}", f"http://{host}:{p}"
            elif dns_mode:
                host = urlparse(url).hostname or url
                yield (lbl or host), host
            else:
                yield lbl, url


def _ml_extract_a_ips(resp):
    ips = []
    if not resp:
        return ips
    for rr in getattr(resp, "answer", []) or []:
        for item in rr.items:
            if hasattr(item, "address"):
                ips.append(item.address)
    return ips


def _dns_probe_udp(args):
    resolver_ip, domain, timeout = args
    start = time.monotonic()
    try:
        q = dns.message.make_query(domain, dns.rdatatype.A)
        r = dns.query.udp(q, resolver_ip, timeout=timeout, port=53)
        ips = _ml_extract_a_ips(r)
        return {"ok": bool(ips), "error": "" if ips else "UDP_NO_A", "ips": ips, "latency_ms": int((time.monotonic() - start) * 1000)}
    except Exception as e:
        return {"ok": False, "error": str(e)[:60], "ips": [], "latency_ms": int((time.monotonic() - start) * 1000)}


def _dns_probe_tcp(args):
    resolver_ip, domain, timeout = args
    start = time.monotonic()
    try:
        q = dns.message.make_query(domain, dns.rdatatype.A)
        r = dns.query.tcp(q, resolver_ip, timeout=timeout, port=53)
        ips = _ml_extract_a_ips(r)
        return {"ok": bool(ips), "error": "" if ips else "TCP_NO_A", "ips": ips, "latency_ms": int((time.monotonic() - start) * 1000)}
    except Exception as e:
        return {"ok": False, "error": str(e)[:60], "ips": [], "latency_ms": int((time.monotonic() - start) * 1000)}


def _dns_probe_dot(args):
    resolver_ip, domain, timeout = args
    start = time.monotonic()
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        q = dns.message.make_query(domain, dns.rdatatype.A)
        r = dns.query.tls(q, resolver_ip, timeout=timeout, port=853, ssl_context=ctx)
        ips = _ml_extract_a_ips(r)
        return {"ok": bool(ips), "error": "" if ips else "DoT_NO_A", "ips": ips, "latency_ms": int((time.monotonic() - start) * 1000)}
    except Exception as e:
        return {"ok": False, "error": str(e)[:60], "ips": [], "latency_ms": int((time.monotonic() - start) * 1000)}


def _dns_probe_all(args):
    resolver_ip, domain, timeout, enable_dot = args
    import concurrent.futures as _cf

    start = time.monotonic()
    tasks = [
        ("udp", _dns_probe_udp, (resolver_ip, domain, timeout)),
        ("tcp", _dns_probe_tcp, (resolver_ip, domain, timeout)),
    ]
    if enable_dot:
        tasks.append(("dot", _dns_probe_dot, (resolver_ip, domain, timeout)))

    results = {}
    with _cf.ThreadPoolExecutor(max_workers=len(tasks)) as ex:
        fut_map = {ex.submit(fn, a): key for key, fn, a in tasks}
        for fut, key in fut_map.items():
            try:
                results[key] = fut.result(timeout=timeout + 1)
            except Exception as e:
                results[key] = {"ok": False, "error": str(e)[:60], "ips": [], "latency_ms": 0}

    if "dot" not in results:
        results["dot"] = {"ok": False, "error": "DOT_DISABLED", "ips": [], "latency_ms": 0}

    all_ips = set()
    responded = False
    for value in results.values():
        if value.get("ok"):
            responded = True
            all_ips.update(value.get("ips", []))

    return {
        "responded": responded,
        "answer_ips": sorted(all_ips),
        "error": "" if responded else "NO_RESPONSE",
        "latency_ms": int((time.monotonic() - start) * 1000),
        "transports": results,
    }

# ==========================================
# 4. LAYERED VALIDATION ENGINE
# ==========================================
async def pre_flight_layer_check(url: str, timeout_val: int, spoofed_sni: str = "www.speedtest.net") -> str:
    parsed = urlparse(url)
    host = parsed.hostname
    if not host: return "PARSE_ERR"
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    
    loop = asyncio.get_running_loop()
    
    try:
        await asyncio.wait_for(loop.getaddrinfo(host, port), timeout=timeout_val)
    except Exception: return "DNS_FAILED"
        
    try:
        r, w = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=timeout_val)
        w.close()
        try: await w.wait_closed()
        except Exception: pass 
    except Exception: return "TCP_FAILED"
        
    if parsed.scheme == "https":
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            sni_name = spoofed_sni if spoofed_sni else host
            r, w = await asyncio.wait_for(
                asyncio.open_connection(host, port, ssl=ctx, server_hostname=sni_name),
                timeout=timeout_val,
            )
            w.close()
            try: await w.wait_closed()
            except Exception: pass
        except ssl.SSLError: return "TLS_FAILED"
        except Exception: return "TLS_CONN_FAILED"

    return "PASSED"

async def check_url(
    session: aiohttp.ClientSession,
    label: str,
    url: str,
    semaphore: asyncio.Semaphore,
    spoofed_sni: str = "www.speedtest.net",
    stealth: bool = False,
):
    last_err = "UNKNOWN"

    while scanner_state == "PAUSED": await asyncio.sleep(0.5)
    if scanner_state == "STOPPED": return label, url, None, 0, "ABORTED"

    async with semaphore:
        # Accurate Timer: starts only after connection slot is acquired
        timeout = aiohttp.ClientTimeout(total=TIMEOUT_SECS) 
        start = time.monotonic() 
        
        while scanner_state == "PAUSED": await asyncio.sleep(0.5)
        if scanner_state == "STOPPED": return label, url, None, 0, "ABORTED"

        layer_timeout = max(3, TIMEOUT_SECS // 2)
        layer_status = await pre_flight_layer_check(url, timeout_val=layer_timeout, spoofed_sni=spoofed_sni)
        
        if layer_status != "PASSED":
            if url.startswith("https://"):
                http_url = "http://" + url[8:]
                fallback_status = await pre_flight_layer_check(http_url, timeout_val=layer_timeout, spoofed_sni=spoofed_sni)
                if fallback_status == "PASSED":
                    url = http_url 
                else:
                    return label, url, None, int((time.monotonic() - start) * 1000), layer_status
            else:
                return label, url, None, int((time.monotonic() - start) * 1000), layer_status

        parsed = urlparse(url)
        host = parsed.hostname
        if not host:
            return label, url, None, int((time.monotonic() - start) * 1000), "PARSE_ERR"
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        path = parsed.path or "/"
        if parsed.query:
            path += f"?{parsed.query}"

        loop = asyncio.get_running_loop()
        try:
            addr_info = await asyncio.wait_for(loop.getaddrinfo(host, port), timeout=layer_timeout)
            resolved_ip = addr_info[0][4][0]
        except Exception:
            return label, url, None, int((time.monotonic() - start) * 1000), "DNS_FAILED"

        dial_url = f"{parsed.scheme}://{resolved_ip}:{port}{path}"
        # Build request headers; optionally randomize to reduce fingerprinting
        req_headers = _build_request_headers(host, stealth)
        req_headers["Host"] = host

        # Small randomized delay to avoid highly-regular request timing
        if stealth:
            try:
                await asyncio.sleep(random.uniform(0.01, 0.15))
            except Exception:
                pass

        for attempt in range(RETRY_COUNT + 1):
            while scanner_state == "PAUSED": await asyncio.sleep(0.5)
            if scanner_state == "STOPPED": return label, url, None, 0, "ABORTED"

            try:
                async with session.get(dial_url, headers=req_headers, timeout=timeout, allow_redirects=True, ssl=False) as resp:
                    return label, url, resp.status, int((time.monotonic() - start) * 1000), None
            except asyncio.TimeoutError:
                last_err = "HTTP_TIMEOUT"
                if attempt < RETRY_COUNT:
                    await asyncio.sleep(0.3)
                    continue
                break
            except Exception as e:
                last_err = f"HTTP_ERR: {str(e)[:30]}"
                break

    return label, url, None, int((time.monotonic() - start) * 1000), last_err

# ==========================================
# 5. DASHBOARD UI BUILDER
# ==========================================
def status_label(status: int) -> str:
    if status < 300: return f"[green]HTTP {status} OK[/green]"
    if status < 400: return f"[cyan]HTTP {status} REDIR[/cyan]"
    if status < 500: return f"[yellow]HTTP {status} WARN[/yellow]"
    return f"[red]HTTP {status} ERR[/red]"

def format_latency(latency: int) -> str:
    if latency < 200: return f"[bold green]{latency}ms[/bold green]"
    if latency < 500: return f"[bold yellow]{latency}ms[/bold yellow]"
    return f"[bold red]{latency}ms[/bold red]"

def generate_dashboard(progress_table):
    stats_table = Table(show_header=True, expand=True, border_style="bright_blue")
    stats_table.add_column("Controls", justify="center")
    stats_table.add_column("State", justify="center", width=12)
    stats_table.add_column("UP", justify="center", style="bold green", width=10)
    stats_table.add_column("DOWN", justify="center", style="bold red", width=10)
    stats_table.add_column("POISON", justify="center", style="bold magenta", width=10)
    stats_table.add_column("HIJACK", justify="center", style="bold yellow", width=10)
    stats_table.add_column("Phase", justify="center", style="bold cyan", width=20)
    
    state_color = "cyan" if scanner_state == "RUNNING" else ("yellow" if scanner_state == "PAUSED" else "red")
    stats_table.add_row(
        "P Pause  |  R Resume  |  Q Stop & Save",
        f"[bold {state_color}]{scanner_state}[/]",
        str(stats["open"]),
        str(stats["dead"]),
        str(stats.get("poisoned", 0)),
        str(stats.get("hijacked", 0)),
        scan_phase
    )

    hits_table = Table(show_header=True, expand=True, border_style="bright_black")
    hits_table.add_column("Latency", justify="right", width=12)
    hits_table.add_column("Status", justify="left", width=15)
    hits_table.add_column("Label", justify="left", style="white")
    hits_table.add_column("URL", justify="left", style="bright_black")
    
    for lat, stat, lbl, url in recent_hits:
        hits_table.add_row(format_latency(lat), stat, lbl, url)
        
    for _ in range(8 - len(recent_hits)):
        hits_table.add_row("-", "-", "-", "-")

    return Panel(
        Group(
            progress_table,
            Text(""),
            stats_table,
            Text("\nRecent Active Nodes:", style="bold bright_black"),
            hits_table
            ,
            Text("\nDeveloped by whisper the heaven & ashentajir", style="dim", justify="right")
        ),
        title="[bold blue]WHITEDNS SCANNER[/bold blue]",
        border_style="blue",
        padding=(1, 2)
    )

# ==========================================
# 6. MAIN EXECUTION MENU
# ==========================================
async def main():
    global scanner_state
    global scan_phase

    os.system('cls' if os.name == 'nt' else 'clear')
    console = Console()
    console.print(Panel("[bold cyan]WHITEDNS SCANNER[/bold cyan]\nWelcome to the dashboard setup.", border_style="cyan"))

    input_file = await questionary.text(
        "Enter target list file (e.g., domains.txt):", 
        default="domains.txt"
    ).ask_async()

    input_file = _abs(input_file)

    if not input_file or not os.path.exists(input_file):
        console.print(f"[red][-] Error: Could not find file '{input_file}'[/red]")
        sys.exit(1)

    c_val = await questionary.text(
        "Enter concurrent connections limit (Default: 150):",
        default=str(DEFAULT_CONCURRENT)
    ).ask_async()

    spoofed_sni = await questionary.text(
        "Enter spoofed SNI for DPI bypass (Default: www.speedtest.net):",
        default="www.speedtest.net"
    ).ask_async()
    if not spoofed_sni:
        spoofed_sni = "www.speedtest.net"

    stealth_answer = await questionary.confirm(
        "Enable stealth mode (randomize headers, add jitter)?",
        default=False,
    ).ask_async()
    stealth_mode = bool(stealth_answer)

    try:
        current_max_concurrent = int(c_val) if c_val is not None and c_val != "" else DEFAULT_CONCURRENT
    except Exception:
        current_max_concurrent = DEFAULT_CONCURRENT

    if current_max_concurrent < 1:
        current_max_concurrent = DEFAULT_CONCURRENT

    requested_concurrent = current_max_concurrent
    cpu_count = os.cpu_count() or 4
    streaming_mode = _count_scannable_lines(input_file) > STREAMING_SCAN_THRESHOLD
    if os.path.exists(LAST_PASSED_FILE):
        streaming_mode = streaming_mode or (_count_scannable_lines(LAST_PASSED_FILE) > STREAMING_SCAN_THRESHOLD)

    # Host-aware performance tuning: use more resources on stronger machines,
    # but keep hard ceilings to prevent process/socket exhaustion.
    # On Windows, file descriptor / socket limits are stricter; cap at ~500-1000 total sockets.
    if sys.platform == "win32":
        requested_concurrent = min(requested_concurrent, 512)
        http_socket_limit = min(requested_concurrent + 100, 1024)
    else:
        http_socket_limit = min(requested_concurrent + 200, 5000)

    http_inflight_window = min(requested_concurrent, max(1500, cpu_count * 350))
    http_inflight_window = min(http_inflight_window, 4500)

    dns_worker_cap = 61 if sys.platform == "win32" else 512
    dns_process_workers_count = min(requested_concurrent, cpu_count * 8, dns_worker_cap)
    dns_inflight_window = dns_process_workers_count
    dns_thread_workers = dns_process_workers_count

    console.print(
        "[green][+][/green] Host performance tuning active "
        f"(CPU={cpu_count}, sockets={http_socket_limit}, "
        f"HTTP window={http_inflight_window}, DNS window={dns_inflight_window}, DNS threads={dns_thread_workers})."
    )

    # --- Scan mode selection (to match Go binary options) ---
    console.print("\n[bold]Select scan mode:[/bold]")
    console.print("  1) Default (HTTP reachability - ports 443/80)")
    console.print("  2) All Cloudflare Ports (13 ports)")
    console.print("  3) DNS Discovery Mode (UDP/TCP/DoT/DoH + poisoned detection)")
    console.print("  4) DNS UDP/TCP only (no DoT / no DoH) - faster, less transport coverage")
    mode = await questionary.text(
        "Enter mode number (1/2/3/4/5):",
        default="1"
    ).ask_async()
    mode = (mode or "1").strip()

    dns_mode = False
    scan_all_ports = False
    dns_udp_tcp_only = False
    if mode and mode.startswith("2"):
        scan_all_ports = True
    elif mode and mode.startswith("3"):
        dns_mode = True
    elif mode and mode.startswith("4"):
        dns_mode = True
        dns_udp_tcp_only = True

    prioritized_count = _count_scannable_lines(LAST_PASSED_FILE) if os.path.exists(LAST_PASSED_FILE) else 0
    main_count = _count_scannable_lines(input_file)

    if streaming_mode:
        console.print(
            f"[green][+][/green] Large input mode enabled (estimated lines={prioritized_count + main_count}, streaming batches)."
        )
    else:
        prioritized_targets = []
        if os.path.exists(LAST_PASSED_FILE):
            try:
                prioritized_targets = parse_input(LAST_PASSED_FILE)
                console.print(f"[green][+] Cache: Loaded {len(prioritized_targets)} prioritized targets.[/green]")
            except Exception:
                pass

        try:
            main_targets = parse_input(input_file)
        except Exception as e:
            console.print(f"[red][-] Could not read {input_file}: {e}[/red]")
            sys.exit(1)

        seen = set()
        TARGETS = []
        for lbl, url in prioritized_targets + main_targets:
            if url not in seen:
                seen.add(url)
                TARGETS.append((lbl, url))

        # If scanning all Cloudflare ports, expand each target across the 13 ports
        if scan_all_ports:
            CF_HTTPS_PORTS = [443, 2053, 2083, 2087, 2096, 8443]
            CF_HTTP_PORTS = [80, 8080, 8880, 2052, 2082, 2086, 2095]
            expanded = []
            for lbl, url in TARGETS:
                parsed = urlparse(url)
                host = parsed.hostname
                base_label = lbl
                for p in CF_HTTPS_PORTS:
                    new_url = f"https://{host}:{p}"
                    expanded.append((f"{base_label}:{p}", new_url))
                for p in CF_HTTP_PORTS:
                    new_url = f"http://{host}:{p}"
                    expanded.append((f"{base_label}:{p}", new_url))
            TARGETS = expanded

        # Custom ports: expand targets using user-provided ports
        if 'custom_ports' in locals() and custom_ports:
            expanded = []
            for lbl, url in TARGETS:
                parsed = urlparse(url)
                host = parsed.hostname
                base_label = lbl
                scheme = parsed.scheme or "https"
                for p in custom_ports:
                    new_url = f"{scheme}://{host}:{p}"
                    expanded.append((f"{base_label}:{p}", new_url))
            TARGETS = expanded

        # DNS mode: treat input file as resolver IPs
        if dns_mode:
            dns_targets = []
            for lbl, url in TARGETS:
                host = urlparse(url).hostname or url
                dns_targets.append((lbl or host, host))
            TARGETS = dns_targets

    async def fetch_truth_table(domain: str, session: aiohttp.ClientSession) -> set:
        providers = [
            "https://cloudflare-dns.com/dns-query?name=%s&type=A",
            "https://dns.google/dns-query?name=%s&type=A",
            "https://dns.quad9.net/dns-query?name=%s&type=A",
        ]
        hardcoded_fallbacks = {
            "google.com": {"142.250.80.46", "142.250.80.78", "142.250.80.110"},
            "speedtest.net": {"151.139.72.2"},
            "facebook.com": {"157.240.1.35", "157.240.3.35"},
        }
        headers = {"Accept": "application/dns-json"}
        for p in providers:
            try:
                url = p % domain
                async with session.get(url, headers=headers, timeout=10, ssl=False) as resp:
                    if resp.status != 200:
                        continue
                    data = await resp.json()
                    ips = set()
                    for ans in data.get("Answer", []):
                        if ans.get("type") == 1:
                            ips.add(ans.get("data"))
                        if ips:
                            return ips
            except Exception:
                continue
        if domain in hardcoded_fallbacks:
            return set(hardcoded_fallbacks[domain])
        return set()

    def is_poisoned_answers(answer_ips: set, truth_ips: set) -> bool:
        # Go parity: if no truth table exists, we cannot verify, so treat as clean.
        if not truth_ips:
            return False
        for ip in answer_ips:
            if ip in truth_ips:
                return False
        return len(answer_ips) > 0

    def extract_a_ips(resp):
        ips = []
        if not resp:
            return ips
        for rr in getattr(resp, "answer", []) or []:
            for item in rr.items:
                if hasattr(item, "address"):
                    ips.append(item.address)
        return ips

    def probe_resolver_sync(resolver_ip: str, domain: str, timeout: int = 5, enable_dot: bool = True):
        q = dns.message.make_query(domain, dns.rdatatype.A)
        result = {
            "responded": False,
            "answer_ips": set(),
            "error": "",
            "latency_ms": 0,
            "transports": {
                "udp": {"ok": False, "error": "", "ips": [], "latency_ms": 0},
                "tcp": {"ok": False, "error": "", "ips": [], "latency_ms": 0},
                "dot": {"ok": False, "error": "", "ips": [], "latency_ms": 0},
            },
        }
        start = time.monotonic()

        # UDP/53
        udp_start = time.monotonic()
        try:
            r_udp = dns.query.udp(q, resolver_ip, timeout=timeout, port=53)
            udp_ips = extract_a_ips(r_udp)
            if udp_ips:
                result["transports"]["udp"] = {
                    "ok": True,
                    "error": "",
                    "ips": udp_ips,
                    "latency_ms": int((time.monotonic() - udp_start) * 1000),
                }
                result["responded"] = True
                result["answer_ips"].update(udp_ips)
            else:
                result["transports"]["udp"] = {
                    "ok": False,
                    "error": "UDP_NO_A",
                    "ips": [],
                    "latency_ms": int((time.monotonic() - udp_start) * 1000),
                }
        except Exception as e:
            result["transports"]["udp"]["error"] = str(e)
            result["transports"]["udp"]["latency_ms"] = int((time.monotonic() - udp_start) * 1000)

        # TCP/53
        tcp_start = time.monotonic()
        try:
            r_tcp = dns.query.tcp(q, resolver_ip, timeout=timeout, port=53)
            tcp_ips = extract_a_ips(r_tcp)
            if tcp_ips:
                result["transports"]["tcp"] = {
                    "ok": True,
                    "error": "",
                    "ips": tcp_ips,
                    "latency_ms": int((time.monotonic() - tcp_start) * 1000),
                }
                result["responded"] = True
                result["answer_ips"].update(tcp_ips)
            else:
                result["transports"]["tcp"] = {
                    "ok": False,
                    "error": "TCP_NO_A",
                    "ips": [],
                    "latency_ms": int((time.monotonic() - tcp_start) * 1000),
                }
        except Exception as e:
            result["transports"]["tcp"]["error"] = str(e)
            result["transports"]["tcp"]["latency_ms"] = int((time.monotonic() - tcp_start) * 1000)

        # DoT/853 (optional)
        if enable_dot:
            dot_start = time.monotonic()
            try:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                r_tls = dns.query.tls(q, resolver_ip, timeout=timeout, port=853, ssl_context=ctx)
                dot_ips = extract_a_ips(r_tls)
                if dot_ips:
                    result["transports"]["dot"] = {
                        "ok": True,
                        "error": "",
                        "ips": dot_ips,
                        "latency_ms": int((time.monotonic() - dot_start) * 1000),
                    }
                    result["responded"] = True
                    result["answer_ips"].update(dot_ips)
                else:
                    result["transports"]["dot"] = {
                        "ok": False,
                        "error": "DoT_NO_A",
                        "ips": [],
                        "latency_ms": int((time.monotonic() - dot_start) * 1000),
                    }
            except Exception as e:
                result["transports"]["dot"]["error"] = str(e)
                result["transports"]["dot"]["latency_ms"] = int((time.monotonic() - dot_start) * 1000)
        else:
            result["transports"]["dot"] = {"ok": False, "error": "DOT_DISABLED", "ips": [], "latency_ms": 0}

        if not result["responded"]:
            result["error"] = "NO_UDP_TCP_DOT_RESPONSE"

        result["answer_ips"] = sorted(list(result["answer_ips"]))
        result["latency_ms"] = int((time.monotonic() - start) * 1000)
        return result

    async def probe_doh(resolver_ip: str, domain: str, session: aiohttp.ClientSession):
        url = f"https://{resolver_ip}/dns-query?name={domain}&type=A"
        headers = {"Accept": "application/dns-json"}
        start = time.monotonic()
        try:
            async with session.get(url, headers=headers, timeout=TIMEOUT_SECS, ssl=False) as r:
                if r.status != 200:
                    return {"ok": False, "error": f"HTTP_{r.status}", "ips": [], "latency_ms": int((time.monotonic() - start) * 1000)}
                data = await r.json()
                ips = []
                for ans in data.get("Answer", []):
                    if ans.get("type") == 1:
                        ips.append(ans.get("data"))
                if not ips:
                    return {"ok": False, "error": "DoH_NO_A", "ips": [], "latency_ms": int((time.monotonic() - start) * 1000)}
                return {"ok": True, "error": "", "ips": ips, "latency_ms": int((time.monotonic() - start) * 1000)}
        except Exception as e:
            return {"ok": False, "error": str(e), "ips": [], "latency_ms": int((time.monotonic() - start) * 1000)}

    async def probe_resolver_async(
        label: str,
        resolver_ip: str,
        domain: str,
        session: aiohttp.ClientSession,
        dns_executor: concurrent.futures.Executor,
        enable_dot: bool = True,
        enable_doh: bool = True,
    ):
        loop = asyncio.get_running_loop()
        try:
            sync_res = await loop.run_in_executor(
                dns_executor,
                _dns_probe_all,
                (resolver_ip, domain, max(3, TIMEOUT_SECS // 2), enable_dot),
            )
        except Exception as e:
            sync_res = {
                "responded": False,
                "answer_ips": [],
                "error": str(e),
                "latency_ms": 0,
                "transports": {
                    "udp": {"ok": False, "error": str(e), "ips": []},
                    "tcp": {"ok": False, "error": str(e), "ips": []},
                    "dot": {"ok": False, "error": str(e), "ips": []},
                },
            }

        if enable_doh:
            doh = await probe_doh(resolver_ip, domain, session)
        else:
            doh = {"ok": False, "error": "DOH_DISABLED", "ips": [], "latency_ms": 0}
        if doh["ok"]:
            sync_res["responded"] = True
            merged = set(sync_res.get("answer_ips", []))
            merged.update(doh.get("ips", []))
            sync_res["answer_ips"] = sorted(list(merged))
        sync_res["transports"]["doh"] = doh
        sync_res["label"] = label
        sync_res["resolver"] = resolver_ip
        return sync_res

    if not streaming_mode and not TARGETS:
        console.print("[red][-] No valid targets found to scan.[/red]")
        sys.exit(1)

    # Determine number of transports per target for DNS mode (2 for UDP/TCP-only, 4 for full)
    if streaming_mode:
        stats["total"] = None
    else:
        if dns_mode:
            transports_per_target = 2 if dns_udp_tcp_only else 4
            stats["total"] = len(TARGETS) * transports_per_target
        else:
            stats["total"] = len(TARGETS)
    stats["done"] = 0
    stats["open"] = 0
    stats["dead"] = 0
    stats["poisoned"] = 0
    stats["hijacked"] = 0
    open_results, dead_results = [], []
    poisoned_results = []
    hijacked_results = []

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    open_file = _abs(f"reachable_{timestamp}.txt")
    full_file = _abs(f"full_log_{timestamp}.txt")
    poisoned_file = _abs(f"poisoned_dns_{timestamp}.txt")
    hijacked_file = _abs(f"hijacked_dns_{timestamp}.txt")
    raw_ip_file = _abs(f"raw_ip_dump_{timestamp}.txt")

    scan_complete = False

    async def run_streaming_scan():
        nonlocal scan_complete

        # Cap limit_per_host to prevent socket pool explosion. ~50-100 per host is reasonable for reachability scanning.
        limit_per_host_val = min(requested_concurrent // 4, 100) if requested_concurrent > 50 else 32
        connector = aiohttp.TCPConnector(
            ssl=False,
            limit=http_socket_limit,
            ttl_dns_cache=600,
            use_dns_cache=True,
            force_close=True,
            enable_cleanup_closed=True,
            limit_per_host=limit_per_host_val,
        )
        semaphore = asyncio.Semaphore(requested_concurrent)

        os.system('cls' if os.name == 'nt' else 'clear')
        threading.Thread(target=kb_listener, daemon=True).start()

        progress = Progress(
            "[progress.description]{task.description}",
            BarColumn(bar_width=40),
            "[progress.percentage]{task.percentage:>3.0f}%",
            "|",
            TextColumn("[cyan]{task.completed}/{task.total}[/cyan]"),
            "|",
            TimeElapsedColumn(),
            "|",
            TimeRemainingColumn()
        )
        task_id = progress.add_task("[bold white]Preparing scan...", total=stats["total"] if stats["total"] else None)

        async def ui_loop(live_ctx):
            while scanner_state != "STOPPED" and not scan_complete:
                progress.update(task_id, completed=stats["done"])
                live_ctx.update(generate_dashboard(progress))
                await asyncio.sleep(0.1)

        async def write_open_line(handle, row):
            handle.write(row + "\n")
            handle.flush()

        with open(open_file, "w", encoding="utf-8") as open_handle, \
             open(full_file, "w", encoding="utf-8") as full_handle, \
             open(poisoned_file, "w", encoding="utf-8") as poisoned_handle, \
             open(hijacked_file, "w", encoding="utf-8") as hijacked_handle, \
             open(raw_ip_file, "w", encoding="utf-8") as raw_ip_handle:

            open_handle.write("Reachability Report - OPEN SITES\n")
            open_handle.write(f"Generated        : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            open_handle.write(f"Total tested     : streaming\n")
            open_handle.write("=" * 80 + "\n\n")

            full_handle.write("Reachability Report - FULL LOG\n")
            full_handle.write(f"Generated : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            full_handle.write("=" * 80 + "\n\n")

            if os.path.exists(LAST_PASSED_FILE):
                source_paths = [LAST_PASSED_FILE, input_file]
            else:
                source_paths = [input_file]

            target_iter = iter(_iter_scanned_targets(source_paths, scan_all_ports, dns_mode))

            with Live(generate_dashboard(progress), console=console, refresh_per_second=10, screen=True) as live:
                ui_task = asyncio.create_task(ui_loop(live))

                dns_executor = concurrent.futures.ProcessPoolExecutor(
                    max_workers=dns_process_workers_count,
                    mp_context=multiprocessing.get_context("spawn"),
                )
                dns_submission_semaphore = asyncio.Semaphore(dns_process_workers_count)

                async with aiohttp.ClientSession(connector=connector, headers=HEADERS) as session:
                    try:
                        if dns_mode:
                            scan_phase = "Building truth table"
                            progress.update(task_id, description="[bold white]Building DNS truth table...")
                            truth_ips = await fetch_truth_table("google.com", session)

                            scan_phase = "DNS probing"
                            progress.update(task_id, description="[bold white]Probing DNS transports...")

                            in_flight = set()

                            async def schedule_dns_next():
                                try:
                                    lbl, host = next(target_iter)
                                except StopIteration:
                                    return False

                                await dns_submission_semaphore.acquire()

                                async def _run_and_release(l, h, ed, eh):
                                    try:
                                        return await probe_resolver_async(l, h, "google.com", session, dns_executor, enable_dot=ed, enable_doh=eh)
                                    finally:
                                        try:
                                            dns_submission_semaphore.release()
                                        except Exception:
                                            pass

                                ed_flag = not dns_udp_tcp_only
                                eh_flag = not dns_udp_tcp_only
                                in_flight.add(asyncio.create_task(_run_and_release(lbl, host, ed_flag, eh_flag)))
                                return True

                            for _ in range(dns_inflight_window):
                                ok = await schedule_dns_next()
                                if not ok:
                                    break

                            while in_flight:
                                while scanner_state == "PAUSED":
                                    await asyncio.sleep(0.2)
                                if scanner_state == "STOPPED":
                                    break

                                done, pending = await asyncio.wait(in_flight, timeout=0.05, return_when=asyncio.FIRST_COMPLETED)
                                if not done:
                                    continue
                                in_flight = pending
                                for fut in done:
                                    try:
                                        res = await fut
                                    except Exception as e:
                                        res = {
                                            "label": "resolver",
                                            "resolver": "unknown",
                                            "responded": False,
                                            "answer_ips": [],
                                            "error": str(e),
                                            "latency_ms": 0,
                                            "transports": {
                                                "udp": {"ok": False, "error": str(e), "ips": []},
                                                "tcp": {"ok": False, "error": str(e), "ips": []},
                                                "dot": {"ok": False, "error": str(e), "ips": []},
                                                "doh": {"ok": False, "error": str(e), "ips": []},
                                            },
                                        }

                                    label = res.get("label", "resolver")
                                    resolver = res.get("resolver", "unknown")
                                    tports = res.get("transports", {})
                                    transport_defs = [("udp", "UDP", 53), ("tcp", "TCP", 53)] if dns_udp_tcp_only else [("udp", "UDP", 53), ("tcp", "TCP", 53), ("dot", "DoT", 853), ("doh", "DoH", 443)]

                                    for key, proto_name, port in transport_defs:
                                        stats["done"] += 1
                                        pdata = tports.get(key, {"ok": False, "error": "NO_RESULT", "ips": []})
                                        ok = bool(pdata.get("ok", False))
                                        answers = set(pdata.get("ips", []))
                                        latency = pdata.get("latency_ms", res.get("latency_ms", 0))
                                        target_url = f"dns://{resolver}:{port}"

                                        poisoned = ok and is_poisoned_answers(answers, truth_ips)
                                        hijacked = False
                                        for ans in answers:
                                            try:
                                                ip_obj = ipaddress.ip_address(ans)
                                                if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local or ip_obj.is_multicast or ip_obj.is_unspecified or ip_obj.is_reserved:
                                                    hijacked = True
                                                    break
                                            except ValueError:
                                                continue

                                        if ok and not poisoned:
                                            stats["open"] += 1
                                            recent_hits.append((latency, f"{proto_name} OK", label, resolver))
                                            await write_open_line(open_handle, f"{label:<24}  {target_url:<24}  {1:<5}  {latency:>6}ms  {proto_name:<6}  {','.join(sorted(list(answers))) if answers else '<no-answer>'}")
                                        else:
                                            err = pdata.get("error") if not ok else "POISONED"
                                            stats["dead"] += 1
                                            await write_open_line(full_handle, f"DEAD    {latency:>6}ms  {err:<15}  {label:<25}  {target_url:<24}  {proto_name:<6}  {','.join(sorted(list(answers))) if answers else '-'}")
                                            if poisoned:
                                                stats["poisoned"] += 1
                                                poisoned_handle.write(f"{label:<24}  {resolver:<22}  {proto_name:<6}  {latency:>6}ms  {','.join(sorted(list(answers))) if answers else '<no-answer>'}\n")
                                            if hijacked:
                                                stats["hijacked"] += 1
                                                hijacked_handle.write(f"{label:<24}  {resolver:<22}  {proto_name:<6}  {latency:>6}ms  {','.join(sorted(list(answers))) if answers else '<no-answer>'}\n")

                                    try:
                                        await schedule_dns_next()
                                    except Exception:
                                        pass

                            for p in in_flight:
                                p.cancel()

                        else:
                            scan_phase = "HTTP probing"
                            progress.update(task_id, description="[bold white]Scanning HTTP targets...")
                            in_flight = set()

                            async def schedule_http_next():
                                try:
                                    lbl, url = next(target_iter)
                                except StopIteration:
                                    return False
                                in_flight.add(asyncio.create_task(check_url(session, lbl, url, semaphore, spoofed_sni=spoofed_sni, stealth=stealth_mode)))
                                return True

                            for _ in range(requested_concurrent):
                                ok = await schedule_http_next()
                                if not ok:
                                    break

                            while in_flight:
                                while scanner_state == "PAUSED":
                                    await asyncio.sleep(0.2)
                                if scanner_state == "STOPPED":
                                    break

                                done, pending = await asyncio.wait(in_flight, timeout=0.05, return_when=asyncio.FIRST_COMPLETED)
                                if not done:
                                    continue
                                in_flight = pending
                                for coro in done:
                                    try:
                                        res = await coro
                                    except Exception as e:
                                        res = ("unknown", "unknown", None, 0, str(e))

                                    stats["done"] += 1
                                    label, url, status, latency, error = res
                                    if error == "ABORTED":
                                        continue

                                    if status is not None:
                                        stats["open"] += 1
                                        recent_hits.append((latency, status_label(status), label, url))
                                        await write_open_line(open_handle, f"{label:<40}  {url:<24}  {status:>5}  {latency:>6}ms")
                                    else:
                                        stats["dead"] += 1
                                        if error == "DNS_FAILED":
                                            stats["poisoned"] += 1
                                        await write_open_line(full_handle, f"DEAD    {latency:>6}ms  {error:<15}  {label:<40}  {url}")

                                    await schedule_http_next()

                            for p in in_flight:
                                p.cancel()

                        scan_complete = True
                        scan_phase = "Finalizing reports"
                        progress.update(task_id, description="[bold white]Finalizing reports...")
                    finally:
                        dns_executor.shutdown(wait=False, cancel_futures=True)

                await ui_task
                progress.update(task_id, completed=stats["done"])
                live.update(generate_dashboard(progress))

        console.print(f"\n[bold green]DONE[/bold green] - {stats['open']}/{stats['done']} reachable")
        if stats["poisoned"]:
            console.print(f"[bold magenta]Poisoned DNS[/bold magenta] - {stats['poisoned']} entries")
            console.print(f"[cyan][+][/cyan] Poisoned results -> {poisoned_file}")
        if stats["hijacked"]:
            console.print(f"[bold yellow]Hijacked DNS[/bold yellow] - {stats['hijacked']} entries")
            console.print(f"[cyan][+][/cyan] Hijacked results -> {hijacked_file}")
        console.print(f"[cyan][+][/cyan] Cache updated -> {LAST_PASSED_FILE}")
        console.print(f"[cyan][+][/cyan] Open results  -> {open_file}")
        console.print(f"[cyan][+][/cyan] Full log      -> {full_file}\n")
        console.print(f"[cyan][+][/cyan] Raw IP dump   -> {raw_ip_file}\n")
        return

    if streaming_mode:
        await run_streaming_scan()
        return

    connector = aiohttp.TCPConnector(
        ssl=False,
        limit=http_socket_limit,
        ttl_dns_cache=600,
        use_dns_cache=True,
        force_close=True,
        enable_cleanup_closed=True,
        limit_per_host=0,
    )
    semaphore = asyncio.Semaphore(requested_concurrent)

    os.system('cls' if os.name == 'nt' else 'clear')

    threading.Thread(target=kb_listener, daemon=True).start()

    progress = Progress(
        "[progress.description]{task.description}",
        BarColumn(bar_width=40),
        "[progress.percentage]{task.percentage:>3.0f}%",
        "|",
        TextColumn("[cyan]{task.completed}/{task.total}[/cyan]"),
        "|",
        TimeElapsedColumn(),
        "|",
        TimeRemainingColumn()
    )
    task_id = progress.add_task("[bold white]Preparing scan...", total=stats["total"])

    async def ui_loop(live_ctx):
        while scanner_state != "STOPPED" and not scan_complete:
            progress.update(task_id, completed=stats["done"])
            live_ctx.update(generate_dashboard(progress))
            await asyncio.sleep(0.1)

    with Live(generate_dashboard(progress), console=console, refresh_per_second=10, screen=True) as live:
        ui_task = asyncio.create_task(ui_loop(live))

        dns_executor = concurrent.futures.ProcessPoolExecutor(
            max_workers=dns_process_workers_count,
            mp_context=multiprocessing.get_context("spawn"),
        )
        # Prevent overwhelming the ProcessPoolExecutor with far more queued tasks
        # than it can reasonably handle. Limit how many DNS probe tasks we
        # submit concurrently using an asyncio.Semaphore. This provides
        # backpressure at the asyncio scheduling level and avoids file/socket
        # exhaustion when requested_concurrent is very large.
        dns_submission_limit = dns_process_workers_count
        dns_submission_semaphore = asyncio.Semaphore(dns_submission_limit)
        debug_log = None

        async with aiohttp.ClientSession(connector=connector, headers=HEADERS) as session:
            if dns_mode:
                scan_phase = "Building truth table"
                progress.update(task_id, description="[bold white]Building DNS truth table...")
                # DNS discovery: fetch truth table first
                truth_ips = await fetch_truth_table("google.com", session)

                scan_phase = "DNS probing"
                progress.update(task_id, description="[bold white]Probing DNS transports...")

                target_iter = iter(TARGETS)
                in_flight = set()

                # Effective in-flight window must not exceed the submission limit
                effective_dns_window = min(dns_inflight_window, dns_submission_limit, len(TARGETS))

                async def schedule_dns_next():
                    try:
                        lbl, host = next(target_iter)
                    except StopIteration:
                        return False

                    # Acquire a slot before scheduling to bound pending tasks
                    await dns_submission_semaphore.acquire()

                    async def _run_and_release(l, h, ed, eh):
                        try:
                            return await probe_resolver_async(l, h, "google.com", session, dns_executor, enable_dot=ed, enable_doh=eh)
                        finally:
                            try:
                                dns_submission_semaphore.release()
                            except Exception:
                                pass

                    ed_flag = not dns_udp_tcp_only
                    eh_flag = not dns_udp_tcp_only
                    task = asyncio.create_task(_run_and_release(lbl, host, ed_flag, eh_flag))
                    in_flight.add(task)
                    return True

                for _ in range(effective_dns_window):
                    ok = await schedule_dns_next()
                    if not ok:
                        break

                # Main DNS probe loop: wait for completions, then schedule more.
                while in_flight:
                    while scanner_state == "PAUSED":
                        await asyncio.sleep(0.2)
                    if scanner_state == "STOPPED":
                        break

                    done, pending = await asyncio.wait(
                        in_flight,
                        timeout=0.05,
                        return_when=asyncio.FIRST_COMPLETED,
                    )
                    if not done:
                        continue
                    in_flight = pending
                    for fut in done:
                        try:
                            res = await fut
                        except Exception as e:
                            res = {
                                "label": "resolver",
                                "resolver": "unknown",
                                "responded": False,
                                "answer_ips": [],
                                "error": str(e),
                                "latency_ms": 0,
                                "transports": {
                                    "udp": {"ok": False, "error": str(e), "ips": []},
                                    "tcp": {"ok": False, "error": str(e), "ips": []},
                                    "dot": {"ok": False, "error": str(e), "ips": []},
                                    "doh": {"ok": False, "error": str(e), "ips": []},
                                },
                            }

                        label = res.get("label", "resolver")
                        resolver = res.get("resolver", "unknown")
                        tports = res.get("transports", {})
                        if dns_udp_tcp_only:
                            transport_defs = [
                                ("udp", "UDP", 53),
                                ("tcp", "TCP", 53),
                            ]
                        else:
                            transport_defs = [
                                ("udp", "UDP", 53),
                                ("tcp", "TCP", 53),
                                ("dot", "DoT", 853),
                                ("doh", "DoH", 443),
                            ]

                        for key, proto_name, port in transport_defs:
                            stats["done"] += 1
                            pdata = tports.get(key, {"ok": False, "error": "NO_RESULT", "ips": []})
                            ok = bool(pdata.get("ok", False))
                            answers = set(pdata.get("ips", []))
                            latency = pdata.get("latency_ms", res.get("latency_ms", 0))
                            target_url = f"dns://{resolver}:{port}"

                            poisoned = ok and is_poisoned_answers(answers, truth_ips)

                            hijacked = False
                            for ans in answers:
                                try:
                                    ip_obj = ipaddress.ip_address(ans)
                                    if (
                                        ip_obj.is_private
                                        or ip_obj.is_loopback
                                        or ip_obj.is_link_local
                                        or ip_obj.is_multicast
                                        or ip_obj.is_unspecified
                                        or ip_obj.is_reserved
                                    ):
                                        hijacked = True
                                        break
                                except ValueError:
                                    continue

                            if hijacked:
                                hijacked_results.append((label, resolver, proto_name, latency, sorted(list(answers))))
                                stats["hijacked"] += 1

                            if ok and not poisoned:
                                open_results.append((label, target_url, 1, latency, proto_name, sorted(list(answers))))
                                stats["open"] += 1
                                recent_hits.append((latency, f"{proto_name} OK", label, resolver))
                            else:
                                err = pdata.get("error") if not ok else "POISONED"
                                dead_results.append((label, target_url, err, latency, proto_name, sorted(list(answers))))
                                stats["dead"] += 1
                                if poisoned:
                                    poisoned_results.append((label, resolver, proto_name, latency, sorted(list(answers))))
                                    stats["poisoned"] += 1

                        # attempt to schedule another probe to keep the pipeline full
                        try:
                            await schedule_dns_next()
                        except Exception:
                            pass

                for p in in_flight:
                    p.cancel()

            else:
                scan_phase = "HTTP probing"
                progress.update(task_id, description="[bold white]Scanning HTTP targets...")
                target_iter = iter(TARGETS)
                in_flight = set()

                async def schedule_http_next():
                    try:
                        lbl, url = next(target_iter)
                    except StopIteration:
                        return False
                    in_flight.add(asyncio.create_task(check_url(session, lbl, url, semaphore, spoofed_sni=spoofed_sni, stealth=stealth_mode)))
                    return True

                for _ in range(min(requested_concurrent, len(TARGETS))):
                    ok = await schedule_http_next()
                    if not ok:
                        break

                while in_flight:
                    while scanner_state == "PAUSED":
                        await asyncio.sleep(0.2)
                    if scanner_state == "STOPPED":
                        break

                    done, pending = await asyncio.wait(
                        in_flight,
                        timeout=0.05,
                        return_when=asyncio.FIRST_COMPLETED,
                    )
                    if not done:
                        continue
                    in_flight = pending
                    for coro in done:
                        try:
                            res = await coro
                        except Exception as e:
                            res = ("unknown", "unknown", None, 0, str(e))

                        stats["done"] += 1

                        label, url, status, latency, error = res
                        if error == "ABORTED":
                            continue

                        if status is not None:
                            open_results.append((label, url, status, latency))
                            stats["open"] += 1
                            recent_hits.append((latency, status_label(status), label, url))
                        else:
                            dead_results.append((label, url, error, latency))
                            if error == "DNS_FAILED":
                                poisoned_results.append((label, url, latency))
                                stats["poisoned"] += 1
                            stats["dead"] += 1

                        await schedule_http_next()

                for p in in_flight:
                    p.cancel()
            dns_executor.shutdown(wait=False, cancel_futures=True)

            scan_phase = "Finalizing reports"
            progress.update(task_id, description="[bold white]Finalizing reports...")
        scanner_state = "STOPPED"
        await ui_task
        progress.update(task_id, completed=stats["done"])
        live.update(generate_dashboard(progress))

    actual_tested = len(open_results) + len(dead_results)
    if actual_tested == 0:
        console.print("\n[yellow][-] Scan was aborted before any results were collected.[/yellow]")
        sys.exit(0)
    
    open_results.sort(key=lambda x: x[3])
    
    with open(open_file, "w", encoding="utf-8") as f:
        f.write("Reachability Report - OPEN SITES\n")
        f.write(f"Generated        : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"Total tested     : {actual_tested} / {stats['total']}\n")
        f.write(f"Open (reachable) : {len(open_results)}\n")
        f.write(f"Closed / Dead    : {len(dead_results)}\n")
        f.write(f"Poisoned DNS     : {len(poisoned_results)}\n")
        f.write(f"Hijacked DNS     : {len(hijacked_results)}\n")
        f.write("=" * 80 + "\n\n")
        f.write(f"{'#':<4}  {'Latency':>8}  {'HTTP':>5}  {'Label':<40}  URL\n")
        f.write("-" * 80 + "\n")
        if dns_mode:
            f.write(f"{'#':<4}  {'Latency':>8}  {'Mode':>6}  {'Label':<24}  {'Target':<24}  Answers\n")
            f.write("-" * 120 + "\n")
            for i, (label, target, status, latency, proto_name, answers) in enumerate(open_results, 1):
                f.write(
                    f"{i:<4}  {latency:>6}ms  {proto_name:>6}  {label:<24}  {target:<24}  "
                    f"{','.join(answers) if answers else '<no-answer>'}\n"
                )
        else:
            for i, (label, url, status, latency) in enumerate(open_results, 1):
                f.write(f"{i:<4}  {latency:>6}ms  {status:>5}  {label:<40}  {url}\n")
        f.write("\n\n" + "=" * 80 + "\n")
        f.write("CLOSED / UNREACHABLE (DNS/TCP/TLS/HTTP Errors)\n")
        f.write("=" * 80 + "\n")
        if dns_mode:
            for label, target, error, latency, proto_name, answers in sorted(dead_results, key=lambda x: x[0]):
                f.write(
                    f"  {label:<24}  {target:<24}  [{proto_name}] [{error}] "
                    f"Answers={','.join(answers) if answers else '<no-answer>'}\n"
                )
        else:
            for label, url, error, latency in sorted(dead_results, key=lambda x: x[0]):
                f.write(f"  {label:<40}  [{error}]\n")
        if poisoned_results:
            f.write("\n" + "=" * 80 + "\n")
            f.write("POISONED DNS\n")
            f.write("=" * 80 + "\n")
            if dns_mode:
                for label, resolver, proto_name, latency, answers in sorted(poisoned_results, key=lambda x: x[0]):
                    f.write(
                        f"  {label:<24}  {resolver:<22}  [{proto_name}] [{latency}ms] "
                        f"Answers={','.join(answers) if answers else '<no-answer>'}\n"
                    )
            else:
                for label, url, latency in sorted(poisoned_results, key=lambda x: x[0]):
                    f.write(f"  {label:<40}  [{latency}ms]  {url}\n")

        if hijacked_results:
            f.write("\n" + "=" * 80 + "\n")
            f.write("HIJACKED DNS\n")
            f.write("=" * 80 + "\n")
            for label, resolver, proto_name, latency, answers in sorted(hijacked_results, key=lambda x: x[0]):
                f.write(
                    f"  {label:<24}  {resolver:<22}  [{proto_name}] [{latency}ms] "
                    f"Answers={','.join(answers) if answers else '<no-answer>'}\n"
                )

    with open(LAST_PASSED_FILE, "w", encoding="utf-8") as f:
        f.write("# Auto-saved cache of last passed domains\n")
        if dns_mode:
            seen_dns = set()
            for label, url, _, _, _, _ in open_results:
                key = f"{label}|{url}"
                if key in seen_dns:
                    continue
                seen_dns.add(key)
                f.write(f"{label} | {url}\n")
        else:
            for label, url, _, _ in open_results:
                f.write(f"{label} | {url}\n")

    if dns_mode:
        all_rows = (
            [
                (lbl, target, proto, lat, "OPEN", "-", ",".join(answers) if answers else "<no-answer>")
                for lbl, target, _, lat, proto, answers in open_results
            ] +
            [
                (lbl, target, f"{proto}:{err or 'DEAD'}", lat, "DEAD", "-", ",".join(answers) if answers else "-")
                for lbl, target, err, lat, proto, answers in dead_results
            ]
        )
    else:
        all_rows = (
            [(lbl, url, str(st), lat, "OPEN", "-", "-") for lbl, url, st, lat in open_results] +
            [(lbl, url, err or "DEAD", lat, "DEAD", "-", "-") for lbl, url, err, lat in dead_results]
        )
    all_rows.sort(key=lambda x: x[0])
    with open(full_file, "w", encoding="utf-8") as f:
        f.write("Reachability Report - FULL LOG\n")
        f.write(f"Generated : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write("=" * 80 + "\n\n")
        f.write(f"{'Tag':<6}  {'Latency':>8}  {'HTTP/Err':<15}  {'Label':<25}  {'Target':<24}  {'Transports':<26}  Answers\n")
        f.write("-" * 80 + "\n")
        for lbl, url, s, lat, tag, trans_summary, answers in all_rows:
            f.write(f"{tag:<6}  {lat:>6}ms  {s:<15}  {lbl:<25}  {url:<24}  {trans_summary:<26}  {answers}\n")

    # Write standalone poisoned DNS report if any poisoned entries were collected
    if poisoned_results:
        with open(poisoned_file, "w", encoding="utf-8") as pf:
            pf.write("Poisoned DNS Report\n")
            pf.write(f"Generated : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            pf.write("=" * 80 + "\n\n")
            if dns_mode:
                pf.write(f"{'Label':<24}  {'Resolver':<22}  {'Proto':<6}  {'Latency':>8}  Answers\n")
                pf.write("-" * 110 + "\n")
                for label, resolver, proto_name, latency, answers in sorted(poisoned_results, key=lambda x: x[0]):
                    pf.write(
                        f"{label:<24}  {resolver:<22}  {proto_name:<6}  {latency:>6}ms  "
                        f"{','.join(answers) if answers else '<no-answer>'}\n"
                    )
            else:
                pf.write(f"{'Label':<40}  {'Latency':>8}  URL\n")
                pf.write("-" * 80 + "\n")
                for label, url, latency in sorted(poisoned_results, key=lambda x: x[0]):
                    pf.write(f"{label:<40}  {latency:>6}ms  {url}\n")

    if hijacked_results:
        with open(hijacked_file, "w", encoding="utf-8") as hf:
            hf.write("Hijacked DNS Report\n")
            hf.write(f"Generated : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            hf.write("=" * 80 + "\n\n")
            hf.write(f"{'Label':<24}  {'Resolver':<22}  {'Proto':<6}  {'Latency':>8}  Answers\n")
            hf.write("-" * 110 + "\n")
            for label, resolver, proto_name, latency, answers in sorted(hijacked_results, key=lambda x: x[0]):
                hf.write(
                    f"{label:<24}  {resolver:<22}  {proto_name:<6}  {latency:>6}ms  "
                    f"{','.join(answers) if answers else '<no-answer>'}\n"
                )

    # Extra plain raw-IP dump (no labels, no headers) from passed/poisoned/hijacked sets.
    raw_ip_values = set()
    if dns_mode:
        for _, target, _, _, _, answers in open_results:
            t_host = urlparse(target).hostname
            if t_host:
                raw_ip_values.add(t_host)
            for a in answers:
                raw_ip_values.add(a)

        for _, resolver, _, _, answers in poisoned_results:
            raw_ip_values.add(resolver)
            for a in answers:
                raw_ip_values.add(a)

        for _, resolver, _, _, answers in hijacked_results:
            raw_ip_values.add(resolver)
            for a in answers:
                raw_ip_values.add(a)
    else:
        # HTTP mode: dump IP-like hosts from reachable/dead URLs.
        for _, url, _, _ in open_results:
            h = urlparse(url).hostname
            if h:
                try:
                    ipaddress.ip_address(h)
                    raw_ip_values.add(h)
                except ValueError:
                    pass
        for _, url, _, _ in dead_results:
            h = urlparse(url).hostname
            if h:
                try:
                    ipaddress.ip_address(h)
                    raw_ip_values.add(h)
                except ValueError:
                    pass

    with open(raw_ip_file, "w", encoding="utf-8") as rf:
        for ip in sorted(raw_ip_values):
            rf.write(f"{ip}\n")
        

    pct = len(open_results) / actual_tested * 100 if actual_tested else 0
    console.print(f"\n[bold green]DONE[/bold green] - {len(open_results)}/{actual_tested} reachable ({pct:.1f}%)")
    if actual_tested < stats['total']:
        console.print(f"[bold yellow][!] SCAN ABORTED EARLY - Saved {actual_tested} completed tests.[/bold yellow]")
    if poisoned_results:
        console.print(f"[bold magenta]Poisoned DNS[/bold magenta] - {len(poisoned_results)} entries")
        if dns_mode:
            for label, resolver, proto_name, latency, answers in sorted(poisoned_results, key=lambda x: x[0]):
                console.print(
                    f"[magenta]  -[/magenta] {label}  [{latency}ms]  {resolver}  [{proto_name}]  "
                    f"answers={','.join(answers) if answers else '<no-answer>'}"
                )
        else:
            for label, url, latency in sorted(poisoned_results, key=lambda x: x[0]):
                console.print(f"[magenta]  -[/magenta] {label}  [{latency}ms]  {url}")
        console.print(f"[cyan][+][/cyan] Poisoned results -> {poisoned_file}")
    if hijacked_results:
        console.print(f"[bold yellow]Hijacked DNS[/bold yellow] - {len(hijacked_results)} entries")
        for label, resolver, proto_name, latency, answers in sorted(hijacked_results, key=lambda x: x[0]):
            console.print(
                f"[yellow]  -[/yellow] {label}  [{latency}ms]  {resolver}  [{proto_name}]  "
                f"answers={','.join(answers) if answers else '<no-answer>'}"
            )
        console.print(f"[cyan][+][/cyan] Hijacked results -> {hijacked_file}")
    console.print(f"[cyan][+][/cyan] Cache updated -> {LAST_PASSED_FILE}")
    console.print(f"[cyan][+][/cyan] Open results  -> {open_file}")
    console.print(f"[cyan][+][/cyan] Full log      -> {full_file}\n")
    console.print(f"[cyan][+][/cyan] Raw IP dump   -> {raw_ip_file}\n")


if __name__ == "__main__":
    multiprocessing.freeze_support()
    if sys.platform == "win32":
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n[!] Force interrupted by user (Ctrl+C).")
        sys.exit(1)
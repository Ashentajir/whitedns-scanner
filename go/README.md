Scanner Package — README

Files included:
- scanner_py.exe — standalone scanner executable (onefile PyInstaller build).
- cloudflareCdnScanner.py — original Python source (for inspection or rebuild).
- requirements-pyinstaller.txt — list of pip packages used for building.
- scanner_py.exe.spec — PyInstaller spec file used for the build (optional).
- README.md — this file.

Usage
1. Run the scanner interactively from a command prompt:
   scanner_py.exe

2. Select input file (e.g., domains.txt) and choose scan mode:
   - 1: HTTP reachability (ports 443/80)
   - 2: All Cloudflare ports (13 ports)
   - 3: DNS Discovery (UDP/TCP/DoT/DoH + poisoned detection)
   - 4: DNS UDP/TCP only (no DoT / no DoH) — faster and lower resource usage

3. Outputs produced (in the working directory):
   - reachable_<timestamp>.txt  — list of open targets
   - full_log_<timestamp>.txt  — full per-target transport details
   - poisoned_dns_<timestamp>.txt — standalone poisoned resolver entries
   - hijacked_dns_<timestamp>.txt — standalone hijacked resolver entries
   - raw_ip_dump_<timestamp>.txt — plain raw IP list
   - dns_debug_<timestamp>.log — debug log for DNS submission/backpressure (when enabled)

Notes & Safety
- The EXE includes bundled Python runtime and libraries; it can be large.
- Running this scanner performs active network probes. Use responsibly and only against targets you are authorized to test.
- Some antivirus / SmartScreen systems may flag onefile PyInstaller binaries. Verify in a safe sandbox/VM before broad distribution.

Need a checksum or zip with different contents? Reply and I'll add SHA256 and create alternate packages.

# Cloudflare CDN Scanner

This repository contains a scanner for checking Cloudflare-backed targets and related DNS behavior. It includes both the Go implementation under `go/` and the packaged Windows executables in the repository root.

## Included Files

- `scanner.exe` - Go-based Windows executable.
- `scanner_py.exe` - Python/PyInstaller Windows executable.
- `go/` - Go source, build scripts, and the scanner engine.
- `python/` - Python source and packaging files.
- `cidrs.txt`, `domains.txt` - sample input lists used by the scanner.

## Quick Start

1. Build the Go scanner:

   ```bash
   go build -o scanner.exe ./cmd/scanner
   ```

2. Run the scanner and provide an input file such as `domains.txt`.

3. Review the generated output files in the repository root, including:

   - `reachable_<timestamp>.txt`
   - `full_log_<timestamp>.txt`
   - `poisoned_dns_<timestamp>.txt`
   - `hijacked_dns_<timestamp>.txt`
   - `raw_ip_dump_<timestamp>.txt`

## Notes

- The scanner performs active network probing, so only use it on targets you are authorized to test.
- Some build outputs are intentionally ignored by git, but the two packaged executables are kept trackable in the repository root.
are we there yet ?
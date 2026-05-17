# Testing Guide - Scanner Bug Fixes

## What Was Fixed

### PRIMARY FIX: Halfway Scan Termination
- **Root Cause**: Result channel buffer was too small, causing data loss under concurrent load
- **Solution**: Increased buffer sizes from 4x to 16x with 256 minimum
- **Result**: All DNS probe results now complete successfully

### Secondary Improvements:
1. Added debug logging to track result counts
2. Improved buffer sizing for both regular and streaming modes
3. Better handling of multi-protocol DNS bursts

---

## Quick Test (Recommended)

### Test 1: Verify Debug Output
```bash
# Run a small DNS scan
.\scanner.exe --dns --input test_resolvers.txt --domain google.com --output . --timeout 10

# Check for debug file
Get-Content debug_count_*.txt | tail -10

# Expected output should show collected results close to (10 resolvers × 4 protocols = 40)
```

### Test 2: Compare Before/After
Use the old scanner.exe and new scanner.exe on the same input:
```bash
# Old version (from backup or prior build)
.\scanner_old.exe --dns --input test_resolvers.txt --domain google.com --output old_results

# New version
.\scanner.exe --dns --input test_resolvers.txt --domain google.com --output new_results

# Compare reports
Compare-Object (Get-Content old_results/poisoned_dns_*.txt) `
              (Get-Content new_results/poisoned_dns_*.txt)
```

### Test 3: Large File Scan
```bash
# Full scan on larger resolver list
.\scanner.exe --dns --input domains.txt --domain google.com --timeout 5

# Monitor for:
# 1. Completion (no early exit)
# 2. All 4 protocols per resolver
# 3. Complete poisoned_dns report
# 4. Debug count file showing ~= expected
```

---

## What to Expect

### Reports Generated:
- `reachable_TIMESTAMP.txt` - Working DNS resolvers
- `full_log_TIMESTAMP.txt` - All results with detailed errors
- `poisoned_dns_TIMESTAMP.txt` - Resolvers returning wrong answers  
- `hijacked_dns_TIMESTAMP.txt` - Resolvers responding from private IPs
- `raw_ip_dump_TIMESTAMP.txt` - All discovered unique IPs
- `debug_count_TIMESTAMP.txt` - Result collection statistics

### Debug Count File
Shows:
- Expected Total: len(resolvers) × 4 protocols
- Actually Collected: Sum of all result categories
- Breakdown by category (Open, Dead, Poisoned)

**✓ Success**: Actually Collected ≈ Expected Total

---

## Troubleshooting

### Issue: Debug file shows much less than expected
**Possible Causes:**
- Timeouts preventing all protocols completing
- Some resolvers unreachable
- Network issues

**Solution:**
- Increase `--timeout` value
- Check network connectivity
- Verify resolver IPs are valid

### Issue: Hijacked DNS report still empty
**Explanation:** 
- Google's DNS answer (216.239.38.120) is PUBLIC, not hijacked
- Hijacked report only shows PRIVATE IP responses
- This is correct behavior

### Issue: Raw IP dump seems small
**Check:**
- Number of unique IPs across all categories
- Look at full_log for actual responses
- Compare to poisoned_dns report

---

## Performance Notes

### Recommended Settings:
```bash
# For large files (1000+ resolvers)
.\scanner.exe --dns --input large_list.txt --domain google.com --timeout 5 --max-concurrent 500

# For quick tests
.\scanner.exe --dns --input test.txt --domain google.com --timeout 10
```

### Resource Usage:
- Memory: ~50-100 MB typical
- CPU: Scales with concurrent workers
- Network: Burst traffic during probes

---

## Files Included

- `scanner.exe` - Updated executable with fixes
- `FIXES_SUMMARY.md` - Detailed technical summary
- `TESTING_GUIDE.md` - This file
- `test_resolvers.txt` - Sample 10 resolver IPs for testing

---

## Next Steps

1. Run Test 1 (Quick Debug Output Test)
2. Run Test 2 (Large File if available)
3. Review debug_count files to verify no data loss
4. Share results or findings

---

Questions or Issues?
- Check debug_count file for result counts
- Look for timeout errors in full_log
- Verify network connectivity to resolvers

Version: 2.0 with Buffer Fixes
Date: 2026-05-06

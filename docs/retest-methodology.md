# Network VAPT Re-testing Methodology

The core purpose of a retest is to determine whether previously reported weaknesses remain exploitable or whether the exposure has been materially reduced.

## Lifecycle

```
Baseline Scan
     ↓
Finding Inventory
     ↓
Remediation
     ↓
Retest Scan
     ↓
Normalize Results
     ↓
Compare
     ↓
Retest Status
     ↓
Management Report
```

## Retest States

- **OPEN:** finding is still observed.
- **FIXED:** baseline finding is no longer observed.
- **CHANGED:** the exposure changed and needs analyst review.
- **NOT_RETESTED:** no comparable evidence exists.
- **INCONCLUSIVE:** results cannot be reliably compared.

## Comparison Principles

Comparison should use stable attributes where possible:

- Asset
- Port/protocol
- Service
- Finding title
- Rule identifier

Version strings alone should not be treated as proof of remediation.

## Evidence

Each retest should preserve:

- Scan timestamp
- Target scope
- Nmap command/options
- Raw machine-readable results
- Baseline report
- Retest report
- Analyst decision

This repository is designed around authorized systems and safe discovery. It does not automatically exploit services to prove remediation.

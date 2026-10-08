# Network VAPT & Vulnerability Re-testing Automation

A lightweight Python security assessment assistant for **authorized labs and systems**.

## What it does

1. Runs Nmap service/version discovery.
2. Parses Nmap XML output.
3. Lists open TCP ports and detected services.
4. Maps common exposed services to rule-based security assessment leads.
5. Assigns a conservative severity to each lead.
6. Suggests an appropriate **security testing/validation method**.
7. Generates HTML and JSON reports.

> The rule engine provides assessment leads, not proof that a target is exploitable. Always validate findings manually and only test systems you are authorized to assess.

## Requirements

- Python 3.9+
- Nmap installed and available as `nmap` in PATH.

No third-party Python packages are required.

## Usage

```bash
python vapt.py 192.168.1.10
```

Optional port selection:

```bash
python vapt.py 192.168.1.10 -p 1-1000
```

Custom report names:

```bash
python vapt.py 192.168.1.10 -o report.html --json results.json
```

## Output

- `vapt_report.html` — readable assessment report
- `vapt_results.json` — machine-readable scan results

## Architecture

```text
Target
  |
  v
Nmap -sV
  |
  v
XML Parser
  |
  +--> Open Ports / Services
  |
  v
Rule-Based Assessment Engine
  |
  +--> Potential Issue
  +--> Severity
  +--> Recommended Test
  |
  v
HTML + JSON Report
```

## Future improvements

- CVE feed integration with an offline/local cache
- CVSS calculation
- Nmap NSE result parsing
- Retest mode comparing two JSON results
- PDF report generation
- More service-specific assessment rules


## Re-testing Workflow

Use [retest.py](retest.py) to compare two machine-readable scan results:

```bash
python retest.py baseline.json retest.json
```

The comparison classifies observations as **OPEN**, **FIXED**, or **CHANGED** based on stable finding attributes. It is an analyst aid, not proof of exploitability.

See [docs/retest-methodology.md](docs/retest-methodology.md) for the full workflow and [docs/retest-report-template.md](docs/retest-report-template.md) for reporting.
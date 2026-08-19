#!/usr/bin/env python3
"""
Network VAPT & Vulnerability Re-testing Automation
Authorized-lab scanner: Nmap-based discovery + rule-based assessment + HTML report.
"""

import argparse
import html
import json
import os
import shutil
import subprocess
import sys
import xml.etree.ElementTree as ET
from datetime import datetime


def require_nmap():
    if shutil.which("nmap") is None:
        print("[!] Nmap was not found in PATH.")
        print("    Install Nmap and make sure the nmap command works.")
        sys.exit(1)


def run_nmap(target, ports=None):
    # XML output makes parsing reliable.
    cmd = ["nmap", "-sV", "-T3", "-oX", "-", target]
    if ports:
        cmd.insert(1, "-p")
        cmd.insert(2, ports)

    print("[+] Running:", " ".join(cmd))
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)

    if result.returncode != 0:
        print("[!] Nmap failed:")
        print(result.stderr.strip())
        sys.exit(1)

    return result.stdout


def parse_nmap(xml_text):
    root = ET.fromstring(xml_text)
    hosts = []

    for host in root.findall("host"):
        status = host.find("status")
        if status is not None and status.get("state") != "up":
            continue

        addresses = []
        for addr in host.findall("address"):
            if addr.get("addr"):
                addresses.append(addr.get("addr"))

        hostname = ""
        hn = host.find("./hostnames/hostname")
        if hn is not None:
            hostname = hn.get("name", "")

        ports = []
        for p in host.findall("./ports/port"):
            state = p.find("state")
            if state is None or state.get("state") != "open":
                continue

            service = p.find("service")
            ports.append({
                "port": int(p.get("portid", 0)),
                "protocol": p.get("protocol", ""),
                "service": service.get("name", "") if service is not None else "",
                "product": service.get("product", "") if service is not None else "",
                "version": service.get("version", "") if service is not None else "",
                "extra": service.get("extrainfo", "") if service is not None else "",
            })

        hosts.append({
            "address": addresses[0] if addresses else "unknown",
            "addresses": addresses,
            "hostname": hostname,
            "ports": ports
        })

    return hosts


def load_rules(path):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def assess(hosts, rules):
    findings = []

    for host in hosts:
        for p in host["ports"]:
            service_text = " ".join([
                p["service"], p["product"], p["version"], p["extra"]
            ]).lower()

            for rule in rules:
                matched = False

                if rule.get("ports") and p["port"] in rule["ports"]:
                    matched = True

                for term in rule.get("keywords", []):
                    if term.lower() in service_text:
                        matched = True

                if matched:
                    findings.append({
                        "host": host["address"],
                        "port": p["port"],
                        "service": p["service"],
                        "product": p["product"],
                        "version": p["version"],
                        "title": rule["title"],
                        "severity": rule["severity"],
                        "reason": rule["reason"],
                        "recommendation": rule["recommendation"],
                        "references": rule.get("references", [])
                    })

    return findings


def severity_rank(value):
    return {"Critical": 4, "High": 3, "Medium": 2, "Low": 1, "Info": 0}.get(value, 0)


def render_report(target, hosts, findings, output):
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    rows = []
    for f in sorted(findings, key=lambda x: severity_rank(x["severity"]), reverse=True):
        refs = "<br>".join(html.escape(x) for x in f["references"]) or "-"
        rows.append(f"""
        <tr>
          <td>{html.escape(f["host"])}</td>
          <td>{f["port"]}/{html.escape(f["service"])}</td>
          <td>{html.escape(f["product"] + " " + f["version"]).strip() or "-"}</td>
          <td><b>{html.escape(f["severity"])}</b></td>
          <td>{html.escape(f["title"])}</td>
          <td>{html.escape(f["reason"])}</td>
          <td>{html.escape(f["recommendation"])}</td>
          <td>{refs}</td>
        </tr>""")

    port_rows = []
    for host in hosts:
        for p in host["ports"]:
            port_rows.append(f"""
            <tr>
              <td>{html.escape(host["address"])}</td>
              <td>{p["port"]}/{html.escape(p["protocol"])}</td>
              <td>{html.escape(p["service"])}</td>
              <td>{html.escape(p["product"] + " " + p["version"]).strip() or "-"}</td>
            </tr>""")

    document = f"""<!doctype html>
<html>
<head>
<meta charset="utf-8">
<title>Network VAPT Report - {html.escape(target)}</title>
<style>
body {{ font-family: Arial, sans-serif; margin: 32px; color: #222; }}
h1 {{ margin-bottom: 4px; }}
small {{ color: #666; }}
table {{ border-collapse: collapse; width: 100%; margin: 18px 0 30px; }}
th, td {{ border: 1px solid #ccc; padding: 8px; text-align: left; vertical-align: top; }}
th {{ background: #eee; }}
.card {{ display:inline-block; padding:12px 18px; border:1px solid #ddd; margin-right:8px; }}
</style>
</head>
<body>
<h1>Network VAPT & Vulnerability Re-testing Report</h1>
<small>Target: {html.escape(target)} | Generated: {now}</small>

<h2>Summary</h2>
<div class="card">Hosts up: {len(hosts)}</div>
<div class="card">Open services: {sum(len(h["ports"]) for h in hosts)}</div>
<div class="card">Potential findings: {len(findings)}</div>

<h2>Open Services</h2>
<table>
<tr><th>Host</th><th>Port</th><th>Service</th><th>Product / Version</th></tr>
{''.join(port_rows) or '<tr><td colspan="4">No open TCP services detected.</td></tr>'}
</table>

<h2>Rule-Based Assessment</h2>
<p>Findings are <b>potential assessment leads</b> based on detected ports/services. They are not proof of exploitability.</p>
<table>
<tr><th>Host</th><th>Port / Service</th><th>Product / Version</th><th>Severity</th>
<th>Finding</th><th>Reason</th><th>Recommended Test</th><th>References</th></tr>
{''.join(rows) or '<tr><td colspan="8">No rule-based findings.</td></tr>'}
</table>
</body>
</html>"""

    with open(output, "w", encoding="utf-8") as f:
        f.write(document)


def save_json(target, hosts, findings, output):
    data = {
        "target": target,
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "hosts": hosts,
        "findings": findings
    }
    with open(output, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)


def main():
    parser = argparse.ArgumentParser(
        description="Nmap-based Network VAPT assessment assistant for authorized targets."
    )
    parser.add_argument("target", help="Authorized IP address, hostname, or lab target")
    parser.add_argument("-p", "--ports", help="Optional Nmap port expression, e.g. 1-1000 or 22,80,443")
    parser.add_argument("--rules", default="rules.json", help="Assessment rule file")
    parser.add_argument("-o", "--output", default="vapt_report.html", help="HTML report path")
    parser.add_argument("--json", default="vapt_results.json", help="JSON results path")
    args = parser.parse_args()

    require_nmap()

    if not os.path.exists(args.rules):
        print(f"[!] Rule file not found: {args.rules}")
        sys.exit(1)

    xml_text = run_nmap(args.target, args.ports)
    hosts = parse_nmap(xml_text)
    rules = load_rules(args.rules)
    findings = assess(hosts, rules)

    print(f"\n[+] Hosts up: {len(hosts)}")
    print(f"[+] Open services: {sum(len(h['ports']) for h in hosts)}")
    print(f"[+] Potential findings: {len(findings)}")

    for f in sorted(findings, key=lambda x: severity_rank(x["severity"]), reverse=True):
        print(f"  [{f['severity']}] {f['host']}:{f['port']} - {f['title']}")
        print(f"      Test: {f['recommendation']}")

    render_report(args.target, hosts, findings, args.output)
    save_json(args.target, hosts, findings, args.json)

    print(f"\n[+] HTML report: {args.output}")
    print(f"[+] JSON results: {args.json}")


if __name__ == "__main__":
    main()

"""
Web Application Module
----------------------
Flask backend providing dashboard visualizations, live monitoring streams,
batch CSV flow analysis, and firewall blocklist management.
"""

from typing import List, Dict, Any
from collections import deque, Counter
from datetime import datetime
import io
import csv
import random
import os
import sys

# Ensure project root is in python path
ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

from flask import Flask, render_template, request, jsonify, redirect, url_for, Response
import pandas as pd
import numpy as np

from core.flow_analyzer import FlowRecord, FEATURE_NAMES, sanitize_dataframe
from core.blocklist_manager import BlocklistManager
from core.threat_engine import ThreatEngine, ThreatVerdict

app = Flask(
    __name__,
    template_folder=os.path.join(os.path.dirname(__file__), "templates"),
    static_folder=os.path.join(os.path.dirname(__file__), "static"),
)
app.config["SECRET_KEY"] = "iids-secure-key-2026"
app.config["MAX_CONTENT_LENGTH"] = 32 * 1024 * 1024  # 32 MB max upload

# System instances
blocklist_manager = BlocklistManager(filepath=os.path.join(ROOT_DIR, "data", "blocklist.json"))
threat_engine = ThreatEngine(
    model_path=os.path.join(ROOT_DIR, "ml", "trained_model.joblib"),
    blocklist=blocklist_manager,
)

# In-memory recent events buffer (max 300)
event_history: deque = deque(maxlen=300)
system_stats = {
    "total_inspected": 0,
    "total_threats": 0,
    "total_benign": 0,
    "verdict_counts": Counter(),
    "severity_counts": Counter(),
    "protocol_counts": Counter(),
}


def log_verdict(verdict: ThreatVerdict):
    """Update global rolling metrics and append verdict to history."""
    system_stats["total_inspected"] += 1
    if verdict.is_threat:
        system_stats["total_threats"] += 1
    else:
        system_stats["total_benign"] += 1

    system_stats["verdict_counts"][verdict.verdict] += 1
    system_stats["severity_counts"][verdict.severity] += 1
    system_stats["protocol_counts"][verdict.protocol] += 1

    event_history.appendleft(verdict.to_dict())


# Sample attack IP pools for live stream simulation
KNOWN_ATTACKERS = [
    "192.168.1.105",
    "10.0.0.88",
    "172.16.2.45",
    "198.51.100.23",
    "203.0.113.19",
]
BENIGN_CLIENTS = [
    "192.168.1.12",
    "192.168.1.15",
    "192.168.1.20",
    "10.0.0.5",
    "172.16.1.10",
]


@app.route("/")
def index():
    """Main security dashboard."""
    recent_events = list(event_history)[:12]
    blocked_count = blocklist_manager.count()
    return render_template(
        "dashboard.html",
        stats=system_stats,
        recent_events=recent_events,
        blocked_count=blocked_count,
    )


@app.route("/monitor")
def monitor():
    """Live traffic flow monitoring console."""
    return render_template("monitor.html")


@app.route("/analyze", methods=["GET", "POST"])
def analyze():
    """Batch CSV network flow file analysis."""
    if request.method == "POST":
        file = request.files.get("file")
        if not file or file.filename == "":
            return render_template("analyze.html", error="Please upload a valid CSV file.")

        try:
            df = pd.read_csv(file)
            df = sanitize_dataframe(df)

            results = []
            for _, row in df.head(100).iterrows():
                src_ip = str(row.get("src_ip", f"192.168.1.{random.randint(2, 250)}"))
                src_port = int(row.get("src_port", random.randint(1024, 65535)))
                dst_ip = str(row.get("dst_ip", "10.0.0.1"))
                dst_port = int(row.get("dst_port", random.choice([80, 443, 22, 21, 8080])))
                protocol = str(row.get("protocol", "TCP"))

                features = {feat: float(row.get(feat, 0.0)) for feat in FEATURE_NAMES}
                flow = FlowRecord(src_ip, src_port, dst_ip, dst_port, protocol, features)
                verdict = threat_engine.evaluate(flow)
                log_verdict(verdict)
                results.append(verdict.to_dict())

            return render_template("analyze.html", results=results, total=len(results))
        except Exception as e:
            return render_template("analyze.html", error=f"Processing failed: {str(e)}")

    return render_template("analyze.html")


@app.route("/firewall", methods=["GET", "POST"])
def firewall():
    """Quarantine firewall blocklist management."""
    if request.method == "POST":
        action = request.form.get("action")
        ip = request.form.get("ip", "").strip()
        reason = request.form.get("reason", "Manual Operator Rule").strip()
        severity = request.form.get("severity", "HIGH")

        if action == "block" and ip:
            blocklist_manager.block_ip(ip, reason=reason, severity=severity)
        elif action == "unblock" and ip:
            blocklist_manager.unblock_ip(ip)

        return redirect(url_for("firewall"))

    blocked_entries = blocklist_manager.get_all()
    return render_template("firewall.html", blocked_entries=blocked_entries)


# ================= API Endpoints =================

@app.route("/api/stats")
def api_stats():
    """Aggregated stats for dynamic dashboard charts."""
    return jsonify({
        "total_inspected": system_stats["total_inspected"],
        "total_threats": system_stats["total_threats"],
        "total_benign": system_stats["total_benign"],
        "verdict_distribution": dict(system_stats["verdict_counts"]),
        "severity_distribution": dict(system_stats["severity_counts"]),
        "protocol_distribution": dict(system_stats["protocol_counts"]),
        "blocked_ips_count": blocklist_manager.count(),
    })


@app.route("/api/simulate-flow")
def api_simulate_flow():
    """Generate and evaluate a realistic simulated flow event."""
    is_attack_sim = random.random() < 0.35

    if is_attack_sim:
        src_ip = random.choice(KNOWN_ATTACKERS)
        attack_type = random.choice(["DDoS", "PortScan", "BruteForce", "WebAttack"])
        if attack_type == "PortScan":
            dst_port = random.randint(20, 1024)
            features = {
                "flow_duration": random.randint(10, 500),
                "total_fwd_packets": 1,
                "total_bwd_packets": 0,
                "total_fwd_bytes": 48,
                "total_bwd_bytes": 0,
                "syn_flag_count": 1,
                "flow_packets_per_sec": 3000,
                "flow_bytes_per_sec": 1500,
            }
        elif attack_type == "DDoS":
            dst_port = random.choice([80, 443])
            features = {
                "flow_duration": random.randint(500, 10000),
                "total_fwd_packets": random.randint(200, 800),
                "total_bwd_packets": 0,
                "total_fwd_bytes": random.randint(100000, 800000),
                "total_bwd_bytes": 0,
                "syn_flag_count": 1,
                "flow_packets_per_sec": 12000,
                "flow_bytes_per_sec": 2000000,
            }
        else:
            dst_port = 22 if attack_type == "BruteForce" else 8080
            features = {
                "flow_duration": random.randint(20000, 200000),
                "total_fwd_packets": 18,
                "total_bwd_packets": 12,
                "total_fwd_bytes": 2400,
                "total_bwd_bytes": 1600,
                "rst_flag_count": 1,
                "syn_flag_count": 1,
                "flow_packets_per_sec": 80,
                "flow_bytes_per_sec": 15000,
            }
        protocol = "TCP"
    else:
        src_ip = random.choice(BENIGN_CLIENTS)
        dst_port = random.choice([80, 443, 53, 8080])
        protocol = "UDP" if dst_port == 53 else "TCP"
        features = {
            "flow_duration": random.randint(5000, 500000),
            "total_fwd_packets": random.randint(4, 25),
            "total_bwd_packets": random.randint(3, 20),
            "total_fwd_bytes": random.randint(500, 8000),
            "total_bwd_bytes": random.randint(1000, 25000),
            "syn_flag_count": 1 if protocol == "TCP" else 0,
            "ack_flag_count": 1 if protocol == "TCP" else 0,
            "flow_packets_per_sec": random.uniform(5, 50),
            "flow_bytes_per_sec": random.uniform(1000, 40000),
        }

    # Ensure all feature names are populated with defaults
    full_features = {k: float(features.get(k, 0.0)) for k in FEATURE_NAMES}
    flow = FlowRecord(
        src_ip=src_ip,
        src_port=random.randint(1025, 65000),
        dst_ip="10.0.0.1",
        dst_port=dst_port,
        protocol=protocol,
        features=full_features,
    )

    verdict = threat_engine.evaluate(flow)
    log_verdict(verdict)
    return jsonify(verdict.to_dict())


@app.route("/api/events")
def api_events():
    """Retrieve recent threat log events."""
    return jsonify(list(event_history))


@app.route("/api/clear")
def api_clear():
    """Clear memory logs."""
    event_history.clear()
    for k in system_stats["verdict_counts"]:
        system_stats["verdict_counts"][k] = 0
    system_stats["total_inspected"] = 0
    system_stats["total_threats"] = 0
    system_stats["total_benign"] = 0
    return jsonify({"status": "cleared"})


@app.route("/export/threats.csv")
def export_csv():
    """Export event log as downloadable CSV file."""
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow([
        "Timestamp", "Source IP", "Source Port", "Destination IP",
        "Destination Port", "Protocol", "Verdict", "Severity",
        "Confidence", "Source", "Explanation"
    ])
    for ev in event_history:
        writer.writerow([
            ev["timestamp"], ev["src_ip"], ev["src_port"],
            ev["dst_ip"], ev["dst_port"], ev["protocol"],
            ev["verdict"], ev["severity"], ev["confidence"],
            ev["detector_source"], ev["explanation"]
        ])
    output.seek(0)
    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment;filename=threat_events.csv"}
    )


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)

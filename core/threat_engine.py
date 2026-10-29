"""
Threat Engine Module
--------------------
Combines Machine Learning inference with stateful heuristic inspection
to detect network threats and anomalies in real time.
"""

from typing import Dict, Any, Optional, Set
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta
import joblib
import os
import numpy as np

from core.flow_analyzer import FlowRecord, FEATURE_NAMES
from core.blocklist_manager import BlocklistManager


@dataclass
class ThreatVerdict:
    """Structured result returned by the threat engine for an inspected flow."""
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    protocol: str
    is_threat: bool
    verdict: str           # e.g., 'BENIGN', 'DDoS', 'PortScan', 'BruteForce', 'Quarantined'
    confidence: float      # 0.0 - 1.0
    severity: str          # 'NORMAL', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'
    detector_source: str   # 'BLOCKLIST', 'HEURISTIC_RULE', 'ML_CLASSIFIER'
    explanation: str
    timestamp: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "src_ip": self.src_ip,
            "src_port": self.src_port,
            "dst_ip": self.dst_ip,
            "dst_port": self.dst_port,
            "protocol": self.protocol,
            "is_threat": self.is_threat,
            "verdict": self.verdict,
            "confidence": round(float(self.confidence), 4),
            "severity": self.severity,
            "detector_source": self.detector_source,
            "explanation": self.explanation,
            "timestamp": self.timestamp,
        }


class ThreatEngine:
    """Intelligent detection engine with hybrid Machine Learning + Rule layers."""

    def __init__(
        self,
        model_path: str = "ml/trained_model.joblib",
        blocklist: Optional[BlocklistManager] = None,
        port_scan_threshold: int = 12,
        scan_window_seconds: int = 15,
    ):
        self.model_path = model_path
        self.blocklist = blocklist or BlocklistManager()
        self.port_scan_threshold = port_scan_threshold
        self.scan_window = timedelta(seconds=scan_window_seconds)

        # Stateful trackers: IP -> list of (timestamp, dst_port)
        self._port_history: Dict[str, list] = defaultdict(list)
        self._syn_history: Dict[str, list] = defaultdict(list)

        self.model = self._load_model()

    def _load_model(self):
        """Load trained ML model artifact if present."""
        if os.path.exists(self.model_path):
            try:
                return joblib.load(self.model_path)
            except Exception as e:
                print(f"[Warning] Failed to load model from {self.model_path}: {e}")
        return None

    def reload_model(self):
        """Reload the model from disk (e.g. after retraining)."""
        self.model = self._load_model()

    def _check_port_scan(self, src_ip: str, dst_port: int, now: datetime) -> bool:
        """Heuristic rule: Detect rapid multi-port scanning sweeps."""
        cutoff = now - self.scan_window
        history = [entry for entry in self._port_history[src_ip] if entry[0] > cutoff]
        history.append((now, dst_port))
        self._port_history[src_ip] = history

        distinct_ports: Set[int] = {p for _, p in history}
        return len(distinct_ports) >= self.port_scan_threshold

    def _check_syn_flood(self, src_ip: str, syn_count: float, now: datetime) -> bool:
        """Heuristic rule: Detect abnormal SYN burst rate."""
        if syn_count > 0:
            cutoff = now - self.scan_window
            history = [t for t in self._syn_history[src_ip] if t > cutoff]
            history.append(now)
            self._syn_history[src_ip] = history
            return len(history) >= 20
        return False

    def evaluate(self, flow: FlowRecord) -> ThreatVerdict:
        """Perform comprehensive hybrid threat evaluation on a flow record."""
        now = datetime.now()
        timestamp_str = now.strftime("%Y-%m-%d %H:%M:%S")

        # Layer 1: Firewall Blocklist Check
        if self.blocklist.is_blocked(flow.src_ip):
            return ThreatVerdict(
                src_ip=flow.src_ip,
                src_port=flow.src_port,
                dst_ip=flow.dst_ip,
                dst_port=flow.dst_port,
                protocol=flow.protocol,
                is_threat=True,
                verdict="QUARANTINED",
                confidence=1.0,
                severity="CRITICAL",
                detector_source="BLOCKLIST",
                explanation=f"Traffic from {flow.src_ip} dropped due to active quarantine policy.",
                timestamp=timestamp_str,
            )

        # Layer 2: Stateful Heuristic Rules
        if self._check_port_scan(flow.src_ip, flow.dst_port, now):
            return ThreatVerdict(
                src_ip=flow.src_ip,
                src_port=flow.src_port,
                dst_ip=flow.dst_ip,
                dst_port=flow.dst_port,
                protocol=flow.protocol,
                is_threat=True,
                verdict="PortScan",
                confidence=0.98,
                severity="HIGH",
                detector_source="HEURISTIC_RULE",
                explanation=f"Host scanned >= {self.port_scan_threshold} distinct ports in a short window.",
                timestamp=timestamp_str,
            )

        syn_count = float(flow.features.get("syn_flag_count", 0))
        if self._check_syn_flood(flow.src_ip, syn_count, now):
            return ThreatVerdict(
                src_ip=flow.src_ip,
                src_port=flow.src_port,
                dst_ip=flow.dst_ip,
                dst_port=flow.dst_port,
                protocol=flow.protocol,
                is_threat=True,
                verdict="SYN_Flood",
                confidence=0.95,
                severity="HIGH",
                detector_source="HEURISTIC_RULE",
                explanation="Abnormal burst of SYN packets with no completion.",
                timestamp=timestamp_str,
            )

        # Layer 3: Machine Learning Model Inference
        features_vec = flow.to_feature_vector().reshape(1, -1)

        if self.model is not None:
            try:
                pred_proba = self.model.predict_proba(features_vec)[0]
                classes = list(self.model.classes_)
                
                # Determine attack vs benign
                if 1 in classes:
                    attack_idx = classes.index(1)
                    threat_prob = float(pred_proba[attack_idx])
                elif "ATTACK" in classes:
                    attack_idx = classes.index("ATTACK")
                    threat_prob = float(pred_proba[attack_idx])
                else:
                    threat_prob = float(pred_proba[1]) if len(pred_proba) > 1 else 0.0

                is_threat = threat_prob >= 0.5
                verdict = "ATTACK" if is_threat else "BENIGN"
                
                # Heuristic labeling based on flow characteristics
                if is_threat:
                    duration = flow.features.get("flow_duration", 0)
                    bytes_sec = flow.features.get("flow_bytes_per_sec", 0)
                    pkts = flow.features.get("total_fwd_packets", 0) + flow.features.get("total_bwd_packets", 0)

                    if bytes_sec > 500000 or pkts > 200:
                        verdict = "DDoS"
                        severity = "CRITICAL" if threat_prob > 0.85 else "HIGH"
                    elif flow.dst_port in (21, 22, 3389) and pkts < 30:
                        verdict = "BruteForce"
                        severity = "HIGH"
                    elif flow.dst_port in (80, 443, 8080) and bytes_sec > 50000:
                        verdict = "WebAttack"
                        severity = "MEDIUM"
                    else:
                        verdict = "MaliciousFlow"
                        severity = "MEDIUM"

                    confidence = threat_prob
                    explanation = f"ML model flagged flow with {confidence:.1%} confidence."
                else:
                    severity = "NORMAL"
                    confidence = 1.0 - threat_prob
                    explanation = "Flow characteristics match normal baseline behavior."

                return ThreatVerdict(
                    src_ip=flow.src_ip,
                    src_port=flow.src_port,
                    dst_ip=flow.dst_ip,
                    dst_port=flow.dst_port,
                    protocol=flow.protocol,
                    is_threat=is_threat,
                    verdict=verdict,
                    confidence=confidence,
                    severity=severity,
                    detector_source="ML_CLASSIFIER",
                    explanation=explanation,
                    timestamp=timestamp_str,
                )

            except Exception as e:
                pass  # Fallback to rule/default if model inference fails

        # Fallback when model is not available
        return ThreatVerdict(
            src_ip=flow.src_ip,
            src_port=flow.src_port,
            dst_ip=flow.dst_ip,
            dst_port=flow.dst_port,
            protocol=flow.protocol,
            is_threat=False,
            verdict="BENIGN",
            confidence=0.90,
            severity="NORMAL",
            detector_source="HEURISTIC_RULE",
            explanation="Traffic evaluated with baseline heuristic filter.",
            timestamp=timestamp_str,
        )

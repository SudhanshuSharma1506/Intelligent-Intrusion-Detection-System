"""
Flow Analyzer Module
--------------------
Handles network flow feature extraction, transformation, and validation
for the Intelligent Intrusion Detection System (IIDS).
"""

from typing import Dict, Any, List
import numpy as np
import pandas as pd

# Core 24 flow features aligned with high-performance intrusion detection
FEATURE_NAMES: List[str] = [
    "flow_duration",
    "total_fwd_packets",
    "total_bwd_packets",
    "total_fwd_bytes",
    "total_bwd_bytes",
    "fwd_packet_length_max",
    "fwd_packet_length_min",
    "fwd_packet_length_mean",
    "bwd_packet_length_mean",
    "flow_bytes_per_sec",
    "flow_packets_per_sec",
    "flow_iat_mean",
    "flow_iat_std",
    "flow_iat_max",
    "fwd_iat_total",
    "syn_flag_count",
    "fin_flag_count",
    "rst_flag_count",
    "psh_flag_count",
    "ack_flag_count",
    "down_up_ratio",
    "avg_packet_size",
    "active_mean",
    "idle_mean",
]


class FlowRecord:
    """Represents an analyzed network flow between two endpoints."""

    def __init__(
        self,
        src_ip: str,
        src_port: int,
        dst_ip: str,
        dst_port: int,
        protocol: str,
        features: Dict[str, float],
    ):
        self.src_ip = src_ip
        self.src_port = src_port
        self.dst_ip = dst_ip
        self.dst_port = dst_port
        self.protocol = protocol.upper()
        self.features = features

    def to_dict(self) -> Dict[str, Any]:
        """Convert flow metadata and features to a flat dictionary."""
        data = {
            "src_ip": self.src_ip,
            "src_port": self.src_port,
            "dst_ip": self.dst_ip,
            "dst_port": self.dst_port,
            "protocol": self.protocol,
        }
        data.update(self.features)
        return data

    def to_feature_vector(self) -> np.ndarray:
        """Extract ordered numerical feature vector matching FEATURE_NAMES."""
        return np.array([float(self.features.get(k, 0.0)) for k in FEATURE_NAMES], dtype=np.float32)


def sanitize_dataframe(df: pd.DataFrame) -> pd.DataFrame:
    """Clean infinite and NaN values often present in network capture data."""
    df_clean = df.copy()
    for col in FEATURE_NAMES:
        if col in df_clean.columns:
            df_clean[col] = pd.to_numeric(df_clean[col], errors="coerce").fillna(0.0)
            df_clean[col] = df_clean[col].replace([np.inf, -np.inf], 0.0)
        else:
            df_clean[col] = 0.0
    return df_clean

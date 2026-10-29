"""
Dataset Generator Module
------------------------
Generates high-fidelity synthetic network flow data modeled on the
CICIDS2017 benchmark distribution for training and offline validation.
"""

from typing import Tuple
import numpy as np
import pandas as pd
from core.flow_analyzer import FEATURE_NAMES


def generate_benchmark_dataset(num_samples: int = 6000, random_seed: int = 42) -> pd.DataFrame:
    """Generate balanced network flow samples spanning benign and malicious patterns."""
    rng = np.random.default_rng(random_seed)

    # 60% benign, 40% attacks across attack categories
    n_benign = int(num_samples * 0.60)
    n_ddos = int(num_samples * 0.15)
    n_portscan = int(num_samples * 0.12)
    n_bruteforce = int(num_samples * 0.08)
    n_webattack = num_samples - (n_benign + n_ddos + n_portscan + n_bruteforce)

    records = []

    # 1. BENIGN Traffic
    for _ in range(n_benign):
        rec = {
            "flow_duration": rng.integers(10_000, 5_000_000),
            "total_fwd_packets": rng.integers(3, 40),
            "total_bwd_packets": rng.integers(2, 35),
            "total_fwd_bytes": rng.integers(200, 15_000),
            "total_bwd_bytes": rng.integers(500, 45_000),
            "fwd_packet_length_max": rng.integers(64, 1500),
            "fwd_packet_length_min": rng.integers(20, 64),
            "fwd_packet_length_mean": rng.uniform(80, 500),
            "bwd_packet_length_mean": rng.uniform(100, 1000),
            "flow_bytes_per_sec": rng.uniform(500, 50_000),
            "flow_packets_per_sec": rng.uniform(2, 100),
            "flow_iat_mean": rng.uniform(1000, 50_000),
            "flow_iat_std": rng.uniform(100, 10_000),
            "flow_iat_max": rng.uniform(5000, 100_000),
            "fwd_iat_total": rng.uniform(5000, 2_000_000),
            "syn_flag_count": rng.choice([0, 1], p=[0.7, 0.3]),
            "fin_flag_count": rng.choice([0, 1], p=[0.8, 0.2]),
            "rst_flag_count": rng.choice([0, 1], p=[0.95, 0.05]),
            "psh_flag_count": rng.choice([0, 1], p=[0.5, 0.5]),
            "ack_flag_count": rng.choice([0, 1], p=[0.2, 0.8]),
            "down_up_ratio": rng.uniform(0.5, 3.0),
            "avg_packet_size": rng.uniform(100, 800),
            "active_mean": rng.uniform(0, 10_000),
            "idle_mean": rng.uniform(0, 50_000),
            "label": 0,
            "category": "BENIGN",
        }
        records.append(rec)

    # 2. DDoS Traffic
    for _ in range(n_ddos):
        rec = {
            "flow_duration": rng.integers(500, 50_000),
            "total_fwd_packets": rng.integers(150, 1000),
            "total_bwd_packets": rng.integers(0, 5),
            "total_fwd_bytes": rng.integers(50_000, 1_000_000),
            "total_bwd_bytes": rng.integers(0, 500),
            "fwd_packet_length_max": rng.integers(1000, 1500),
            "fwd_packet_length_min": rng.integers(64, 500),
            "fwd_packet_length_mean": rng.uniform(500, 1400),
            "bwd_packet_length_mean": rng.uniform(0, 100),
            "flow_bytes_per_sec": rng.uniform(500_000, 10_000_000),
            "flow_packets_per_sec": rng.uniform(1000, 50_000),
            "flow_iat_mean": rng.uniform(10, 500),
            "flow_iat_std": rng.uniform(5, 100),
            "flow_iat_max": rng.uniform(50, 1000),
            "fwd_iat_total": rng.uniform(500, 45_000),
            "syn_flag_count": rng.choice([1, 2], p=[0.8, 0.2]),
            "fin_flag_count": 0,
            "rst_flag_count": rng.choice([0, 1], p=[0.7, 0.3]),
            "psh_flag_count": 0,
            "ack_flag_count": 0,
            "down_up_ratio": 0.0,
            "avg_packet_size": rng.uniform(600, 1400),
            "active_mean": 0.0,
            "idle_mean": 0.0,
            "label": 1,
            "category": "DDoS",
        }
        records.append(rec)

    # 3. PortScan Traffic
    for _ in range(n_portscan):
        rec = {
            "flow_duration": rng.integers(10, 2000),
            "total_fwd_packets": rng.integers(1, 3),
            "total_bwd_packets": rng.integers(0, 1),
            "total_fwd_bytes": rng.integers(40, 120),
            "total_bwd_bytes": rng.integers(0, 60),
            "fwd_packet_length_max": rng.integers(40, 64),
            "fwd_packet_length_min": rng.integers(40, 64),
            "fwd_packet_length_mean": rng.uniform(40, 60),
            "bwd_packet_length_mean": rng.uniform(0, 40),
            "flow_bytes_per_sec": rng.uniform(100, 10_000),
            "flow_packets_per_sec": rng.uniform(500, 5000),
            "flow_iat_mean": rng.uniform(1, 50),
            "flow_iat_std": rng.uniform(0, 10),
            "flow_iat_max": rng.uniform(5, 100),
            "fwd_iat_total": rng.uniform(10, 1500),
            "syn_flag_count": 1,
            "fin_flag_count": 0,
            "rst_flag_count": rng.choice([0, 1], p=[0.5, 0.5]),
            "psh_flag_count": 0,
            "ack_flag_count": 0,
            "down_up_ratio": 0.0,
            "avg_packet_size": rng.uniform(40, 64),
            "active_mean": 0.0,
            "idle_mean": 0.0,
            "label": 1,
            "category": "PortScan",
        }
        records.append(rec)

    # 4. BruteForce Traffic
    for _ in range(n_bruteforce):
        rec = {
            "flow_duration": rng.integers(50_000, 500_000),
            "total_fwd_packets": rng.integers(10, 30),
            "total_bwd_packets": rng.integers(8, 25),
            "total_fwd_bytes": rng.integers(1000, 4000),
            "total_bwd_bytes": rng.integers(800, 3000),
            "fwd_packet_length_max": rng.integers(100, 400),
            "fwd_packet_length_min": rng.integers(20, 60),
            "fwd_packet_length_mean": rng.uniform(60, 200),
            "bwd_packet_length_mean": rng.uniform(60, 180),
            "flow_bytes_per_sec": rng.uniform(5000, 30_000),
            "flow_packets_per_sec": rng.uniform(40, 200),
            "flow_iat_mean": rng.uniform(500, 5000),
            "flow_iat_std": rng.uniform(100, 1500),
            "flow_iat_max": rng.uniform(1000, 15_000),
            "fwd_iat_total": rng.uniform(40_000, 450_000),
            "syn_flag_count": 1,
            "fin_flag_count": 1,
            "rst_flag_count": rng.choice([1, 2], p=[0.7, 0.3]),
            "psh_flag_count": 1,
            "ack_flag_count": 1,
            "down_up_ratio": rng.uniform(0.7, 1.2),
            "avg_packet_size": rng.uniform(70, 180),
            "active_mean": rng.uniform(100, 2000),
            "idle_mean": rng.uniform(0, 5000),
            "label": 1,
            "category": "BruteForce",
        }
        records.append(rec)

    # 5. WebAttack Traffic
    for _ in range(n_webattack):
        rec = {
            "flow_duration": rng.integers(100_000, 3_000_000),
            "total_fwd_packets": rng.integers(8, 50),
            "total_bwd_packets": rng.integers(5, 40),
            "total_fwd_bytes": rng.integers(3000, 50_000),
            "total_bwd_bytes": rng.integers(1000, 20_000),
            "fwd_packet_length_max": rng.integers(800, 1500),
            "fwd_packet_length_min": rng.integers(30, 80),
            "fwd_packet_length_mean": rng.uniform(300, 1200),
            "bwd_packet_length_mean": rng.uniform(150, 700),
            "flow_bytes_per_sec": rng.uniform(20_000, 150_000),
            "flow_packets_per_sec": rng.uniform(20, 250),
            "flow_iat_mean": rng.uniform(1000, 20_000),
            "flow_iat_std": rng.uniform(500, 5000),
            "flow_iat_max": rng.uniform(3000, 50_000),
            "fwd_iat_total": rng.uniform(80_000, 2_500_000),
            "syn_flag_count": 1,
            "fin_flag_count": 1,
            "rst_flag_count": rng.choice([0, 1], p=[0.8, 0.2]),
            "psh_flag_count": 1,
            "ack_flag_count": 1,
            "down_up_ratio": rng.uniform(0.3, 1.5),
            "avg_packet_size": rng.uniform(300, 900),
            "active_mean": rng.uniform(1000, 20_000),
            "idle_mean": rng.uniform(5000, 50_000),
            "label": 1,
            "category": "WebAttack",
        }
        records.append(rec)

    df = pd.DataFrame(records)
    # Shuffle dataset
    df = df.sample(frac=1.0, random_state=random_seed).reset_index(drop=True)
    return df


if __name__ == "__main__":
    import os
    os.makedirs("data", exist_ok=True)
    df = generate_benchmark_dataset(6000)
    out_path = "data/benchmark_dataset.csv"
    df.to_csv(out_path, index=False)
    print(f"Generated {len(df)} records -> {out_path}")
    print("Class distribution:")
    print(df["category"].value_counts())

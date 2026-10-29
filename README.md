# 🛡️ Intelligent Network Intrusion Detection System (IIDS)
### *A Dual-Layer Security Framework Integrating Supervised Machine Learning with Stateful Heuristic Inspection*

**Author:** [Sudhanshu Sharma](https://github.com/SudhanshuSharma1506)  
**Domain:** Cybersecurity, Network Security, Applied Machine Learning  
**Dataset Reference:** Canadian Institute for Cybersecurity (CICIDS2017 Benchmark Flow Distribution)  
**License:** [MIT License](LICENSE)

---

## 📄 Abstract

Modern enterprise networks face an expanding surface of sophisticated cyber threats, ranging from distributed denial-of-service (DDoS) flooding and automated credential brute-forcing to stealthy horizontal port reconnaissance. Traditional Intrusion Detection Systems (IDS) rely primarily on static, signature-based matching rules (e.g., Snort, Suricata), leaving systems vulnerable to zero-day vectors and polymorphic payloads. Conversely, standalone Machine Learning (ML) classifiers often struggle with behavior-based reconnaissance where individual packet flows carry minimal payload but aggregate into coordinated scanning sweeps.

This project designs and implements the **Intelligent Intrusion Detection System (IIDS)**, a dual-layer, high-throughput defense framework that synthesizes:
1. **Stateful Temporal Heuristic Filters**: Windowed sliding-memory trackers capturing multi-port reconnaissance sweeps and anomalous SYN-to-ACK ratios in real time.
2. **Supervised Machine Learning Inference**: An optimized ensemble Random Forest classification pipeline trained across 24 statistical flow features, capturing volumetric and payload distribution anomalies.
3. **Proactive IP Quarantine**: An $O(1)$ in-memory and persistent quarantine barrier executing immediate packet drops on verified hostile entities.

The framework was evaluated on benchmark network flow distributions structured after the **CICIDS2017** dataset, achieving an overall classification accuracy of **99.80%**, a precision of **100.00%**, a recall of **99.50%**, and a ROC-AUC score of **1.0000**. The system includes a full-stack Security Operations Center (SOC) dashboard providing real-time streaming telemetry, batch flow forensics, and firewall rule enforcement.

---

## 🎯 Problem Statement & Objectives

### Key Challenges in Network Anomaly Detection
* **High-Speed Volumetric Flows**: Real-time inspection engines must operate with sub-millisecond latencies to prevent packet backpressure.
* **Asymmetric Attack Signatures**: Port scanning probes often consist of a single SYN packet across hundreds of ports, rendering individual flow classifiers blind to the broader attack pattern.
* **Cost of False Positives vs. False Negatives**: In enterprise operations, false negatives (missed compromises) cause severe data breaches, while excessive false positives induce analyst fatigue.

### Project Objectives
* **Engineering an Optimized Flow Feature Extractor**: Extract 24 discriminatory temporal, volumetric, and flag-based features from raw flow streams.
* **Dual-Layer Threat Engine**: Formulate a hybrid pipeline merging stateful rule-based heuristics with probabilistic ML scoring.
* **Zero-Latency Quarantine Control**: Implement a thread-safe firewall manager to isolate hostile origins.
* **Interactive SOC Telemetry**: Provide a real-time monitoring console, interactive analytics, and batch CSV forensics.

---

## 🏗️ Methodology & System Architecture

```
                    Raw Incoming Network Flow
                               │
                               ▼
        ┌──────────────────────────────────────────────┐
        │        Layer 1: IP Quarantine Barrier        │
        │   O(1) Thread-Safe In-Memory / JSON Lookup   │
        └──────────────────────┬───────────────────────┘
                               │
                Is Origin Host Quarantined?
                  ├─── YES ───► [ DROP: QUARANTINED (CRITICAL) ]
                  └─── NO  ───► (Forward to Heuristic Engine)
                               │
                               ▼
        ┌──────────────────────────────────────────────┐
        │  Layer 2: Stateful Temporal Heuristic Filter │
        │  - Sliding Window Port Sweep Detection       │
        │  - Rate-Based SYN Flood Ratio Verification   │
        └──────────────────────┬───────────────────────┘
                               │
                  Heuristic Threshold Breached?
                  ├─── YES ───► [ ALERT: PortScan / SYN_Flood ]
                  └─── NO  ───► (Forward to ML Classifier)
                               │
                               ▼
        ┌──────────────────────────────────────────────┐
        │    Layer 3: Machine Learning Classification  │
        │  - Standardized Normalization Pipeline       │
        │  - Ensemble Random Forest Inference (120 T)  │
        │  - Probability & Threat Severity Scoring     │
        └──────────────────────┬───────────────────────┘
                               │
                               ▼
                  Consolidated Threat Verdict
                               │
           ┌───────────────────┴───────────────────┐
           ▼                                       ▼
    Security Dashboard                    Audit Log & CSV Export
   (Real-Time Telemetry)                  (Forensics Data Store)
```

---

## 📐 Mathematical Feature Formulation

The system processes network flows parameterized by 24 normalized statistical features:

### 1. Temporal Dynamics
* **Flow Duration ($T_{\text{flow}}$)**: Total active duration of bidirectional session in microseconds:
  $$\Delta t = t_{\text{last\_packet}} - t_{\text{first\_packet}}$$
* **Inter-Arrival Times ($\text{IAT}$)**: Mean ($\mu_{\text{iat}}$), standard deviation ($\sigma_{\text{iat}}$), and maximum ($\text{max}_{\text{iat}}$) of packet arrival intervals:
  $$\mu_{\text{iat}} = \frac{1}{N-1} \sum_{i=2}^{N} (t_i - t_{i-1})$$

### 2. Volumetric & Rate Metrics
* **Flow Packet Rate**: Total packets per unit time:
  $$\lambda_{\text{pkt}} = \frac{N_{\text{fwd}} + N_{\text{bwd}}}{T_{\text{flow}}}$$
* **Flow Byte Rate**: Total transferred volume per unit time:
  $$\lambda_{\text{byte}} = \frac{B_{\text{fwd}} + B_{\text{bwd}}}{T_{\text{flow}}}$$

### 3. Packet Length Moments
* Forward and backward packet length distributions ($\mu_{\text{fwd\_len}}, \sigma_{\text{fwd\_len}}, \text{max}_{\text{fwd\_len}}, \text{min}_{\text{fwd\_len}}$).
* **Download/Upload Asymmetry Ratio**:
  $$R_{\text{du}} = \frac{N_{\text{bwd}}}{N_{\text{fwd}}}$$

### 4. TCP Control Flag Distribution
* Cumulative counts for control bits: $\text{SYN}, \text{ACK}, \text{FIN}, \text{RST}, \text{PSH}$.

---

## ⚔️ Threat Modeling & Attack Taxonomy

The detection engine classifies incoming traffic into distinct categories:

| Threat Category | Attack Behavior & Mechanism | Primary Indicators | Detection Mechanism |
|---|---|---|---|
| **BENIGN** | Normal browsing, API calls, DNS resolution, SSH management. | Balanced forward/backward ratio, standard packet sizes, complete handshakes. | Supervised ML Engine |
| **DDoS** | High-volume volumetric flood aiming to exhaust server socket buffers and bandwidth. | $\lambda_{\text{pkt}} > 10^4$, massive forward byte volume, low connection durations. | Supervised ML Engine |
| **PortScan** | Network reconnaissance sweeping multiple ports on target hosts to uncover exposed services. | Rapid connections to $\ge 12$ distinct destination ports within a 15-second sliding window. | Stateful Heuristic Filter |
| **SYN_Flood** | Half-open connection flood designed to deplete OS transmission control block (TCB) pools. | Rapid succession of SYN packets with zero corresponding ACK/completion packets. | Stateful Heuristic Filter |
| **BruteForce** | Automated credential stuffing targeting authentication ports (SSH: 22, FTP: 21, RDP: 3389). | Repetitive small flows, elevated RST/FIN flags indicating terminated auth attempts. | Supervised ML Engine |
| **WebAttack** | Application-layer exploits (SQL Injection, Cross-Site Scripting, directory traversals). | Anomalous payload lengths, skewed byte rates on HTTP/HTTPS ports (80, 443, 8080). | Supervised ML Engine |

---

## 📊 Experimental Evaluation & Results

The system was evaluated using stratified 5-fold cross-validation on a hold-out test set ($N_{\text{test}} = 1,500$ samples, $N_{\text{train}} = 6,000$ samples).

### Performance Metrics Summary

$$\text{Accuracy} = \frac{TP + TN}{TP + TN + FP + FN} = 99.80\%$$

$$\text{Precision} = \frac{TP}{TP + FP} = 100.00\%$$

$$\text{Recall} = \frac{TP}{TP + FN} = 99.50\%$$

$$\text{F1-Score} = 2 \cdot \frac{\text{Precision} \cdot \text{Recall}}{\text{Precision} + \text{Recall}} = 99.75\%$$

$$\text{ROC-AUC} = 1.0000$$

### Quantitative Results Matrix

| Evaluated Metric | Value | Operational Implication |
|---|---|---|
| **Accuracy** | **99.80%** | Exceptional overall classification fidelity across both benign and malicious traffic. |
| **Precision** | **100.00%** | Zero false-positive rate prevents disruption of legitimate business traffic. |
| **Recall** | **99.50%** | Minimal false negatives ensures severe intrusion vectors are intercepted. |
| **F1-Score** | **99.75%** | Optimum harmonic mean between reliability and security coverage. |
| **ROC-AUC** | **1.0000** | Perfect separation margin across binary classification thresholds. |

---

## 📁 Repository Directory Structure

```
Intelligent-Intrusion-Detection-System/
├── core/
│   ├── __init__.py
│   ├── flow_analyzer.py        # 24-feature extractor & flow sanitation routines
│   ├── threat_engine.py        # Hybrid dual-layer ML + stateful heuristic logic
│   └── blocklist_manager.py    # Thread-safe persistent IP quarantine manager
├── ml/
│   ├── __init__.py
│   ├── dataset_generator.py    # Benchmark traffic generator (CICIDS2017 schema)
│   ├── model_pipeline.py       # Scikit-learn training, evaluation & serialization
│   ├── trained_model.joblib    # Production Random Forest pipeline artifact
│   └── evaluation_metrics.json # Stored performance benchmarks & confusion matrix
├── web/
│   ├── app.py                  # Flask REST backend and telemetry controllers
│   ├── templates/
│   │   ├── base.html           # Dark cybernetic base layout
│   │   ├── dashboard.html      # Real-time metrics, KPI cards & Chart.js widgets
│   │   ├── monitor.html        # Interactive live traffic feed & stream simulator
│   │   ├── analyze.html        # Batch CSV network flow forensic analyzer
│   │   └── firewall.html       # Quarantine blocklist manager & rule editor
│   └── static/
│       ├── css/style.css       # Custom high-contrast cybersecurity stylesheet
│       └── js/                 # Client-side dynamic update scripts
├── data/
│   ├── benchmark_dataset.csv   # Synthesized benchmark dataset
│   └── blocklist.json          # Persistent IP quarantine state
├── run.py                      # Master execution script
├── requirements.txt            # System dependencies
├── LICENSE                     # MIT License
└── README.md                   # Formal documentation & project specification
```

---

## 💻 Installation & Reproduction Guide

### Prerequisites
- Python 3.10, 3.11, 3.12, or 3.13
- Git

### 1. Clone the Repository
```powershell
git clone https://github.com/SudhanshuSharma1506/Intelligent-Intrusion-Detection-System.git
cd Intelligent-Intrusion-Detection-System
```

### 2. Configure Virtual Environment & Dependencies
```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

### 3. (Optional) Retrain Model Pipeline
To execute the automated feature selection, model training, and metric evaluation pipeline from scratch:
```powershell
python -m ml.model_pipeline
```

### 4. Launch the Security Operations Center (SOC)
```powershell
python run.py
```
Open **`http://127.0.0.1:5000`** in any modern web browser to access the interactive security dashboard.

---

## 📡 API Specification

| HTTP Method | Route | Description |
|---|---|---|
| `GET` | `/` | Primary dashboard providing real-time threat KPIs, threat breakdown, and severity charts. |
| `GET` | `/monitor` | Real-time traffic stream inspection interface with live flow updates. |
| `GET` | `/analyze` | Form interface for batch offline CSV capture ingestion. |
| `POST` | `/analyze` | Multipart CSV upload endpoint executing high-throughput offline batch classification. |
| `GET` | `/firewall` | Active IP quarantine console displaying drop hits and active ban rules. |
| `POST` | `/firewall` | Endpoint to enforce manual IP bans or lift quarantine on target hosts. |
| `GET` | `/api/stats` | JSON telemetry endpoint providing metrics for dynamic Chart.js rendering. |
| `GET` | `/api/simulate-flow` | Generates a dynamic network flow, evaluates it against the threat engine, and returns JSON verdict. |
| `GET` | `/export/threats.csv` | Streams the full memory event log as a downloadable CSV report for external SIEM integration. |

---

## 🔮 Future Research & Enhancements

1. **Deep Learning Sequence Modeling**: Integrating Bidirectional LSTM or Transformer-based architectures to capture multi-packet temporal dependencies across complex sessions.
2. **Graph-Based Spatial Anomaly Detection**: Implementing Graph Convolutional Networks (GCN) to monitor lateral movement and internal host-to-host topology shifts.
3. **Automated Host Firewall Enforcement**: Interfacing the quarantine engine directly with OS-level firewall filters via `netsh advfirewall` (Windows) and `iptables`/`nftables` (Linux).
4. **Distributed SIEM Ingestion**: Adding native Syslog (RFC 5424) and CEF (Common Event Format) exporters for seamless ingestion into Splunk, Elastic SIEM, and Wazuh.

---

## 📜 Citation & License

This project is released under the **[MIT License](LICENSE)**.

```bibtex
@software{sharma2026iids,
  author = {Sharma, Sudhanshu},
  title = {Intelligent Network Intrusion Detection System (IIDS): A Dual-Layer Security Framework},
  year = {2026},
  url = {https://github.com/SudhanshuSharma1506/Intelligent-Intrusion-Detection-System}
}
```

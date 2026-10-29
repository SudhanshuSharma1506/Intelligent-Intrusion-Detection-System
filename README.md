# 🛡️ Intelligent Intrusion Detection System (IIDS)

An enterprise-grade, hybrid **Network Intrusion Detection System** combining Machine Learning classification, stateful heuristic traffic inspection, and real-time firewall quarantine management.

---

## 🚀 Key Highlights

- **Dual-Layer Threat Engine**: Pairs a high-precision **Random Forest Classifier** with **stateful heuristic detection** (tracking port scan sweeps and SYN connection bursts).
- **Zero-Latency Firewall Quarantine**: In-memory and persistent IP blocklist dropping malicious traffic on future connections.
- **Dynamic Live Monitoring**: Real-time traffic simulation feed with sub-second threat scoring and alert triggering.
- **Batch Flow Ingestion**: Offline CSV network flow analysis with instant classification and severity tagging.
- **Modern Security Operations Console**: Polished cyber dark-mode interface built with Flask, Bootstrap 5, FontAwesome, and Chart.js.

---

## 🏗️ Architecture & Inspection Pipeline

```
            Incoming Network Traffic Flow
                         │
                         ▼
        ┌─────────────────────────────────┐
        │   Layer 1: IP Blocklist Check   │
        └────────────────┬────────────────┘
                         │
           Is Source IP Quarantined?
                  ├─── YES ───► [ DROP: QUARANTINED (CRITICAL) ]
                  └─── NO  ───► (Proceed to Layer 2)
                                         │
                                         ▼
        ┌─────────────────────────────────┐
        │ Layer 2: Stateful Heuristic Rule│
        │ - Port Scan Sweep Tracker       │
        │ - SYN Flood Burst Detector      │
        └────────────────┬────────────────┘
                         │
              Rule Threshold Exceeded?
                  ├─── YES ───► [ ALERT: PortScan / SYN_Flood ]
                  └─── NO  ───► (Proceed to Layer 3)
                                         │
                                         ▼
        ┌─────────────────────────────────┐
        │ Layer 3: Machine Learning Engine│
        │ - StandardScaler Normalization  │
        │ - Random Forest Classification  │
        │ - Confidence & Severity Scoring │
        └────────────────┬────────────────┘
                         │
                         ▼
          Unified Security Verdict & Telemetry
                         │
         ┌───────────────┴───────────────┐
         ▼                               ▼
  Flask Security UI             Audit Log & CSV Export
```

---

## 📊 Detection Performance

Trained and evaluated on network flow distributions structured after the **CICIDS2017** benchmark:

| Metric | Score | Note |
|---|---|---|
| **Accuracy** | **99.80%** | Comprehensive multi-vector test set |
| **Precision** | **100.00%** | Zero false positives on benign baseline |
| **Recall** | **99.50%** | High sensitivity for detecting critical intrusions |
| **F1-Score** | **99.75%** | Harmonic balance between precision and recall |
| **ROC-AUC** | **1.0000** | Strong discrimination across class boundaries |

---

## 🛠️ Project Structure

```
Intelligent-Intrusion-Detection-System/
├── core/
│   ├── __init__.py
│   ├── flow_analyzer.py        # Feature vector extraction and data sanitation
│   ├── threat_engine.py        # Hybrid ML + stateful heuristic inspection logic
│   └── blocklist_manager.py    # Thread-safe persistent IP quarantine manager
├── ml/
│   ├── __init__.py
│   ├── dataset_generator.py    # Benchmark traffic dataset generator
│   ├── model_pipeline.py       # Scikit-learn training and evaluation pipeline
│   ├── trained_model.joblib    # Serialized ML pipeline artifact
│   └── evaluation_metrics.json # Evaluation reports and confusion matrix
├── web/
│   ├── app.py                  # Flask web application and API endpoints
│   ├── templates/              # Jinja2 templates (dashboard, monitor, etc.)
│   └── static/                 # Stylesheets and frontend assets
├── data/                       # Datasets and active blocklists
├── run.py                      # Application launcher
└── requirements.txt            # Python dependencies
```

---

## 💻 Installation & Quickstart

### 1. Prerequisites
- Python 3.10 or higher
- Git

### 2. Setup Environment
```powershell
# Clone the repository
git clone https://github.com/SudhanshuSharma1506/iids.git
cd iids

# Install dependencies
pip install -r requirements.txt
```

### 3. Run the System
```powershell
python run.py
```
Open your browser and navigate to **`http://127.0.0.1:5000`** to access the security operations console.

---

## 🔌 API Endpoints

- `GET /` — Primary security dashboard.
- `GET /monitor` — Interactive real-time streaming traffic monitor.
- `GET /analyze` — Batch CSV network capture analyzer.
- `GET /firewall` — IP blocklist and quarantine rule manager.
- `GET /api/stats` — Real-time telemetry JSON for dashboard charts.
- `GET /api/simulate-flow` — Generate and score a dynamic network flow event.
- `GET /export/threats.csv` — Download active threat logs in CSV format.

---

## 📄 License
This project is open source and available under the [MIT License](LICENSE).

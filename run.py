"""
Top-level runner for Intelligent Intrusion Detection System (IIDS).
Checks model dependencies, ensures baseline artifacts exist, and launches the web interface.
"""

import os
import sys

# Ensure root directory is on Python path
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
if CURRENT_DIR not in sys.path:
    sys.path.insert(0, CURRENT_DIR)

from ml.model_pipeline import train_detection_pipeline


def main():
    print("=" * 60)
    print("  🛡️  INTELLIGENT INTRUSION DETECTION SYSTEM (IIDS)  🛡️")
    print("=" * 60)

    model_path = os.path.join(CURRENT_DIR, "ml", "trained_model.joblib")
    if not os.path.exists(model_path):
        print("[!] No trained ML model found. Initializing baseline training pipeline...")
        train_detection_pipeline(
            data_path=os.path.join(CURRENT_DIR, "data", "benchmark_dataset.csv"),
            model_output_path=model_path,
            metrics_output_path=os.path.join(CURRENT_DIR, "ml", "evaluation_metrics.json"),
        )
    else:
        print(f"[✓] Detection model loaded from: {model_path}")

    # Launch Flask application
    from web.app import app
    print("\n[+] Starting IIDS Security Dashboard...")
    print("[+] Open your browser at: http://127.0.0.1:5000\n")
    app.run(host="127.0.0.1", port=5000, debug=False)


if __name__ == "__main__":
    main()

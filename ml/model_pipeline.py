"""
Model Pipeline Module
---------------------
Trains, evaluates, and serializes the Machine Learning detection pipeline
using scikit-learn.
"""

from typing import Dict, Any, Tuple
import os
import json
import joblib
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import RandomForestClassifier
from sklearn.pipeline import Pipeline
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    roc_auc_score,
    confusion_matrix,
    classification_report,
)

from core.flow_analyzer import FEATURE_NAMES, sanitize_dataframe
from ml.dataset_generator import generate_benchmark_dataset


def train_detection_pipeline(
    data_path: str = "data/benchmark_dataset.csv",
    model_output_path: str = "ml/trained_model.joblib",
    metrics_output_path: str = "ml/evaluation_metrics.json",
    test_size: float = 0.20,
    random_seed: int = 42,
) -> Tuple[Pipeline, Dict[str, Any]]:
    """Build, train, evaluate, and save the intrusion detection model pipeline."""

    # 1. Load or Generate Dataset
    if os.path.exists(data_path):
        print(f"[*] Loading training data from {data_path}...")
        df = pd.read_csv(data_path)
    else:
        print("[*] Benchmark dataset not found. Generating synthetic dataset...")
        df = generate_benchmark_dataset(num_samples=7500, random_seed=random_seed)
        os.makedirs(os.path.dirname(data_path) or ".", exist_ok=True)
        df.to_csv(data_path, index=False)
        print(f"[*] Saved dataset to {data_path}")

    # Ensure required features exist
    df = sanitize_dataframe(df)

    if "label" not in df.columns:
        raise ValueError("Dataset missing 'label' target column.")

    X = df[FEATURE_NAMES].values
    y = df["label"].astype(int).values

    # 2. Train / Test Split
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=test_size, random_state=random_seed, stratify=y
    )
    print(f"[*] Dataset split: {len(X_train)} train, {len(X_test)} test samples.")

    # 3. Create Pipeline with Robust Ensemble Classifier
    pipeline = Pipeline([
        ("scaler", StandardScaler()),
        ("classifier", RandomForestClassifier(
            n_estimators=120,
            max_depth=16,
            min_samples_split=4,
            random_state=random_seed,
            n_jobs=-1,
        )),
    ])

    print("[*] Training Random Forest intrusion classifier...")
    pipeline.fit(X_train, y_train)

    # 4. Model Evaluation
    y_pred = pipeline.predict(X_test)
    y_proba = pipeline.predict_proba(X_test)[:, 1]

    acc = accuracy_score(y_test, y_pred)
    prec = precision_score(y_test, y_pred, zero_division=0)
    rec = recall_score(y_test, y_pred, zero_division=0)
    f1 = f1_score(y_test, y_pred, zero_division=0)
    roc = roc_auc_score(y_test, y_proba)
    cm = confusion_matrix(y_test, y_pred).tolist()

    metrics = {
        "accuracy": round(float(acc), 4),
        "precision": round(float(prec), 4),
        "recall": round(float(rec), 4),
        "f1_score": round(float(f1), 4),
        "roc_auc": round(float(roc), 4),
        "confusion_matrix": cm,
        "test_samples": len(y_test),
        "training_samples": len(y_train),
    }

    print("\n========== MODEL PERFORMANCE EVALUATION ==========")
    print(f"Accuracy:  {acc * 100:.2f}%")
    print(f"Precision: {prec * 100:.2f}%")
    print(f"Recall:    {rec * 100:.2f}%")
    print(f"F1-Score:  {f1 * 100:.2f}%")
    print(f"ROC-AUC:   {roc:.4f}")
    print("==================================================\n")

    # 5. Serialize Artifacts
    os.makedirs(os.path.dirname(model_output_path) or ".", exist_ok=True)
    joblib.dump(pipeline, model_output_path)
    print(f"[+] Saved model pipeline to {model_output_path}")

    with open(metrics_output_path, "w", encoding="utf-8") as f:
        json.dump(metrics, f, indent=2)
    print(f"[+] Saved evaluation metrics to {metrics_output_path}")

    return pipeline, metrics


if __name__ == "__main__":
    train_detection_pipeline()

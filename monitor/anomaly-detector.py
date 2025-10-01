#!/usr/bin/env python3
"""
ICS Behavioral Anomaly Detector

Analyzes time-series telemetry or event logs from ICS devices to detect behavioral anomalies.

Author: Ali AlEnezi
License: MIT
Version: 1.0.0
"""

import argparse
import json
import logging
from pathlib import Path
from typing import List, Dict, Any
from datetime import datetime

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class AnomalyDetector:
    """Detect anomalies in ICS telemetry data."""

    def __init__(self, contamination: float = 0.01, random_state: int = 42):
        self.model = IsolationForest(
            n_estimators=100,
            contamination=contamination,
            random_state=random_state
        )
        self.scaler = StandardScaler()
        self.features = []

    def load_data(self, file_path: Path) -> pd.DataFrame:
        """Load telemetry JSON array into DataFrame and ensure timestamps."""
        data = []
        with open(file_path, 'r') as f:
            arr = json.load(f)
            for rec in arr:
                data.append(rec)
        df = pd.DataFrame(data)
        if 'timestamp' not in df.columns:
            raise ValueError("Input data must include a 'timestamp' field")
        df['timestamp'] = pd.to_datetime(df['timestamp'])
        df.set_index('timestamp', inplace=True)
        return df

    def preprocess(self, df: pd.DataFrame, features: List[str]) -> pd.DataFrame:
        """Validate, convert to numeric, fill missing values, and scale features."""
        missing_features = [f for f in features if f not in df.columns]
        if missing_features:
            raise ValueError(f"Features not found in data: {missing_features}")
        
        df_numeric = df[features].apply(pd.to_numeric, errors='coerce')
        if df_numeric.isnull().any().any():
            logger.warning("Missing values detected, applying linear interpolation")
            df_numeric = df_numeric.interpolate(method='linear').fillna(method='bfill').fillna(method='ffill')
        
        scaled = self.scaler.fit_transform(df_numeric) if not self.features else self.scaler.transform(df_numeric)
        df_scaled = pd.DataFrame(scaled, index=df.index, columns=features)
        return df_scaled

    def train(self, df: pd.DataFrame, features: List[str]) -> None:
        """Fit model on historical data."""
        self.features = features
        X = self.preprocess(df, features).values
        self.model.fit(X)
        logger.info("IsolationForest model trained on provided data")

    def detect(self, df: pd.DataFrame, features: List[str]) -> pd.DataFrame:
        """Detect anomalies in new data."""
        if not self.features:
            raise RuntimeError("Model has not been trained")
        X = self.preprocess(df, features).values
        preds = self.model.predict(X)
        df_result = df.copy()
        df_result['anomaly'] = (preds == -1)
        return df_result

    def summary(self, df: pd.DataFrame) -> Dict[str, Any]:
        """Provide summary of anomalies."""
        total = len(df)
        anomalies = df['anomaly'].sum()
        return {
            'total_records': total,
            'anomalies_detected': int(anomalies),
            'anomaly_rate': round(anomalies / total, 4)
        }

def main():
    parser = argparse.ArgumentParser(description='ICS Behavioral Anomaly Detector')
    parser.add_argument('--train', '-t', help='Historical telemetry JSON file for training')
    parser.add_argument('--test', '-e', required=True, help='New telemetry JSON file for anomaly detection')
    parser.add_argument('--features', '-f', nargs='+', required=True, help='List of numeric fields to use')
    parser.add_argument('--report', '-r', help='Output anomaly report JSON file', default='anomaly_report.json')
    args = parser.parse_args()

    detector = AnomalyDetector()
    
    # Training step
    if args.train:
        df_train = detector.load_data(Path(args.train))
        detector.train(df_train, args.features)
    else:
        logger.warning("No training data provided; model uses default IsolationForest behavior")

    # Detection step
    df_test = detector.load_data(Path(args.test))
    df_result = detector.detect(df_test, args.features)
    summary = detector.summary(df_result)

    # Save report
    report = {
        'summary': summary,
        'anomalies': df_result[df_result['anomaly']].reset_index().to_dict(orient='records')
    }
    with open(args.report, 'w') as f:
        json.dump(report, f, indent=2, default=str)
    logger.info(f"Anomaly detection report saved to {args.report}")

    print(f"Anomaly detection complete: {summary['anomalies_detected']} anomalies ({summary['anomaly_rate']*100}%)")
    return 0

if __name__ == '__main__':
    exit(main())

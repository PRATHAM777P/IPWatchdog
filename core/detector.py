"""
core/detector.py – Ensemble anomaly detection for IP traffic.

Pipeline
--------
1. Feature engineering per IP (request count, error rate, method entropy,
   path diversity, hour-of-day spread, avg bytes, burst score).
2. IsolationForest  → continuous anomaly score (-1 = anomalous, +1 = normal).
3. KMeans clustering → cluster label for grouping similar IPs.
4. Combined score    → normalised float in [-1, +1].
"""

import logging
from typing import Optional, Dict

import numpy as np
import pandas as pd

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Lazy imports so the module loads even without scikit-learn installed
# ---------------------------------------------------------------------------
try:
    from sklearn.ensemble import IsolationForest
    from sklearn.cluster import KMeans
    from sklearn.preprocessing import StandardScaler
    _SKLEARN_AVAILABLE = True
except ImportError:
    _SKLEARN_AVAILABLE = False
    logger.warning("scikit-learn not installed – falling back to heuristic scoring only.")


class IPDetector:
    """
    Runs the full detection pipeline on a parsed log DataFrame.
    Returns an enriched DataFrame sorted by anomaly_score ascending
    (most suspicious first).
    """

    def __init__(
        self,
        n_clusters: int = 10,
        contamination: float = 0.05,
        min_requests: int = 3,
    ):
        self.n_clusters = n_clusters
        self.contamination = contamination
        self.min_requests = min_requests
        self._scaler = StandardScaler() if _SKLEARN_AVAILABLE else None

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def run(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Full batch analysis.

        Parameters
        ----------
        df : pd.DataFrame
            Output of LogParser.parse()

        Returns
        -------
        pd.DataFrame
            One row per unique IP, sorted by anomaly_score ascending.
            Columns: IP, request_count, error_rate, method_entropy,
                     path_diversity, avg_bytes, burst_score,
                     anomaly_score, cluster
        """
        features_df = self._engineer_features(df)
        if features_df.empty:
            return features_df

        feature_cols = [
            "request_count", "error_rate", "method_entropy",
            "path_diversity", "avg_bytes", "burst_score",
        ]

        if _SKLEARN_AVAILABLE and len(features_df) >= 2:
            X = features_df[feature_cols].values
            X_scaled = self._scaler.fit_transform(X)

            # Isolation Forest
            iso_contamination = min(self.contamination, (len(features_df) - 1) / len(features_df))
            iso = IsolationForest(contamination=iso_contamination, random_state=42, n_jobs=-1)
            iso_scores = iso.fit_predict(X_scaled)           # +1 normal / -1 anomaly
            iso_raw = iso.score_samples(X_scaled)            # raw decision function

            # KMeans
            k = min(self.n_clusters, len(features_df))
            km = KMeans(n_clusters=k, random_state=42, n_init=10)
            clusters = km.fit_predict(X_scaled)

            # Normalise raw IsolationForest score to [-1, 1]
            rng = iso_raw.max() - iso_raw.min()
            if rng > 0:
                normalised = 2 * (iso_raw - iso_raw.min()) / rng - 1
            else:
                normalised = np.zeros_like(iso_raw, dtype=float)

            features_df["anomaly_score"] = normalised.round(4)
            features_df["cluster"] = clusters
        else:
            # Heuristic fallback (no sklearn)
            features_df["anomaly_score"] = self._heuristic_score(features_df, feature_cols)
            features_df["cluster"] = 0

        return features_df.sort_values("anomaly_score").reset_index(drop=True)

    def score_single(self, record: dict) -> float:
        """
        Quick heuristic score for a single log record (real-time monitoring).
        Returns a float in [-1, 0] where lower is more suspicious.
        """
        score = 0.0
        status = record.get("status", 200)
        method = record.get("method", "GET")

        if status >= 400:
            score -= 0.3
        if status == 404:
            score -= 0.1
        if status == 403:
            score -= 0.2
        if status >= 500:
            score -= 0.2
        if method in ("DELETE", "PUT", "TRACE", "CONNECT"):
            score -= 0.2
        if method == "HEAD":
            score -= 0.05

        path = record.get("path", "")
        suspicious_paths = ("/etc/passwd", "/wp-admin", "/.env", "/shell", "/cmd", "/phpmyadmin")
        if any(p in path.lower() for p in suspicious_paths):
            score -= 0.4

        return max(-1.0, score)

    # ------------------------------------------------------------------
    # Feature engineering
    # ------------------------------------------------------------------

    def _engineer_features(self, df: pd.DataFrame) -> pd.DataFrame:
        """Aggregate per-IP features."""
        if df.empty:
            return pd.DataFrame()

        grp = df.groupby("IP")
        rows = []

        for ip, g in grp:
            n = len(g)
            if n < self.min_requests:
                continue

            # Error rate: fraction of 4xx/5xx responses
            error_rate = (g["status"] >= 400).sum() / n if "status" in g else 0.0

            # Method entropy: uniform distribution = 0 bits (boring); diverse = suspicious
            if "method" in g:
                mc = g["method"].value_counts(normalize=True)
                method_entropy = float(-np.sum(mc * np.log2(mc + 1e-9)))
            else:
                method_entropy = 0.0

            # Path diversity: unique paths / total requests
            path_diversity = g["path"].nunique() / n if "path" in g else 0.0

            # Average bytes
            avg_bytes = g["bytes"].mean() if "bytes" in g else 0.0

            # Burst score: requests in a single hour / total requests
            if "hour" in g and g["hour"].max() >= 0:
                max_hour_count = g["hour"].value_counts().max()
                burst_score = max_hour_count / n
            else:
                burst_score = 0.0

            rows.append({
                "IP": ip,
                "request_count": n,
                "error_rate": round(error_rate, 4),
                "method_entropy": round(method_entropy, 4),
                "path_diversity": round(path_diversity, 4),
                "avg_bytes": round(avg_bytes, 2),
                "burst_score": round(burst_score, 4),
            })

        if not rows:
            return pd.DataFrame()
        return pd.DataFrame(rows)

    # ------------------------------------------------------------------
    # Heuristic fallback
    # ------------------------------------------------------------------

    @staticmethod
    def _heuristic_score(df: pd.DataFrame, feature_cols: list) -> pd.Series:
        """Simple z-score based anomaly score when sklearn is unavailable."""
        scores = pd.Series(0.0, index=df.index)
        for col in feature_cols:
            col_data = df[col].astype(float)
            mean = col_data.mean()
            std = col_data.std() or 1.0
            z = (col_data - mean) / std
            # High error_rate / burst_score → suspicious (high z = bad)
            # Low request_count alone is not suspicious
            if col in ("error_rate", "burst_score", "method_entropy"):
                scores -= z.clip(0, None) * 0.2
        return scores.clip(-1.0, 0.0).round(4)

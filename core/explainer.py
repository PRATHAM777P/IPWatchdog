"""
core/explainer.py – Human-readable explanations for flagged IPs.

For each IP the explainer inspects its feature vector and emits a list of
plain-English reason strings that the dashboard renders as tags / tooltips.
"""

import logging
from typing import Dict, List

import pandas as pd

logger = logging.getLogger(__name__)

# Thresholds (can be tuned or moved to config)
_ERROR_RATE_WARN   = 0.20   # 20 % of requests are errors
_ERROR_RATE_HIGH   = 0.50   # 50 % of requests are errors
_BURST_WARN        = 0.70   # 70 % of requests in a single hour
_METHOD_ENTROPY_HI = 1.5    # high method diversity
_PATH_DIVERSITY_LO = 0.05   # scanning – many requests to few distinct paths
_PATH_DIVERSITY_HI = 0.95   # harvesting – every request to a unique path
_REQUEST_COUNT_HI  = 500    # high-volume IP


class Explainer:
    """
    Takes the output DataFrame of IPDetector.run() and returns a dict
    mapping each IP to a list of explanation strings.
    """

    def explain(self, result_df: pd.DataFrame) -> Dict[str, List[str]]:
        explanations: Dict[str, List[str]] = {}
        for _, row in result_df.iterrows():
            ip = row["IP"]
            reasons = self._reasons_for(row)
            explanations[ip] = reasons
        return explanations

    # ------------------------------------------------------------------

    @staticmethod
    def _reasons_for(row: pd.Series) -> List[str]:
        reasons: List[str] = []

        error_rate = row.get("error_rate", 0.0)
        burst_score = row.get("burst_score", 0.0)
        method_entropy = row.get("method_entropy", 0.0)
        path_diversity = row.get("path_diversity", 0.0)
        request_count = row.get("request_count", 0)
        anomaly_score = row.get("anomaly_score", 0.0)

        # Anomaly score bucket
        if anomaly_score < -0.7:
            reasons.append("🔴 Highly anomalous traffic pattern detected by ML model")
        elif anomaly_score < -0.4:
            reasons.append("🟠 Moderately anomalous traffic pattern")
        elif anomaly_score < -0.1:
            reasons.append("🟡 Slightly unusual compared to baseline traffic")

        # Error rate
        if error_rate >= _ERROR_RATE_HIGH:
            reasons.append(f"⚠️  High error rate ({error_rate:.0%}) – possible scan or brute-force")
        elif error_rate >= _ERROR_RATE_WARN:
            reasons.append(f"ℹ️  Elevated error rate ({error_rate:.0%})")

        # Burst activity
        if burst_score >= _BURST_WARN:
            reasons.append(f"⚡ Traffic burst – {burst_score:.0%} of requests in a single hour")

        # Method diversity
        if method_entropy >= _METHOD_ENTROPY_HI:
            reasons.append("🔧 Unusual HTTP method mix (DELETE / PUT / TRACE / PATCH …)")

        # Path pattern
        if path_diversity <= _PATH_DIVERSITY_LO:
            reasons.append("🔁 Repetitive path pattern – possible brute-force or flood")
        elif path_diversity >= _PATH_DIVERSITY_HI:
            reasons.append("🕵️  Very high path diversity – possible directory scan / crawl")

        # Volume
        if request_count >= _REQUEST_COUNT_HI:
            reasons.append(f"📈 High request volume ({request_count:,} requests)")

        if not reasons:
            reasons.append("✅ No specific anomaly indicators found")

        return reasons

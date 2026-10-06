"""
sqlx/analysis/timing.py
~~~~~~~~~~~~~~~~~~~~~~~
Statistical timing analysis for detecting time-based blind SQL injection.
Builds a baseline from normal request latencies, then flags outliers
that could indicate successful SLEEP() / WAITFOR DELAY injections.
"""
from __future__ import annotations
import statistics
from typing import Dict, List, Tuple


class TimingAnalyser:
    """Detects timing anomalies consistent with time-based blind injection."""

    def __init__(self, baseline_threshold_ms: float = 5000.0,
                 z_score_threshold: float = 3.0):
        """
        Args:
            baseline_threshold_ms: Responses taking longer than this are
                                   immediately flagged (default 5s).
            z_score_threshold: Standard deviations above mean to flag
                                as anomaly (default 3σ).
        """
        self.baseline_threshold_ms = baseline_threshold_ms
        self.z_score_threshold     = z_score_threshold
        self._samples: List[float] = []

    # ── baseline ───────────────────────────────────────────────────────────

    def add_baseline(self, latency_ms: float) -> None:
        """Add a normal (non-injected) response latency for baseline."""
        self._samples.append(latency_ms)

    def add_baseline_many(self, latencies: List[float]) -> None:
        self._samples.extend(latencies)

    def reset_baseline(self) -> None:
        self._samples.clear()

    # ── detection ──────────────────────────────────────────────────────────

    def is_anomalous(self, latency_ms: float) -> Tuple[bool, str]:
        """Return (is_anomalous, reason_string)."""
        # Absolute threshold check
        if latency_ms >= self.baseline_threshold_ms:
            return (True,
                    f"Latency {latency_ms:.0f}ms ≥ threshold "
                    f"{self.baseline_threshold_ms:.0f}ms")

        # Z-score check (need ≥5 samples for meaningful stdev)
        if len(self._samples) >= 5:
            mean  = statistics.mean(self._samples)
            stdev = statistics.stdev(self._samples)
            if stdev > 0:
                z = (latency_ms - mean) / stdev
                if z > self.z_score_threshold:
                    return (True,
                            f"Latency z-score={z:.1f} > threshold "
                            f"{self.z_score_threshold} (mean={mean:.0f}ms)")

        return False, ""

    def analyse_batch(self, latencies: List[float]) -> Dict:
        """Analyse a list of latencies and return a structured report."""
        if not latencies:
            return {"anomalies": [], "mean_ms": 0, "max_ms": 0,
                    "has_time_based_signal": False}

        anomalies = []
        for i, lat in enumerate(latencies):
            flagged, reason = self.is_anomalous(lat)
            if flagged:
                anomalies.append({
                    "index":      i,
                    "latency_ms": lat,
                    "reason":     reason,
                })

        return {
            "anomalies":            anomalies,
            "mean_ms":              statistics.mean(latencies),
            "max_ms":               max(latencies),
            "min_ms":               min(latencies),
            "stdev_ms":             statistics.stdev(latencies) if len(latencies) > 1 else 0,
            "baseline_samples":     len(self._samples),
            "has_time_based_signal": bool(anomalies),
        }

    def summary(self) -> str:
        if not self._samples:
            return "No baseline established yet"
        mean = statistics.mean(self._samples)
        return (
            f"Baseline: {len(self._samples)} samples, "
            f"mean={mean:.1f}ms, "
            f"threshold={self.baseline_threshold_ms:.0f}ms"
        )


# Module-level singleton
_timing = TimingAnalyser()

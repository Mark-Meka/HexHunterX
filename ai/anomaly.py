"""
HexHunterX -- Statistical Anomaly Detection.
# AI-ENHANCED

Detects anomalies in HTTP response times and sizes using a rolling baseline
(mean and standard deviation) via the Python statistics module.
"""

import statistics
from collections import deque
from utils.logger import HexHunterXLogger

logger = HexHunterXLogger.get_logger("ai.anomaly")

class AnomalyDetector:
    def __init__(self, window_size: int = 100, min_requests: int = 10, stddev_multiplier: float = 2.0):
        self.window_size = window_size
        self.min_requests = min_requests
        self.stddev_multiplier = stddev_multiplier
        
        self._times = deque(maxlen=window_size)
        self._sizes = deque(maxlen=window_size)

    def analyze(self, time_ms: float, size_bytes: int) -> dict:
        """
        Analyze a response for anomalies.
        Returns dict: {"is_anomalous": bool, "reason": str, "deviation_score": float}
        """
        result = {"is_anomalous": False, "reason": "", "deviation_score": 0.0}

        # Add to baseline
        self._times.append(time_ms)
        self._sizes.append(size_bytes)

        if len(self._times) < self.min_requests:
            return result

        try:
            mean_time = statistics.mean(self._times)
            stdev_time = statistics.stdev(self._times) if len(self._times) > 1 else 0
            
            mean_size = statistics.mean(self._sizes)
            stdev_size = statistics.stdev(self._sizes) if len(self._sizes) > 1 else 0

            time_deviation = 0.0
            if stdev_time > 0:
                time_deviation = abs(time_ms - mean_time) / stdev_time
                
            size_deviation = 0.0
            if stdev_size > 0:
                size_deviation = abs(size_bytes - mean_size) / stdev_size

            if time_deviation > self.stddev_multiplier:
                result["is_anomalous"] = True
                result["reason"] = f"Response time {time_ms:.0f}ms deviates significantly from mean {mean_time:.0f}ms"
                result["deviation_score"] = time_deviation

            if size_deviation > self.stddev_multiplier:
                result["is_anomalous"] = True
                reason_part = f"Response size {size_bytes}B deviates significantly from mean {mean_size:.0f}B"
                result["reason"] = reason_part if not result["reason"] else result["reason"] + " | " + reason_part
                result["deviation_score"] = max(result["deviation_score"], size_deviation)

        except statistics.StatisticsError:
            pass

        return result

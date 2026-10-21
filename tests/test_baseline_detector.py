import numpy as np
import pandas as pd
import pytest

from src.baseline_detector import BaselineDetector


class FixedClassifier:
    def predict_proba(self, _features):
        return np.array([[0.8, 0.2]], dtype=float)


def test_zero_threshold_override_is_not_replaced_by_saved_threshold():
    detector = BaselineDetector()
    detector.base_model = FixedClassifier()
    detector.classes_ = ["BENIGN", "PortScan"]
    detector.feature_columns = ["flow_duration"]
    detector.optimal_threshold = 0.9

    scored = detector.score_flows(
        pd.DataFrame({"flow_duration": [10.0]}),
        pd.DataFrame({"flow_id": ["flw_test"]}),
        threshold=0.0,
    )

    assert scored["risk_score"].iloc[0] == 0.2
    assert scored["is_alert"].iloc[0]


@pytest.mark.parametrize("threshold", [-0.1, 1.1, float("nan")])
def test_invalid_threshold_override_is_rejected(threshold):
    detector = BaselineDetector()
    detector.base_model = FixedClassifier()
    detector.classes_ = ["BENIGN", "PortScan"]
    detector.feature_columns = ["flow_duration"]
    with pytest.raises(ValueError, match=r"finite value in \[0, 1\]"):
        detector.score_flows(
            pd.DataFrame({"flow_duration": [10.0]}),
            pd.DataFrame({"flow_id": ["flw_test"]}),
            threshold=threshold,
        )

"""Tests for the metrics module."""
import math

from cada.metrics import MonitorRecord, gap_table, operating_point, recall_at_fpr


def test_operating_point_perfect():
    op = operating_point([1, 1, 0, 0], [1, 1, 0, 0])
    assert op.recall == 1.0 and op.fpr == 0.0 and op.f1 == 1.0


def test_operating_point_all_false_negative():
    op = operating_point([1, 1], [0, 0])
    assert op.recall == 0.0


def test_recall_at_fpr_separable():
    # scores perfectly separate classes -> recall 1.0 at any FPR target
    y = [1, 1, 0, 0]
    scores = [0.9, 0.8, 0.2, 0.1]
    assert recall_at_fpr(y, scores, target_fpr=0.0) == 1.0


def test_gap_table_detects_drop():
    recs = [
        MonitorRecord("m", "O0_clean", [1, 1, 0], [1, 1, 0]),   # recall 1.0
        MonitorRecord("m", "O1_base64", [1, 1, 0], [0, 0, 0]),  # recall 0.0
    ]
    _, gaps = gap_table(recs)
    assert math.isclose(gaps["m"]["clean_recall"], 1.0)
    assert math.isclose(gaps["m"]["obf_mean_recall"], 0.0)
    assert math.isclose(gaps["m"]["gap"], 1.0)

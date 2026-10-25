import pandas as pd
import pytest

from src.data_loader import FlowDataLoader, split_temporally


def _mixed_time_flows():
    data = pd.DataFrame(
        {
            "timestamp": pd.to_datetime(
                [
                    "2026-01-01T00:00:00Z",
                    "2026-01-01T00:00:01Z",
                    "2026-01-01T00:00:02Z",
                    "2026-01-01T00:00:03Z",
                    "2026-01-01T00:00:04Z",
                    "2026-01-01T00:00:05Z",
                    "2026-01-01T00:00:06Z",
                    "2026-01-01T00:00:07Z",
                    "2026-01-01T00:00:08Z",
                    "2026-01-01T00:00:09Z",
                ],
                utc=True,
            ),
            "flow_id": [f"flow-{i}" for i in range(10)],
            "label": ["BENIGN"] * 5 + ["PortScan"] * 5,
            "feature": range(10),
        }
    )
    return data.iloc[[9, 0, 4, 1, 8, 2, 7, 3, 6, 5]].reset_index(drop=True)


def _assert_disjoint_time_ranges(train, validation, test):
    assert train["timestamp"].max() < validation["timestamp"].min()
    assert validation["timestamp"].max() < test["timestamp"].min()


def test_loader_defaults_to_global_chronological_split():
    data = _mixed_time_flows()
    parts = FlowDataLoader().prepare_temporal_split(data)
    train_meta, val_meta, test_meta = parts[2], parts[5], parts[8]

    _assert_disjoint_time_ranges(train_meta, val_meta, test_meta)
    assert set(train_meta["flow_id"]).isdisjoint(val_meta["flow_id"])
    assert set(train_meta["flow_id"]).isdisjoint(test_meta["flow_id"])
    assert set(val_meta["flow_id"]).isdisjoint(test_meta["flow_id"])


def test_shared_temporal_split_keeps_complete_rows_and_global_boundaries():
    train, validation, test = split_temporally(_mixed_time_flows())

    _assert_disjoint_time_ranges(train, validation, test)
    assert len(train) + len(validation) + len(test) == 10
    assert list(train["feature"]) == [0, 1, 2, 3, 4, 5]
    assert list(validation["feature"]) == [6, 7]
    assert list(test["feature"]) == [8, 9]


def test_split_never_divides_rows_with_identical_timestamps():
    data = _mixed_time_flows()
    data.loc[data["feature"] == 1, "timestamp"] = data.loc[
        data["feature"] == 0, "timestamp"
    ].iloc[0]

    train, validation, test = split_temporally(data)

    _assert_disjoint_time_ranges(train, validation, test)
    assert len(train) + len(validation) + len(test) == 10


def test_global_time_split_rejects_invalid_timestamps():
    data = _mixed_time_flows()
    data.loc[data.index[0], "timestamp"] = pd.NaT

    with pytest.raises(ValueError, match="valid timestamp for every row"):
        split_temporally(data)

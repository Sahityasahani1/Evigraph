"""Read-only access to the flow table (CSV or Parquet). The ONLY place that knows its columns."""
from pathlib import Path

import pandas as pd

HIDDEN = {"label"}  # ground truth must never reach the agent


def _clean(row: pd.Series) -> dict:
    out = {}
    for k, v in row.items():
        if k in HIDDEN:
            continue
        if isinstance(v, pd.Timestamp):
            out[k] = v.isoformat()
        elif hasattr(v, "item"):
            out[k] = v.item()
        else:
            out[k] = v
    return out


class FlowStore:
    def __init__(self, path: str | Path):
        p = Path(path)
        df = pd.read_parquet(p) if p.suffix == ".parquet" else pd.read_csv(p)
        df["timestamp"] = pd.to_datetime(df["timestamp"], format="ISO8601")
        if df["flow_id"].duplicated().any():
            raise ValueError("flow_id must be unique")
        self.df = df.sort_values("timestamp").set_index("flow_id", drop=False)

    def has_flow(self, flow_id: str) -> bool:
        return flow_id in self.df.index

    def flows_for_host(self, ip, start=None, end=None, limit=10):
        d = self.df
        mask = (d["src_ip"] == ip) | (d["dst_ip"] == ip)
        if start is not None:
            mask &= d["timestamp"] >= start
        if end is not None:
            mask &= d["timestamp"] <= end
        sel = d[mask]
        return len(sel), [_clean(r) for _, r in sel.head(limit).iterrows()]

    def host_summary(self, ip):
        d = self.df
        out, inn = d[d["src_ip"] == ip], d[d["dst_ip"] == ip]
        if out.empty and inn.empty:
            return None
        both = pd.concat([out, inn])
        return {
            "host_ip": ip,
            "flows_total": len(both),
            "flows_as_source": len(out),
            "flows_as_destination": len(inn),
            "first_seen": both["timestamp"].min().isoformat(),
            "last_seen": both["timestamp"].max().isoformat(),
            "unique_destination_hosts": int(out["dst_ip"].nunique()),
            "unique_destination_ports": int(out["dst_port"].nunique()),
            "top_destination_ports": {
                str(p): int(c) for p, c in out["dst_port"].value_counts().head(5).items()
            },
            "bytes_sent": float(out["tot_len_fwd_pkts"].sum() + inn["tot_len_bwd_pkts"].sum()),
            "bytes_received": float(out["tot_len_bwd_pkts"].sum() + inn["tot_len_fwd_pkts"].sum()),
            "syn_flags_as_source": int(out["syn_flag_cnt"].sum()),
            "rst_flags_as_source": int(out["rst_flag_cnt"].sum()),
        }
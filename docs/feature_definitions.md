# Exact Formula & Operational Specification for 35 Canonical Network Flow Features

**Document:** Canonical Feature Definitions & Mathematical Specifications  
**Author:** Member 1 (Data & Traffic Pipeline)  
**Standard:** CICFlowMeter v4.0 / CICIDS2017 & Member 2 Model Specifications  
**Status:** Approved Reference Standard  
**Date:** October 2026  

---

## 1. Overview & Mathematical Conventions

This document provides the exhaustive mathematical formula, unit of measurement, directionality, and boundary behavior for all **35 canonical features** extracted by the EviGraph PCAP streaming pipeline (`parsers/pcap.py`).

### 1.1 Notation & Definitions
- **5-Tuple:** An ordered identifier `(src_ip, src_port, dst_ip, dst_port, protocol)`.
- **Directionality:**
  - **Forward ($fwd$):** Traffic flowing from the initial connection initiator ($A \to B$).
  - **Backward ($bwd$):** Traffic flowing in the reverse direction ($B \to A$).
- **Packet Lengths:**
  - $L_f = [l_{f,1}, l_{f,2}, \dots, l_{f,N_f}]$: Sequence of packet lengths (in bytes) in the forward direction.
  - $L_b = [l_{b,1}, l_{b,2}, \dots, l_{b,N_b}]$: Sequence of packet lengths (in bytes) in the backward direction.
  - $L_{all} = L_f \mathbin{\Vert} L_b$: Concatenation of all packet lengths in the flow.
  - $N_f = |L_f|$: Total forward packet count (`tot_fwd_pkts`).
  - $N_b = |L_b|$: Total backward packet count (`tot_bwd_pkts`).
- **Timestamps & Inter-Arrival Times (IAT):**
  - $T_{all} = [t_1, t_2, \dots, t_N]$: Monotonically ordered packet arrival timestamps (in seconds).
  - $T_f = [t_{f,1}, t_{f,2}, \dots, t_{f,N_f}]$: Forward packet timestamps.
  - $T_b = [t_{b,1}, t_{b,2}, \dots, t_{b,N_b}]$: Backward packet timestamps.
  - $IAT_{all} = [(t_{i} - t_{i-1}) \times 10^6 \mid i = 2, \dots, N]$ (in microseconds).
  - $IAT_f = [(t_{f,i} - t_{f,i-1}) \times 10^6 \mid i = 2, \dots, N_f]$ (in microseconds).
  - $IAT_b = [(t_{b,i} - t_{b,i-1}) \times 10^6 \mid i = 2, \dots, N_b]$ (in microseconds).
- **Timeouts:**
  - Idle timeout: **120 seconds** (flows with inter-packet gaps $> 120s$ are closed).
  - Active timeout: **1800 seconds** (flows exceeding 30 minutes duration are segmented).
  - Connection teardown: TCP `RST` terminates immediately; `FIN` terminates connection.

---

## 2. Feature-by-Feature Specification Table

| # | Feature Name in `config.py` | Canonical Store Column | Mathematical Formula | Unit | Direction | Edge Case / Fallback |
| :-: | :--- | :--- | :--- | :--- | :--- | :--- |
| **1** | `flow_duration` | `feat_flow_duration` | $(t_N - t_1) \times 10^6$ | Microseconds ($\mu s$) | Bidirectional | Single packet: $0.0$ |
| **2** | `tot_fwd_pkts` | `feat_tot_fwd_pkts` | $N_f = \lvert L_f \rvert$ | Count | Forward | $\ge 1$ |
| **3** | `tot_bwd_pkts` | `feat_tot_bwd_pkts` | $N_b = \lvert L_b \rvert$ | Count | Backward | $\ge 0$ |
| **4** | `tot_len_fwd_pkts` | `feat_tot_len_fwd_pkts` | $\sum_{i=1}^{N_f} l_{f,i}$ | Bytes | Forward | $\ge 0$ |
| **5** | `tot_len_bwd_pkts` | `feat_tot_len_bwd_pkts` | $\sum_{i=1}^{N_b} l_{b,i}$ | Bytes | Backward | $\ge 0$ |
| **6** | `fwd_pkt_len_max` | `feat_fwd_pkt_len_max` | $\max(L_f)$ | Bytes | Forward | Empty: $0.0$ |
| **7** | `fwd_pkt_len_min` | `feat_fwd_pkt_len_min` | $\min(L_f)$ | Bytes | Forward | Empty: $0.0$ |
| **8** | `fwd_pkt_len_mean` | `feat_fwd_pkt_len_mean` | $\frac{1}{N_f} \sum_{i=1}^{N_f} l_{f,i}$ | Bytes | Forward | Empty: $0.0$ |
| **9** | `fwd_pkt_len_std` | `feat_fwd_pkt_len_std` | $\sqrt{\frac{1}{N_f - 1} \sum_{i=1}^{N_f} (l_{f,i} - \mu_{fwd})^2}$ | Bytes | Forward | $N_f \le 1 \implies 0.0$ |
| **10** | `bwd_pkt_len_max` | `feat_bwd_pkt_len_max` | $\max(L_b)$ | Bytes | Backward | Empty: $0.0$ |
| **11** | `bwd_pkt_len_min` | `feat_bwd_pkt_len_min` | $\min(L_b)$ | Bytes | Backward | Empty: $0.0$ |
| **12** | `bwd_pkt_len_mean` | `feat_bwd_pkt_len_mean` | $\frac{1}{N_b} \sum_{i=1}^{N_b} l_{b,i}$ | Bytes | Backward | Empty: $0.0$ |
| **13** | `bwd_pkt_len_std` | `feat_bwd_pkt_len_std` | $\sqrt{\frac{1}{N_b - 1} \sum_{i=1}^{N_b} (l_{b,i} - \mu_{bwd})^2}$ | Bytes | Backward | $N_b \le 1 \implies 0.0$ |
| **14** | `flow_bytes_s` | `feat_flow_bytes_s` | $\frac{\text{tot\_len\_fwd\_pkts} + \text{tot\_len\_bwd\_pkts}}{\max(10^{-6}, (t_N - t_1))}$ | Bytes / sec | Bidirectional | Single packet: $\frac{\text{bytes}}{10^{-6}}$ |
| **15** | `flow_pkts_s` | `feat_flow_pkts_s` | $\frac{N_f + N_b}{\max(10^{-6}, (t_N - t_1))}$ | Packets / sec | Bidirectional | Single packet: $\frac{\text{pkts}}{10^{-6}}$ |
| **16** | `flow_iat_mean` | `feat_flow_iat_mean` | $\frac{1}{\lvert IAT_{all} \rvert} \sum \Delta t_{all}$ | Microseconds ($\mu s$) | Bidirectional | $\lvert IAT \rvert = 0 \implies 0.0$ |
| **17** | `flow_iat_std` | `feat_flow_iat_std` | $\sqrt{\frac{1}{\lvert IAT_{all} \rvert - 1} \sum (\Delta t_i - \mu_{iat})^2}$ | Microseconds ($\mu s$) | Bidirectional | $\lvert IAT \rvert \le 1 \implies 0.0$ |
| **18** | `flow_iat_max` | `feat_flow_iat_max` | $\max(IAT_{all})$ | Microseconds ($\mu s$) | Bidirectional | Empty: $0.0$ |
| **19** | `flow_iat_min` | `feat_flow_iat_min` | $\min(IAT_{all})$ | Microseconds ($\mu s$) | Bidirectional | Empty: $0.0$ |
| **20** | `fwd_iat_tot` | `feat_fwd_iat_tot` | $\sum IAT_f = (t_{f,N_f} - t_{f,1}) \times 10^6$ | Microseconds ($\mu s$) | Forward | $N_f \le 1 \implies 0.0$ |
| **21** | `bwd_iat_tot` | `feat_bwd_iat_tot` | $\sum IAT_b = (t_{b,N_b} - t_{b,1}) \times 10^6$ | Microseconds ($\mu s$) | Backward | $N_b \le 1 \implies 0.0$ |
| **22** | `fwd_psh_flags` | `feat_fwd_psh_flags` | $\sum_{i=1}^{N_f} \mathbb{I}(\text{flags}_{f,i} \mathbin{\&} \text{0x08})$ | Count | Forward | $\ge 0$ |
| **23** | `bwd_psh_flags` | `feat_bwd_psh_flags` | $\sum_{i=1}^{N_b} \mathbb{I}(\text{flags}_{b,i} \mathbin{\&} \text{0x08})$ | Count | Backward | $\ge 0$ |
| **24** | `fwd_urg_flags` | `feat_fwd_urg_flags` | $\sum_{i=1}^{N_f} \mathbb{I}(\text{flags}_{f,i} \mathbin{\&} \text{0x20})$ | Count | Forward | $\ge 0$ |
| **25** | `bwd_urg_flags` | `feat_bwd_urg_flags` | $\sum_{i=1}^{N_b} \mathbb{I}(\text{flags}_{b,i} \mathbin{\&} \text{0x20})$ | Count | Backward | $\ge 0$ |
| **26** | `fin_flag_cnt` | `feat_fin_flag_cnt` | $\sum_{i=1}^{N} \mathbb{I}(\text{flags}_i \mathbin{\&} \text{0x01})$ | Count | Bidirectional | $\ge 0$ |
| **27** | `syn_flag_cnt` | `feat_syn_flag_cnt` | $\sum_{i=1}^{N} \mathbb{I}(\text{flags}_i \mathbin{\&} \text{0x02})$ | Count | Bidirectional | $\ge 0$ |
| **28** | `rst_flag_cnt` | `feat_rst_flag_cnt` | $\sum_{i=1}^{N} \mathbb{I}(\text{flags}_i \mathbin{\&} \text{0x04})$ | Count | Bidirectional | $\ge 0$ |
| **29** | `psh_flag_cnt` | `feat_psh_flag_cnt` | $\sum_{i=1}^{N} \mathbb{I}(\text{flags}_i \mathbin{\&} \text{0x08})$ | Count | Bidirectional | $\ge 0$ |
| **30** | `ack_flag_cnt` | `feat_ack_flag_cnt` | $\sum_{i=1}^{N} \mathbb{I}(\text{flags}_i \mathbin{\&} \text{0x10})$ | Count | Bidirectional | $\ge 0$ |
| **31** | `urg_flag_cnt` | `feat_urg_flag_cnt` | $\sum_{i=1}^{N} \mathbb{I}(\text{flags}_i \mathbin{\&} \text{0x20})$ | Count | Bidirectional | $\ge 0$ |
| **32** | `down_up_ratio` | `feat_down_up_ratio` | $\frac{N_b}{N_f}$ | Ratio | Bidirectional | $N_f = 0 \implies 0.0$ |
| **33** | `pkt_size_avg` | `feat_pkt_size_avg` | $\frac{\sum_{i=1}^{N} l_i}{N}$ | Bytes | Bidirectional | $N = 0 \implies 0.0$ |
| **34** | `init_fwd_win_byts` | `feat_init_fwd_win_byts` | First observed TCP window size in $A \to B$ | Bytes | Forward | Non-TCP: $0$ |
| **35** | `init_bwd_win_byts` | `feat_init_bwd_win_byts` | First observed TCP window size in $B \to A$ | Bytes | Backward | Non-TCP: $0$ |

---

## 3. Storage Unit Isolation Principle

In the EviGraph architecture, feature storage adheres strictly to **Member 2 Inter-Member Contract Section 3.2**:

1. **Model Features (`feat_*`)**:
   - `feat_flow_duration`, `feat_flow_iat_*`, `feat_fwd_iat_tot`, and `feat_bwd_iat_tot` are stored in **MICROSECONDS** ($\mu s$) as `float32`.
   - Reason: Member 2's GNN and HistGradientBoosting tree splits were trained directly on CICIDS microsecond distributions ($\sim 10^3 - 10^8 \mu s$). Modifying these to seconds causes model collapse.

2. **Forensic Timestamp & Canonical Duration**:
   - The primary canonical column `duration` is stored in **SECONDS** (`float64`) for human forensic readability and standard SI unit compliance.
   - `ts_end = ts_start + pd.to_timedelta(duration, unit="s")`.

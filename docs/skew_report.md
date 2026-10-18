# Train/Serve Feature Distribution Skew Report

**Pipeline Component:** Member 1 PCAP-to-Flows Streaming Parser vs CICIDS Ground-Truth CSV  
**Statistical Standard:** Two-Sample Kolmogorov-Smirnov Test (`scipy.stats.ks_2samp`)  
**Generated:** 2026-10-18T06:09:08.327870+00:00  

## 1. Executive Summary

To guarantee forensic validity and zero train/serve feature skew, the streaming PCAP parser's calculated features are validated against pre-computed CICIDS benchmark telemetry. The Kolmogorov-Smirnov (KS) statistic tests the null hypothesis that the empirical distributions of the streaming pipeline and reference dataset are drawn from identical continuous distributions.

| Alignment Level | KS Statistic Range | Interpretation |
| :--- | :--- | :--- |
| **Negligible Skew** | $D < 0.10$ | Statistically identical feature geometry |
| **Low Skew** | $0.10 \le D < 0.25$ | Minor rounding or timing variance |
| **Moderate Skew** | $0.25 \le D < 0.50$ | Noticeable discretization shift |
| **High Skew** | $D \ge 0.50$ | Structural definition divergence (Requires Retraining) |

## 2. Feature-by-Feature Skew Evaluation (All 35 Canonical Features)

| Feature Name | KS Statistic ($D$) | p-value | PCAP Mean | CSV Mean | Alignment Status |
| :--- | :---: | :---: | :---: | :---: | :--- |
| `flow_duration` | 1.0000 | 0.0000 | 0.00 | 132,039.55 | **High Skew** |
| `tot_fwd_pkts` | 1.0000 | 0.0000 | 1.00 | 17.27 | **High Skew** |
| `tot_bwd_pkts` | 1.0000 | 0.0000 | 0.00 | 17.43 | **High Skew** |
| `tot_len_fwd_pkts` | 1.0000 | 0.0000 | 129.20 | 1,202.77 | **High Skew** |
| `tot_len_bwd_pkts` | 1.0000 | 0.0000 | 0.00 | 4,496.88 | **High Skew** |
| `fwd_pkt_len_max` | 0.9100 | 0.0000 | 129.20 | 752.41 | **High Skew** |
| `fwd_pkt_len_min` | 1.0000 | 0.0000 | 129.20 | 40.00 | **High Skew** |
| `fwd_pkt_len_mean` | 0.3700 | 0.0000 | 129.20 | 165.35 | **Moderate Skew** |
| `fwd_pkt_len_std` | 1.0000 | 0.0000 | 0.00 | 44.16 | **High Skew** |
| `bwd_pkt_len_max` | 1.0000 | 0.0000 | 0.00 | 988.80 | **High Skew** |
| `bwd_pkt_len_min` | 1.0000 | 0.0000 | 0.00 | 40.00 | **High Skew** |
| `bwd_pkt_len_mean` | 1.0000 | 0.0000 | 0.00 | 514.19 | **High Skew** |
| `bwd_pkt_len_std` | 1.0000 | 0.0000 | 0.00 | 113.06 | **High Skew** |
| `flow_bytes_s` | 1.0000 | 0.0000 | 129,200,016.00 | 43,320.78 | **High Skew** |
| `flow_pkts_s` | 1.0000 | 0.0000 | 1,000,000.00 | 107.29 | **High Skew** |
| `flow_iat_mean` | 1.0000 | 0.0000 | 0.00 | 28,204.93 | **High Skew** |
| `flow_iat_std` | 1.0000 | 0.0000 | 0.00 | 10,625.78 | **High Skew** |
| `flow_iat_max` | 1.0000 | 0.0000 | 0.00 | 58,590.13 | **High Skew** |
| `flow_iat_min` | 1.0000 | 0.0000 | 0.00 | 248.31 | **High Skew** |
| `fwd_iat_tot` | 1.0000 | 0.0000 | 0.00 | 107,453.82 | **High Skew** |
| `bwd_iat_tot` | 1.0000 | 0.0000 | 0.00 | 107,937.95 | **High Skew** |
| `fwd_psh_flags` | 0.2900 | 0.0004 | 0.00 | 0.29 | **Moderate Skew** |
| `bwd_psh_flags` | 0.3000 | 0.0002 | 0.00 | 0.30 | **Moderate Skew** |
| `fwd_urg_flags` | 0.0000 | 1.0000 | 0.00 | 0.00 | **Negligible Skew** |
| `bwd_urg_flags` | 0.0000 | 1.0000 | 0.00 | 0.00 | **Negligible Skew** |
| `fin_flag_cnt` | 1.0000 | 0.0000 | 0.00 | 1.00 | **High Skew** |
| `syn_flag_cnt` | 0.1900 | 0.0539 | 0.81 | 1.00 | **Low Skew** |
| `rst_flag_cnt` | 0.0000 | 1.0000 | 0.00 | 0.00 | **Negligible Skew** |
| `psh_flag_cnt` | 1.0000 | 0.0000 | 0.00 | 1.00 | **High Skew** |
| `ack_flag_cnt` | 1.0000 | 0.0000 | 0.00 | 1.00 | **High Skew** |
| `urg_flag_cnt` | 0.0000 | 1.0000 | 0.00 | 0.00 | **Negligible Skew** |
| `down_up_ratio` | 1.0000 | 0.0000 | 0.00 | 1.14 | **High Skew** |
| `pkt_size_avg` | 0.6500 | 0.0000 | 129.20 | 283.72 | **High Skew** |
| `init_fwd_win_byts` | 0.1900 | 0.0539 | 23,652.00 | 29,200.00 | **Low Skew** |
| `init_bwd_win_byts` | 1.0000 | 0.0000 | 0.00 | 28,960.00 | **High Skew** |

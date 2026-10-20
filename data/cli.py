"""
EviGraph Data & Traffic Pipeline CLI (Member 1)
Built with Typer for command-line operation, validation, and automated pipelines.
Commands:
  ingest          Ingests capture into immutable vault and processed Parquet
  features        Computes anti-leakage flow features and host behavioral graph metrics
  verify          Cryptographically verifies audit log chain and evidence files
  stats           Displays catalog summary, host count, and attack class distribution
  export-member2  Exports strict 44-column Member-2 dataset with sidecar manifest
  run-all         End-to-end multi-stage pipeline execution with per-stage timing & peak RSS
"""

import os
import time
from pathlib import Path
from typing import Optional

import psutil
import typer
from rich.console import Console
from rich.table import Table

from data.adapters import export_member2
from data.config import settings
from data.evidence import AuditLogger, EvidenceStore, IntegrityError, verify_chain
from data.features.host import HostFeatureExtractor
from data.parsers import parse_cicids, parse_pcap, parse_zeek_conn
from data.query import QueryAPI
from data.storage import DuckDBCatalog, ParquetStorageEngine

app = typer.Typer(
    name="evigraph-data",
    help="EviGraph Forensic Data & Traffic Pipeline (Member 1) CLI",
    add_completion=False
)
console = Console()


def get_peak_rss_mb() -> float:
    """Returns the current process's resident memory (RSS) in megabytes."""
    process = psutil.Process(os.getpid())
    return process.memory_info().rss / (1024 * 1024)


@app.command()
def ingest(
    path: Optional[Path] = typer.Option(None, "--path", "-p", help="Path to input capture file"),
    type: Optional[str] = typer.Option(None, "--type", "-t", help="Parser type: 'cicids', 'zeek', or 'pcap'"),
    source_description: Optional[str] = typer.Option(None, "--source-description", "-d", help="Provenance description"),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Target Parquet filename in data/processed/"),
    max_rows: Optional[int] = typer.Option(None, "--max-rows", "-n", help="Max rows to process"),
    # Positional argument for backward compatibility
    file_path: Optional[Path] = typer.Argument(None, help="Positional path to capture file")
):
    """Ingests, canonicalizes, and registers a network traffic capture into the forensic ledger."""
    target_path = path or file_path
    if not target_path or not target_path.exists():
        console.print(f"[bold red]Error: Input file does not exist:[/bold red] {target_path}")
        raise typer.Exit(code=1)

    console.print(f"[bold green]Ingesting telemetry file:[/bold green] {target_path.name}")

    # Register raw evidence
    store = EvidenceStore()
    desc = source_description or f"CLI Ingestion of {target_path.name}"
    ev_record = store.register_evidence(target_path, source_description=desc)
    ev_id = ev_record["evidence_id"]

    fmt = (type or "").lower()
    suffix = target_path.suffix.lower()

    if fmt == "zeek" or suffix == ".log":
        df = parse_zeek_conn(target_path, evidence_id=ev_id, max_rows=max_rows)
    elif fmt == "pcap" or suffix in (".pcap", ".pcapng"):
        df = parse_pcap(target_path, evidence_id=ev_id, max_packets=max_rows)
    else:
        df = parse_cicids(target_path, evidence_id=ev_id, max_rows=max_rows)

    if df.empty:
        console.print("[yellow]Warning: Parser returned 0 flows.[/yellow]")
        return

    # Write standardized parquet
    storage = ParquetStorageEngine()
    out_file = output or f"{target_path.stem}_processed.parquet"
    out_path = storage.write_parquet(df, out_file, sidecar_manifest=True)

    console.print(f"[bold green]Success![/bold green] Ingested [cyan]{len(df):,}[/cyan] flows into {out_path}")
    console.print(f"Evidence ID: [yellow]{ev_id}[/yellow] | SHA-256: [yellow]{ev_record['sha256'][:16]}...[/yellow]")


@app.command()
def features(
    output_host_features: Optional[str] = typer.Option(
        None, "--out-host", help="Output path for host_features.parquet"
    )
):
    """Computes flow feature rates and extracts host behavioral metrics into host_features.parquet."""
    console.print("[bold green]Computing host and flow behavioral features...[/bold green]")
    catalog = DuckDBCatalog()
    flows_df = catalog.query("SELECT * FROM flows")

    if flows_df.empty:
        console.print("[yellow]No flows found in catalog. Run 'ingest' first.[/yellow]")
        return

    # Extract host features
    host_extractor = HostFeatureExtractor(time_window_secs=settings.window_size_secs)
    out_path = Path(output_host_features) if output_host_features else None
    host_df, saved_path = host_extractor.extract_and_save(flows_df, out_path=out_path)

    console.print(f"[bold green]Host features successfully saved to:[/bold green] {saved_path}")
    console.print(f" * Unique Hosts Indexed: [cyan]{len(host_df):,}[/cyan]")
    console.print(f" * Host Metrics Computed: [cyan]{len(host_df.columns)}[/cyan]")


@app.command(name="verify")
def verify():
    """Validates the audit log hash chain and re-hashes every registered evidence file."""
    try:
        verify_chain()
        console.print("[bold green]PASS: Evidence integrity and audit log hash chain are 100% verified.[/bold green]")
    except IntegrityError as e:
        console.print(f"[bold red]INTEGRITY VIOLATION DETECTED:[/bold red] {e}")
        raise typer.Exit(code=1) from e


@app.command(name="stats")
def stats():
    """Displays dataset catalog summary, host count, and attack class distributions."""
    summary()


@app.command()
def summary():
    """Displays dataset catalog summary and attack class distributions from DuckDB."""
    catalog = DuckDBCatalog()
    info = catalog.get_catalog_summary()

    if info.get("total_flows", 0) == 0:
        console.print("[yellow]Catalog is empty. Ingest data first with 'ingest' command.[/yellow]")
        return

    console.print("\n[bold]EviGraph Telemetry Catalog Summary:[/bold]")
    console.print(f" * Total Flows : [cyan]{info['total_flows']:,}[/cyan]")
    console.print(f" * Total Hosts : [cyan]{info.get('total_hosts', 0):,}[/cyan]")
    if "time_range" in info and isinstance(info["time_range"], dict):
        console.print(f" * Time Window : {info['time_range'].get('start')} -> {info['time_range'].get('end')}")

    table = Table(title="Class Distribution")
    table.add_column("Attack Family", style="cyan")
    table.add_column("Flow Count", justify="right", style="green")

    for label, count in info.get("class_distribution", {}).items():
        table.add_row(str(label), f"{count:,}")

    console.print(table)


@app.command(name="export-member2")
def export_member2_cmd(
    out: Path = typer.Option(
        Path("data/processed/member2_flows.parquet"), "--out", "-o", help="Target Parquet output path"
    ),
    split: Optional[str] = typer.Option(None, "--split", "-s", help="Optional split filter: train, val, test")
):
    """Exports strict 44-column Member-2 dataset with companion sidecar manifest."""
    console.print(f"[bold green]Exporting Member 2 dataset to:[/bold green] {out}")
    try:
        exported_path = export_member2(out, split=split)
        manifest_path = exported_path.parent / f"{exported_path.name}.manifest.json"
        console.print(f"[bold green]Success![/bold green] Exported Member 2 parquet to: {exported_path}")
        if manifest_path.exists():
            console.print(f"Sidecar Manifest: {manifest_path}")
    except Exception as e:
        console.print(f"[bold red]Export Error:[/bold red] {e}")
        raise typer.Exit(code=1)


@app.command()
def query(
    sql: str = typer.Argument(..., help="SQL query to execute against the DuckDB 'flows' view")
):
    """Executes a SQL query directly against the DuckDB catalog."""
    catalog = DuckDBCatalog()
    try:
        res = catalog.query(sql)
        console.print(res.to_string())
    except Exception as e:
        console.print(f"[bold red]SQL Query Error:[/bold red] {e}")
        raise typer.Exit(code=1)


@app.command()
def export_splits(
    train_ratio: float = typer.Option(0.60, "--train", "-t", help="Train split ratio"),
    val_ratio: float = typer.Option(0.20, "--val", "-v", help="Validation split ratio"),
    prefix: str = typer.Option("benchmark", "--prefix", "-p", help="Output split prefix")
):
    """Exports stratified temporal Train / Val / Test Parquet splits for Member 2."""
    api = QueryAPI()
    try:
        paths = api.export_splits_for_member2(train_ratio=train_ratio, val_ratio=val_ratio, split_prefix=prefix)
        console.print("[bold green]Successfully exported Member 2 Splits:[/bold green]")
        for split_name, p in paths.items():
            console.print(f" * {split_name.capitalize()}: {p.name}")
    except Exception as e:
        console.print(f"[bold red]Export Error:[/bold red] {e}")
        raise typer.Exit(code=1)


@app.command(name="run-all")
def run_all(
    cicids_dir: Path = typer.Option(..., "--cicids-dir", "-d", help="Directory or file path containing CICIDS captures"),
    limit_rows: Optional[int] = typer.Option(None, "--limit-rows", "-n", help="Max rows to process"),
    out: Path = typer.Option(Path("data/processed/member2_flows.parquet"), "--out", "-o", help="Member 2 export output path")
):
    """
    Executes the end-to-end multi-stage pipeline:
    ingest -> clean -> features -> storage -> catalog -> verify -> export-member2.
    Measures wall time and peak RSS per stage, records audit entries, and aborts if verify fails.
    """
    console.print("\n[bold cyan]=======================================================[/bold cyan]")
    console.print("[bold cyan]       EviGraph End-to-End Pipeline: RUN-ALL          [/bold cyan]")
    console.print("[bold cyan]=======================================================[/bold cyan]\n")

    logger = AuditLogger()
    stage_metrics = []

    # Find files to process
    if cicids_dir.is_file():
        files_to_process = [cicids_dir]
    elif cicids_dir.is_dir():
        files_to_process = sorted(list(cicids_dir.glob("*.csv")) + list(cicids_dir.glob("*.parquet")))
    else:
        console.print(f"[bold red]Error: Path does not exist:[/bold red] {cicids_dir}")
        raise typer.Exit(code=1)

    if not files_to_process:
        console.print(f"[bold red]No capture files found in:[/bold red] {cicids_dir}")
        raise typer.Exit(code=1)

    total_start = time.perf_counter()
    raw_dfs = []

    # -------------------------------------------------------------
    # STAGE 1: INGEST
    # -------------------------------------------------------------
    s1_start = time.perf_counter()
    console.print(f"[bold]Stage 1: INGEST ({len(files_to_process)} file(s))...[/bold]")
    store = EvidenceStore()
    evidence_ids = []

    for f in files_to_process:
        ev = store.register_evidence(f, source_description=f"run-all ingestion: {f.name}")
        evidence_ids.append(ev["evidence_id"])
        # Parse initial slice
        if f.suffix.lower() == ".parquet":
            import pandas as pd
            df_slice = pd.read_parquet(f)
            if limit_rows:
                df_slice = df_slice.head(limit_rows)
            df_slice["evidence_id"] = ev["evidence_id"]
            raw_dfs.append(df_slice)
        else:
            df_slice = parse_cicids(f, evidence_id=ev["evidence_id"], max_rows=limit_rows)
            raw_dfs.append(df_slice)

    s1_time = time.perf_counter() - s1_start
    s1_rss = get_peak_rss_mb()
    logger.log_action("RUN_ALL_INGEST", params={"files": len(files_to_process), "evidence_ids": evidence_ids})
    stage_metrics.append(("1. Ingest", s1_time, s1_rss))
    console.print(f"  --> Completed in {s1_time:.3f}s | Peak RSS: {s1_rss:.1f} MB")

    # Combine flows
    import pandas as pd
    combined_raw = pd.concat(raw_dfs, ignore_index=True) if raw_dfs else pd.DataFrame()

    # -------------------------------------------------------------
    # STAGE 2: CLEAN & CANONICALIZE
    # -------------------------------------------------------------
    s2_start = time.perf_counter()
    console.print(f"[bold]Stage 2: CLEAN ({len(combined_raw):,} raw flows)...[/bold]")
    from data.schema import validate_and_canonicalize
    cleaned_df = validate_and_canonicalize(combined_raw)
    s2_time = time.perf_counter() - s2_start
    s2_rss = get_peak_rss_mb()
    logger.log_action("RUN_ALL_CLEAN", params={"raw_rows": len(combined_raw), "cleaned_rows": len(cleaned_df)})
    stage_metrics.append(("2. Clean", s2_time, s2_rss))
    console.print(f"  --> Completed in {s2_time:.3f}s | Peak RSS: {s2_rss:.1f} MB")

    # -------------------------------------------------------------
    # STAGE 3: FEATURES (FLOW + HOST ISOLATION)
    # -------------------------------------------------------------
    s3_start = time.perf_counter()
    console.print("[bold]Stage 3: FEATURES (Flow 35 Features & Host Isolation)...[/bold]")
    host_extractor = HostFeatureExtractor(time_window_secs=settings.window_size_secs)
    host_df, host_feat_path = host_extractor.extract_and_save(cleaned_df)
    s3_time = time.perf_counter() - s3_start
    s3_rss = get_peak_rss_mb()
    logger.log_action("RUN_ALL_FEATURES", params={"flows": len(cleaned_df), "hosts": len(host_df)})
    stage_metrics.append(("3. Features", s3_time, s3_rss))
    console.print(f"  --> Completed in {s3_time:.3f}s | Peak RSS: {s3_rss:.1f} MB (Indexed {len(host_df):,} hosts)")

    # -------------------------------------------------------------
    # STAGE 4: STORAGE (PARQUET + MANIFEST)
    # -------------------------------------------------------------
    s4_start = time.perf_counter()
    console.print("[bold]Stage 4: STORAGE (Snappy Parquet & Sidecar Manifest)...[/bold]")
    storage = ParquetStorageEngine()
    storage_path = storage.write_parquet(cleaned_df, "flows.parquet", sidecar_manifest=True)
    s4_time = time.perf_counter() - s4_start
    s4_rss = get_peak_rss_mb()
    logger.log_action("RUN_ALL_STORAGE", params={"path": str(storage_path), "rows": len(cleaned_df)})
    stage_metrics.append(("4. Storage", s4_time, s4_rss))
    console.print(f"  --> Completed in {s4_time:.3f}s | Peak RSS: {s4_rss:.1f} MB")

    # -------------------------------------------------------------
    # STAGE 5: CATALOG (DUCKDB ZERO-COPY VIEWS)
    # -------------------------------------------------------------
    s5_start = time.perf_counter()
    console.print("[bold]Stage 5: CATALOG (DuckDB Analytical Views)...[/bold]")
    catalog = DuckDBCatalog()
    catalog.refresh()
    total_indexed = catalog.count_flows()
    s5_time = time.perf_counter() - s5_start
    s5_rss = get_peak_rss_mb()
    logger.log_action("RUN_ALL_CATALOG", params={"indexed_flows": total_indexed})
    stage_metrics.append(("5. Catalog", s5_time, s5_rss))
    console.print(f"  --> Completed in {s5_time:.3f}s | Peak RSS: {s5_rss:.1f} MB (Catalog flows: {total_indexed:,})")

    # -------------------------------------------------------------
    # STAGE 6: VERIFY (CRYPTOGRAPHIC CHAIN & AUDIT CHECK)
    # -------------------------------------------------------------
    s6_start = time.perf_counter()
    console.print("[bold]Stage 6: VERIFY (Cryptographic Chain-of-Custody)...[/bold]")
    try:
        verify_chain()
        s6_time = time.perf_counter() - s6_start
        s6_rss = get_peak_rss_mb()
        logger.log_action("RUN_ALL_VERIFY", params={"status": "PASS"})
        stage_metrics.append(("6. Verify", s6_time, s6_rss))
        console.print(f"  --> [bold green]PASS[/bold green] in {s6_time:.3f}s | Peak RSS: {s6_rss:.1f} MB")
    except IntegrityError as e:
        console.print(f"  --> [bold red]FAIL: Verification broken:[/bold red] {e}")
        logger.log_action("RUN_ALL_VERIFY", params={"status": "FAIL", "error": str(e)})
        console.print("[bold red]Pipeline ABORTED at Stage 6 due to verification failure![/bold red]")
        raise typer.Exit(code=1)

    # -------------------------------------------------------------
    # STAGE 7: EXPORT-MEMBER2 (STRICT 44-COLUMN CONTRACT)
    # -------------------------------------------------------------
    s7_start = time.perf_counter()
    console.print(f"[bold]Stage 7: EXPORT-MEMBER2 ({out})...[/bold]")
    exported_p = export_member2(out, df=cleaned_df)
    s7_time = time.perf_counter() - s7_start
    s7_rss = get_peak_rss_mb()
    logger.log_action("RUN_ALL_EXPORT_MEMBER2", params={"out": str(exported_p), "rows": len(cleaned_df)})
    stage_metrics.append(("7. Export Member 2", s7_time, s7_rss))
    console.print(f"  --> Completed in {s7_time:.3f}s | Peak RSS: {s7_rss:.1f} MB")

    total_time = time.perf_counter() - total_start
    final_rss = get_peak_rss_mb()
    rows_per_sec = len(cleaned_df) / max(total_time, 0.001)

    # Output Summary Table
    table = Table(title="EviGraph Multi-Stage Pipeline Execution Report")
    table.add_column("Stage", style="cyan")
    table.add_column("Wall Time (s)", justify="right", style="green")
    table.add_column("Peak RSS (MB)", justify="right", style="magenta")

    for st_name, st_t, st_m in stage_metrics:
        table.add_row(st_name, f"{st_t:.3f}", f"{st_m:.1f}")

    table.add_row("[bold]TOTAL[/bold]", f"[bold]{total_time:.3f}[/bold]", f"[bold]{final_rss:.1f}[/bold]")
    console.print("\n", table)

    console.print(f"\n[bold green]Pipeline Run-All Finished Successfully![/bold green]")
    console.print(f" * Processed Flows : [cyan]{len(cleaned_df):,}[/cyan]")
    console.print(f" * Throughput      : [cyan]{rows_per_sec:,.1f} rows/s[/cyan]")
    console.print(f" * Member 2 Export : [yellow]{exported_p}[/yellow]\n")


if __name__ == "__main__":
    app()

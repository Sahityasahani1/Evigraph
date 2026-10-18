"""
EviGraph Data & Traffic Pipeline CLI (Member 1)
Built with Typer for command-line operation, validation, and automated pipelines.
"""

from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.table import Table

from evigraph.data.evidence import EvidenceStore
from evigraph.data.parsers import parse_cicids, parse_pcap, parse_zeek_conn
from evigraph.data.query import QueryAPI
from evigraph.data.storage import DuckDBCatalog, ParquetStorageEngine

app = typer.Typer(
    name="evigraph-data",
    help="EviGraph Forensic Data & Traffic Pipeline (Member 1) CLI",
    add_completion=False
)
console = Console()


@app.command()
def ingest(
    file_path: Path = typer.Argument(..., help="Path to input capture file (.csv, .parquet, .log, .pcap)"),
    evidence_id: Optional[str] = typer.Option(None, "--evidence-id", "-e", help="Custom evidence ID or hash"),
    output_name: Optional[str] = typer.Option(None, "--output", "-o", help="Target Parquet filename in data/processed/"),
    max_rows: Optional[int] = typer.Option(None, "--max-rows", "-n", help="Max rows to process"),
    format_type: Optional[str] = typer.Option(None, "--format", "-f", help="Format override: 'cicids', 'zeek', or 'pcap'")
):
    """Ingests, canonicalizes, and registers a network traffic capture into the forensic ledger."""
    file_path = Path(file_path)
    if not file_path.exists():
        console.print(f"[bold red]Error: File does not exist:[/bold red] {file_path}")
        raise typer.Exit(code=1)

    console.print(f"[bold green]Ingesting telemetry file:[/bold green] {file_path.name}")

    # Register raw evidence
    store = EvidenceStore()
    ev_record = store.register_evidence(file_path)
    ev_id = evidence_id or ev_record["evidence_id"]

    # Determine parser
    fmt = (format_type or "").lower()
    suffix = file_path.suffix.lower()

    if fmt == "zeek" or suffix == ".log":
        df = parse_zeek_conn(file_path, evidence_id=ev_id, max_rows=max_rows)
    elif fmt == "pcap" or suffix in (".pcap", ".pcapng"):
        df = parse_pcap(file_path, evidence_id=ev_id, max_packets=max_rows)
    else:
        df = parse_cicids(file_path, evidence_id=ev_id, max_rows=max_rows)

    if df.empty:
        console.print("[yellow]Warning: Parser returned 0 flows.[/yellow]")
        return

    # Write standardized parquet
    storage = ParquetStorageEngine()
    out_file = output_name or f"{file_path.stem}_processed.parquet"
    out_path = storage.write_parquet(df, out_file)

    console.print(f"[bold green]Success![/bold green] Ingested [cyan]{len(df):,}[/cyan] flows into {out_path}")
    console.print(f"Evidence ID: [yellow]{ev_id}[/yellow] | SHA-256: [yellow]{ev_record['sha256'][:16]}...[/yellow]")


@app.command(name="verify")
def verify():
    """Validates the audit log hash chain and re-hashes every registered evidence file."""
    from evigraph.data.evidence import IntegrityError, verify_chain
    try:
        verify_chain()
        console.print("[bold green]PASS: Evidence integrity and audit log hash chain are 100% verified.[/bold green]")
    except IntegrityError as e:
        console.print(f"[bold red]INTEGRITY VIOLATION DETECTED:[/bold red] {e}")
        raise typer.Exit(code=1) from e


@app.command(name="verify-evidence", hidden=True)
def verify_evidence():
    """Alias for verify command."""
    verify()


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
    if "time_range" in info:
        console.print(f" * Time Window : {info['time_range']['start']} -> {info['time_range']['end']}")

    table = Table(title="Class Distribution")
    table.add_column("Attack Family", style="cyan")
    table.add_column("Flow Count", justify="right", style="green")

    for label, count in info.get("class_distribution", {}).items():
        table.add_row(str(label), f"{count:,}")

    console.print(table)


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
        for split_name, path in paths.items():
            console.print(f" * {split_name.capitalize()}: {path.name}")
    except Exception as e:
        console.print(f"[bold red]Export Error:[/bold red] {e}")
        raise typer.Exit(code=1)


if __name__ == "__main__":
    app()

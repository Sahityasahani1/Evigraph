"""
Tests for CLI interface
"""

from typer.testing import CliRunner

from evigraph.data.cli import app

runner = CliRunner()


def test_cli_help():
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    assert "EviGraph Forensic Data & Traffic Pipeline" in result.output
    assert "ingest" in result.output
    assert "verify" in result.output
    assert "summary" in result.output
    assert "query" in result.output
    assert "export-splits" in result.output


def test_cli_verify():
    result = runner.invoke(app, ["verify"])
    assert result.exit_code == 0
    assert "PASS" in result.output

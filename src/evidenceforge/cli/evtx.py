"""Explicit binary export of already-finalized EvidenceForge Windows events."""

from pathlib import Path

import typer

from evidenceforge.evtx_export import EvtxExportError, export_evtx


def export_evtx_command(
    source: Path = typer.Argument(..., exists=True, dir_okay=False, readable=True),
    destination: Path = typer.Argument(..., dir_okay=False),
) -> None:
    """Serialize completed Windows Events XML as genuine binary EVTX.

    SOURCE must contain one host/channel and strictly increasing native record IDs.
    DESTINATION must not exist. Prints a JSON content-identity receipt on success.
    """
    try:
        receipt = export_evtx(source, destination)
    except (EvtxExportError, OSError) as exc:
        typer.echo(f"EVTX export failed: {exc}", err=True)
        raise typer.Exit(code=1) from exc
    typer.echo(receipt.model_dump_json())

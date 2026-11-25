"""Binary-export boundaries; expected facts originate in input XML."""

import hashlib
import json
import struct
import zlib
from datetime import UTC
from pathlib import Path
from xml.etree import ElementTree as ET

import pytest
from Evtx.Evtx import Evtx

NS = "http://schemas.microsoft.com/win/2004/08/events/event"


def event(
    record_id: int,
    *,
    time: str = "2026-01-02T03:04:05.1234567Z",
    computer: str = "host.example",
    payload: str = "",
) -> str:
    return f'''<Event xmlns="{NS}"><System>
<Provider Name="Microsoft-Windows-Security-Auditing" Guid="{{54849625-5478-4994-a5ba-3e3b0328c30d}}"/>
<EventID>4624</EventID><Version>2</Version><Level>0</Level><Task>12544</Task>
<Opcode>0</Opcode><Keywords>0x8020000000000000</Keywords>
<TimeCreated SystemTime="{time}"/><EventRecordID>{record_id}</EventRecordID>
<Correlation/><Execution ProcessID="4" ThreadID="9"/><Channel>Security</Channel>
<Computer>{computer}</Computer><Security UserID="S-1-5-18"/></System>
{payload or '<EventData><Data Name="TargetUserName">Zoë &amp; 李 😀</Data><Data Name="Empty"/></EventData>'}
</Event>'''


def export(tmp_path: Path, records: list[str]):
    from evidenceforge.evtx_export import export_evtx

    source, output = tmp_path / "source.xml", tmp_path / "output.evtx"
    source.write_text(
        "<?xml version='1.0' encoding='utf-8'?><Events>" + "".join(records) + "</Events>"
    )
    return source, output, export_evtx(source, output)


def headers(path: Path) -> tuple[bytes, list[bytes]]:
    data = path.read_bytes()
    assert data[:8] == b"ElfFile\0"
    assert len(data) >= 4096 and (len(data) - 4096) % 65536 == 0
    assert struct.unpack_from("<I", data, 124)[0] == zlib.crc32(data[:120])
    chunks = [data[p : p + 65536] for p in range(4096, len(data), 65536)]
    for chunk in chunks:
        assert chunk[:8] == b"ElfChnk\0"
        free = struct.unpack_from("<I", chunk, 48)[0]
        assert struct.unpack_from("<I", chunk, 52)[0] == zlib.crc32(chunk[512:free])
        assert struct.unpack_from("<I", chunk, 124)[0] == zlib.crc32(
            chunk[128:512], zlib.crc32(chunk[:120])
        )
    return data[:4096], chunks


def test_writes_binary_with_native_id_gaps_and_exact_filetime(tmp_path):
    source, output, receipt = export(tmp_path, [event(900_001), event(900_008)])
    header, chunks = headers(output)
    assert receipt.records == 2 and receipt.chunks == 1
    assert receipt.source_sha256 != receipt.output_sha256
    assert source.read_bytes().startswith(b"<?xml")
    assert struct.unpack_from("<Q", header, 24)[0] == 900_009
    assert struct.unpack_from("<QQQQ", chunks[0], 8) == (1, 2, 900_001, 900_008)
    # Independently calculated ticks from 1601-01-01 to 2026-01-02T03:04:05Z.
    from datetime import datetime

    delta = datetime(2026, 1, 2, 3, 4, 5, tzinfo=UTC) - datetime(1601, 1, 1, tzinfo=UTC)
    expected = (delta.days * 86400 + delta.seconds) * 10_000_000 + 1_234_567
    assert struct.unpack_from("<Q", chunks[0], 512 + 16)[0] == expected
    assert receipt.source_sha256 == hashlib.sha256(source.read_bytes()).hexdigest()
    assert receipt.output_sha256 == hashlib.sha256(output.read_bytes()).hexdigest()


def test_same_xml_produces_identical_bytes_and_streams_multiple_chunks(tmp_path):
    from evidenceforge.evtx_export import export_evtx

    payload = '<EventData><Data Name="Message">' + "a" * 2500 + "</Data></EventData>"
    source, output, receipt = export(
        tmp_path, [event(100 + i * 11, payload=payload) for i in range(25)]
    )
    second = tmp_path / "again.evtx"
    export_evtx(source, second)
    assert second.read_bytes() == output.read_bytes()
    _, chunks = headers(output)
    assert len(chunks) > 1 and receipt.chunks == len(chunks)
    previous = 0
    for chunk in chunks:
        first, last = struct.unpack_from("<QQ", chunk, 8)
        assert first == previous + 1
        previous = last
    assert previous == 25


@pytest.mark.parametrize(
    "records, message",
    [
        ([event(9), event(1)], "increasing"),
        ([event(9), event(9)], "increasing"),
        ([event(1), event(2, computer="other.example")], "host/channel"),
        ([event(1, time="2026-01-01T00:00:00")], "timestamp"),
        ([event(1, time="2026-01-01T00:00:00.12345678Z")], "timestamp"),
        ([event(0)], "record ID"),
        (
            [
                event(1).replace(
                    "<EventRecordID>1</EventRecordID>",
                    "<EventRecordID>" + "9" * 5000 + "</EventRecordID>",
                )
            ],
            "record ID",
        ),
        ([event(1).replace("<EventRecordID>1</EventRecordID>", "")], "EventRecordID"),
        (
            [event(1).replace("<Version>2</Version>", "<EventRecordID>2</EventRecordID>")],
            "EventRecordID",
        ),
        (
            [
                event(
                    1,
                    payload='<EventData><Data Name="TooLarge">'
                    + "x" * 100_000
                    + "</Data></EventData>",
                )
            ],
            "limit",
        ),
    ],
)
def test_invalid_source_never_publishes_partial_output(tmp_path, records, message):
    from evidenceforge.evtx_export import EvtxExportError

    with pytest.raises(EvtxExportError, match=message):
        export(tmp_path, records)
    assert not (tmp_path / "output.evtx").exists()
    assert sorted(p.name for p in tmp_path.iterdir()) == ["source.xml"]


@pytest.mark.parametrize(
    "xml",
    [
        "<Events>" + event(1),
        '<!DOCTYPE Events [<!ENTITY e "attack">]><Events>' + event(1) + "</Events>",
        "<Events><Unexpected/></Events>",
        "<Events>unexpected text</Events>",
        "<Events><!--hidden--></Events>",
        "<Events>"
        + event(1, payload='<EventData>mixed<Data Name="value">text</Data></EventData>')
        + "</Events>",
        "<Events>"
        + event(1, payload='<EventData><p:Data xmlns:p="urn:other">text</p:Data></EventData>')
        + "</Events>",
        "<Events>"
        + event(
            1, payload="<EventData>" + "<Nested>" * 40 + "text" + "</Nested>" * 40 + "</EventData>"
        )
        + "</Events>",
        "<Events>"
        + event(1, payload="<EventData>" + "<Data/>" * 1100 + "</EventData>")
        + "</Events>",
        '<Events><Event xmlns="' + "x" * 200_000 + '"/></Events>',
    ],
)
def test_malformed_or_unsupported_xml_is_rejected(tmp_path, xml):
    from evidenceforge.evtx_export import EvtxExportError, export_evtx

    source = tmp_path / "source.xml"
    source.write_text(xml)
    with pytest.raises(EvtxExportError):
        export_evtx(source, tmp_path / "output.evtx")
    assert not (tmp_path / "output.evtx").exists()


def test_output_cannot_replace_input_or_existing_file(tmp_path):
    from evidenceforge.evtx_export import export_evtx

    source, output, _ = export(tmp_path, [event(1)])
    original = source.read_bytes()
    output_bytes = output.read_bytes()
    with pytest.raises(FileExistsError):
        export_evtx(source, source)
    with pytest.raises(FileExistsError):
        export_evtx(source, output)
    assert source.read_bytes() == original and output.read_bytes() == output_bytes


def test_empty_log_is_valid_empty_binary(tmp_path):
    _, output, receipt = export(tmp_path, [])
    _, chunks = headers(output)
    assert receipt.records == 0 and receipt.chunks == 0 and chunks == []


def test_filetime_timezone_offset_is_exact(tmp_path):
    _, output, _ = export(tmp_path, [event(1, time="2026-01-02T04:04:05.1234567+01:00")])
    _, chunks = headers(output)
    original = struct.unpack_from("<Q", chunks[0], 528)[0]
    another = tmp_path / "utc"
    another.mkdir()
    _, output, _ = export(another, [event(1)])
    _, chunks = headers(output)
    assert struct.unpack_from("<Q", chunks[0], 528)[0] == original


def facts(element: ET.Element) -> tuple:
    return (
        element.tag,
        tuple(element.attrib.items()),
        element.text if not len(element) else None,
        tuple(facts(child) for child in element),
    )


def test_independent_decoder_preserves_namespaces_attributes_and_values(tmp_path):

    payload = """<UserData><LogFileCleared xmlns="http://manifests.microsoft.com/win/2004/08/windows/eventlog"><SubjectUserName>Zoë &amp; 李 😀</SubjectUserName><SubjectUserSid>S-1-5-18</SubjectUserSid></LogFileCleared></UserData>"""
    records = [event(1), event(3, payload=payload).replace("<EventID>4624", "<EventID>1102")]
    _, output, _ = export(tmp_path, records)
    with Evtx(str(output)) as log:
        decoded = list(log.records())
        assert len(decoded) == len(records)
        for wanted, actual in zip(records, decoded, strict=True):
            assert facts(ET.fromstring(actual.xml())) == facts(ET.fromstring(wanted))


WINDOWS_CASES = json.loads(
    (Path(__file__).parents[1] / "fixtures/record_validation/windows_variants.json").read_text()
)


@pytest.mark.parametrize(
    "case", WINDOWS_CASES, ids=lambda case: case["format"] + ":" + case["variant"]
)
def test_every_production_windows_variant_roundtrips_through_independent_reader(tmp_path, case):
    from tests.support.native_records import render_record

    raw = render_record(tmp_path, case)
    _, output, receipt = export(tmp_path, [raw])
    assert receipt.records == 1
    with Evtx(str(output)) as log:
        decoded = list(log.records())
        assert len(decoded) == 1
        assert decoded[0].record_num() == int(case["fields"]["EventRecordID"])
        assert facts(ET.fromstring(decoded[0].xml())) == facts(ET.fromstring(raw))


def test_cli_emits_receipt_and_refuses_existing_destination(tmp_path):
    from typer.testing import CliRunner

    from evidenceforge.cli.commands import app

    source = tmp_path / "source.xml"
    output = tmp_path / "output.evtx"
    source.write_text("<Events>" + event(11) + "</Events>")
    result = CliRunner().invoke(app, ["export-evtx", str(source), str(output)])
    assert result.exit_code == 0, result.output
    assert json.loads(result.stdout)["records"] == 1
    assert output.read_bytes().startswith(b"ElfFile\0")
    rejected = CliRunner().invoke(app, ["export-evtx", str(source), str(output)])
    assert rejected.exit_code == 1 and "EVTX export failed" in rejected.stderr


def test_late_xml_failure_does_not_publish_already_written_chunks(tmp_path):
    from evidenceforge.evtx_export import EvtxExportError, export_evtx

    payload = '<EventData><Data Name="Message">' + "x" * 2500 + "</Data></EventData>"
    source = tmp_path / "late.xml"
    source.write_text(
        "<Events>" + "".join(event(i + 1, payload=payload) for i in range(25)) + "<Event>"
    )
    with pytest.raises(EvtxExportError):
        export_evtx(source, tmp_path / "output.evtx")
    assert sorted(path.name for path in tmp_path.iterdir()) == ["late.xml"]


@pytest.mark.parametrize("namespace", ["urn:foreign", ""])
@pytest.mark.parametrize("name", ["System", "EventRecordID", "TimeCreated", "Computer", "Channel"])
def test_foreign_system_metadata_namespace_is_rejected(tmp_path, name, namespace):
    from evidenceforge.evtx_export import EvtxExportError

    raw = event(11).replace(f"<{name}", f'<{name} xmlns="{namespace}"', 1)
    with pytest.raises(EvtxExportError, match="namespace"):
        export(tmp_path, [raw])
    assert sorted(path.name for path in tmp_path.iterdir()) == ["source.xml"]


@pytest.mark.parametrize("name", ["System", "EventRecordID", "TimeCreated", "Computer", "Channel"])
def test_explicit_windows_metadata_namespace_preserves_the_event(tmp_path, name):
    raw = event(11).replace(f"<{name}", f'<{name} xmlns="{NS}"', 1)
    _, output, receipt = export(tmp_path, [raw])
    assert receipt.records == 1
    with Evtx(str(output)) as log:
        decoded = list(log.records())
        assert len(decoded) == 1
        assert facts(ET.fromstring(decoded[0].xml())) == facts(ET.fromstring(raw))

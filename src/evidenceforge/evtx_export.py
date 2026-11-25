"""Bounded, deterministic serialization of finalized Windows XML into binary EVTX.

The BinXML framing adapts weave's MIT-licensed writer; see THIRD_PARTY_NOTICES.md.
No synthetic facts, timestamps, identities or provider defaults are introduced.
"""

from __future__ import annotations

import hashlib
import os
import re
import struct
import tempfile
import zlib
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta, timezone
from pathlib import Path
from typing import BinaryIO
from xml.parsers import expat

from pydantic import BaseModel, ConfigDict

from evidenceforge.models.exceptions import EvidenceForgeError

FILE_HEADER_SIZE = 4096
CHUNK_SIZE = 65536
CHUNK_HEADER_SIZE = 512
MAX_EVENT_XML_BYTES = 128 * 1024
MAX_NODES = 1024
MAX_DEPTH = 32
EVENT_NAMESPACE = "http://schemas.microsoft.com/win/2004/08/events/event"
_TIME = re.compile(r"(\d{4}-\d{2}-\d{2})T(\d{2}:\d{2}:\d{2})(?:\.(\d{1,7}))?(Z|[+-]\d{2}:\d{2})")
_EPOCH = datetime(1601, 1, 1, tzinfo=UTC)


class EvtxExportError(EvidenceForgeError):
    """Unsupported source facts or an invalid/bounded XML or EVTX representation."""


class EvtxExportReceipt(BaseModel):
    """Content identities of the input and completed EVTX output."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)
    source_sha256: str
    output_sha256: str
    records: int
    chunks: int
    computer: str | None
    channel: str | None
    header_time_policy: str = "copy-system-time"


@dataclass(slots=True)
class _Node:
    name: str
    attrs: dict[str, str]
    children: list[_Node] = field(default_factory=list)
    text: list[str] = field(default_factory=list)


def _only(parent: _Node, name: str) -> _Node:
    """Select metadata from an already-verified Windows Event/System parent."""
    found = [child for child in parent.children if child.name == name]
    if len(found) != 1:
        raise EvtxExportError(f"Expected exactly one {name} in {parent.name}")
    node = found[0]
    if node.attrs.get("xmlns", EVENT_NAMESPACE) != EVENT_NAMESPACE:
        raise EvtxExportError(f"Unexpected {name} namespace")
    return node


def _leaf(node: _Node) -> str:
    if node.children:
        raise EvtxExportError(f"Expected scalar {node.name}")
    return "".join(node.text)


def _filetime(text: str) -> int:
    match = _TIME.fullmatch(text)
    if match is None:
        raise EvtxExportError(
            "Expected timezone-aware ISO timestamp with at most seven fractional digits"
        )
    date, clock, fraction, zone = match.groups()
    try:
        offset = timedelta()
        if zone != "Z":
            hours, minutes = int(zone[1:3]), int(zone[4:6])
            if hours > 23 or minutes > 59:
                raise ValueError("Invalid timezone offset")
            offset = timedelta(hours=hours, minutes=minutes)
            if zone[0] == "-":
                offset = -offset
        value = datetime.fromisoformat(f"{date}T{clock}").replace(tzinfo=timezone(offset))
        delta = value.astimezone(UTC) - _EPOCH
    except (ValueError, OverflowError) as exc:
        raise EvtxExportError("Invalid Windows event timestamp") from exc
    ticks = (delta.days * 86400 + delta.seconds) * 10_000_000 + int((fraction or "").ljust(7, "0"))
    if not 0 <= ticks <= 0xFFFFFFFFFFFFFFFF:
        raise EvtxExportError("Windows event timestamp is outside FILETIME range")
    return ticks


class _XmlEvents:
    """SAX parser retaining at most one explicitly bounded finalized event."""

    def __init__(self, accept: Callable[[_Node], None]) -> None:
        self.accept = accept
        self.stack: list[_Node] = []
        self.root_seen = False
        self.root_closed = False
        self.nodes = 0
        self.event_start = 0
        self.bytes_read = 0
        self.parser = expat.ParserCreate(encoding="utf-8")
        self.parser.StartElementHandler = self._start
        self.parser.EndElementHandler = self._end
        self.parser.CharacterDataHandler = self._text
        self.parser.StartDoctypeDeclHandler = self._unsupported
        self.parser.EntityDeclHandler = self._unsupported
        self.parser.ExternalEntityRefHandler = self._unsupported
        self.parser.ProcessingInstructionHandler = self._unsupported
        self.parser.CommentHandler = self._unsupported
        self.parser.XmlDeclHandler = self._declaration

    @staticmethod
    def _unsupported(*args: object) -> None:
        raise EvtxExportError("DTD, entities, comments and processing instructions are unsupported")

    @staticmethod
    def _declaration(version: str, encoding: str | None, standalone: int) -> None:
        if version != "1.0" or (encoding and encoding.lower() not in {"utf-8", "utf8"}):
            raise EvtxExportError("Only XML 1.0 UTF-8 input is supported")

    def _start(self, name: str, attrs: dict[str, str]) -> None:
        if not self.root_seen:
            if name != "Events" or attrs:
                raise EvtxExportError("Expected unqualified Events XML container")
            self.root_seen = True
            return
        if not self.stack:
            if self.root_closed or name != "Event" or attrs.get("xmlns") != EVENT_NAMESPACE:
                raise EvtxExportError("Expected Windows Event with its default namespace")
            self.event_start = self.parser.CurrentByteIndex
            self.nodes = 0
        self.nodes += 1
        if self.nodes > MAX_NODES or len(self.stack) >= MAX_DEPTH or len(attrs) > 128:
            raise EvtxExportError("XML event node/depth/attribute limit exceeded")
        # EvidenceForge uses unprefixed elements and default namespace declarations.
        # Reject unbound/prefixed names rather than quietly changing their meaning.
        if ":" in name or any(":" in key and not key.startswith("xmlns:") for key in attrs):
            raise EvtxExportError("Prefixed XML names are unsupported")
        node = _Node(name, attrs)
        if self.stack:
            self.stack[-1].children.append(node)
        self.stack.append(node)

    def _end(self, name: str) -> None:
        if not self.stack:
            if name != "Events":
                raise EvtxExportError("Unexpected XML container end")
            self.root_closed = True
            return
        node = self.stack.pop()
        if node.children and any(part.strip() for part in node.text):
            raise EvtxExportError("Mixed XML content is unsupported")
        if self.parser.CurrentByteIndex - self.event_start > MAX_EVENT_XML_BYTES:
            raise EvtxExportError("XML event byte limit exceeded")
        if not self.stack:
            self.accept(node)

    def _text(self, text: str) -> None:
        if self.stack:
            self.stack[-1].text.append(text)
        elif text.strip():
            raise EvtxExportError("Unexpected text outside Event")

    def feed(self, data: bytes, *, final: bool = False) -> None:
        self.bytes_read += len(data)
        try:
            self.parser.Parse(data, final)
        except expat.ExpatError as exc:
            raise EvtxExportError(
                f"Malformed XML at line {exc.lineno}, column {exc.offset}"
            ) from exc
        # Also bound incomplete large attribute/name tokens buffered inside Expat.
        if self.bytes_read - self.parser.CurrentByteIndex > MAX_EVENT_XML_BYTES:
            raise EvtxExportError("XML token byte limit exceeded")
        if self.stack and self.bytes_read - self.event_start > MAX_EVENT_XML_BYTES:
            raise EvtxExportError("XML event byte limit exceeded")
        if final and (not self.root_closed or self.stack):
            raise EvtxExportError("Incomplete Events container")


class _BinXml:
    """Self-contained BinXML templates with UTF-16 substitutions and inline names."""

    def __init__(self, offset: int, ordinal: int) -> None:
        self.offset = offset
        self.ordinal = ordinal
        self.data = bytearray()
        self.values: list[bytes] = []

    def encode(self, event: _Node) -> bytes:
        self.data += b"\x0f\x01\x01\x00\x0c\x01"
        self.data += struct.pack("<II", self.ordinal, self.offset + 14)
        template_start = len(self.data)
        self.data += bytes(24)
        body_start = len(self.data)
        self._element(event)
        self.data += b"\x00"
        body = self.data[body_start:]
        self.data[template_start:body_start] = (
            struct.pack("<I", 0) + hashlib.sha256(body).digest()[:16] + struct.pack("<I", len(body))
        )
        self.data += struct.pack("<I", len(self.values))
        for value in self.values:
            self.data += struct.pack("<HBB", len(value), 1, 0)
        for value in self.values:
            self.data += value
        return bytes(self.data)

    def _name(self, name: str) -> None:
        encoded = name.encode("utf-16le")
        units = len(encoded) // 2
        if units > 0xFFFF:
            raise EvtxExportError("BinXML name length limit exceeded")
        self.data += struct.pack("<I", self.offset + len(self.data) + 4)
        name_hash = 0
        for index in range(0, len(encoded), 2):
            name_hash = (
                name_hash * 37 + int.from_bytes(encoded[index : index + 2], "little")
            ) & 0xFFFF
        self.data += struct.pack("<IHH", 0, name_hash, units) + encoded + b"\0\0"

    def _value(self, text: str) -> None:
        encoded = text.encode("utf-16le")
        if len(encoded) > 0xFFFF or len(self.values) >= 0xFFFF:
            raise EvtxExportError("BinXML substitution limit exceeded")
        self.data += b"\x0d" + struct.pack("<HB", len(self.values), 1)
        self.values.append(encoded)

    def _element(self, node: _Node) -> None:
        start = len(self.data)
        self.data += bytes([0x41 if node.attrs else 0x01]) + struct.pack("<H", 0xFFFF) + bytes(4)
        self._name(node.name)
        if node.attrs:
            attribute_size = len(self.data)
            self.data += bytes(4)
            for index, (key, value) in enumerate(node.attrs.items()):
                self.data.append(0x06 if index == len(node.attrs) - 1 else 0x46)
                self._name(key)
                self._value(value)
            struct.pack_into("<I", self.data, attribute_size, len(self.data) - attribute_size - 4)
        if not node.children and not node.text:
            self.data.append(0x03)
        else:
            self.data.append(0x02)
            if node.children:
                for child in node.children:
                    self._element(child)
            else:
                self._value("".join(node.text))
            self.data.append(0x04)
        struct.pack_into("<I", self.data, start + 3, len(self.data) - start - 7)


def _file_header(chunks: int, next_record: int) -> bytes:
    header = bytearray(FILE_HEADER_SIZE)
    header[:8] = b"ElfFile\0"
    struct.pack_into(
        "<QQQIHHHH", header, 8, 0, max(chunks - 1, 0), next_record, 128, 1, 3, 4096, chunks
    )
    struct.pack_into("<I", header, 124, zlib.crc32(header[:120]))
    return bytes(header)


class _EvtxWriter:
    """One source/epoch, one retained chunk, and monotonically counted positions."""

    def __init__(self, output: BinaryIO) -> None:
        self.output = output
        self.output.write(bytes(FILE_HEADER_SIZE))
        self.chunk = bytearray(CHUNK_SIZE)
        self.cursor = CHUNK_HEADER_SIZE
        self.records = 0
        self.chunks = 0
        self.first_position = 0
        self.first_id = 0
        self.last_id = 0
        self.last_offset = 0
        self.identity: tuple[str, str] | None = None

    def accept(self, event: _Node) -> None:
        system = _only(event, "System")
        record_text = _leaf(_only(system, "EventRecordID"))
        if len(record_text) > 20 or not re.fullmatch(r"[0-9]+", record_text):
            raise EvtxExportError("Expected positive decimal record ID")
        record_id = int(record_text)
        if not 1 <= record_id < 0xFFFFFFFFFFFFFFFF:
            raise EvtxExportError("Windows record ID is outside supported range")
        if record_id <= self.last_id:
            raise EvtxExportError(
                "Record IDs must be increasing; split log-clear epochs into separate exports"
            )
        identity = (_leaf(_only(system, "Computer")), _leaf(_only(system, "Channel")))
        if not all(identity) or (self.identity is not None and identity != self.identity):
            raise EvtxExportError("Expected a single nonempty host/channel per export")
        time_node = _only(system, "TimeCreated")
        if "SystemTime" not in time_node.attrs:
            raise EvtxExportError("Missing TimeCreated SystemTime timestamp")
        ticks = _filetime(time_node.attrs["SystemTime"])
        ordinal = self.records + 1
        if ordinal > 0xFFFFFFFF:
            raise EvtxExportError("EVTX record ordinal limit exceeded")
        record = self._record(event, record_id, ticks, ordinal)
        if self.cursor + len(record) > CHUNK_SIZE:
            self._flush()
            record = self._record(event, record_id, ticks, ordinal)
        if self.cursor == CHUNK_HEADER_SIZE:
            self.first_position, self.first_id = ordinal, record_id
        self.last_offset = self.cursor
        self.chunk[self.cursor : self.cursor + len(record)] = record
        self.cursor += len(record)
        self.records = ordinal
        self.last_id = record_id
        self.identity = identity

    def _record(self, event: _Node, record_id: int, ticks: int, ordinal: int) -> bytes:
        payload = _BinXml(self.cursor + 24, ordinal).encode(event)
        size = (24 + len(payload) + 4 + 7) // 8 * 8
        if size > CHUNK_SIZE - CHUNK_HEADER_SIZE:
            raise EvtxExportError("EVTX record size limit exceeded")
        record = bytearray(size)
        record[:4] = b"\x2a\x2a\0\0"
        struct.pack_into("<IQQ", record, 4, size, record_id, ticks)
        record[24 : 24 + len(payload)] = payload
        struct.pack_into("<I", record, size - 4, size)
        return bytes(record)

    def _flush(self) -> None:
        if self.cursor == CHUNK_HEADER_SIZE:
            return
        if self.chunks == 0xFFFF:
            raise EvtxExportError("EVTX file chunk limit exceeded")
        self.chunk[:8] = b"ElfChnk\0"
        struct.pack_into(
            "<QQQQIII",
            self.chunk,
            8,
            self.first_position,
            self.records,
            self.first_id,
            self.last_id,
            128,
            self.last_offset,
            self.cursor,
        )
        struct.pack_into(
            "<I", self.chunk, 52, zlib.crc32(self.chunk[CHUNK_HEADER_SIZE : self.cursor])
        )
        crc = zlib.crc32(self.chunk[128:CHUNK_HEADER_SIZE], zlib.crc32(self.chunk[:120]))
        struct.pack_into("<I", self.chunk, 124, crc)
        self.output.write(self.chunk)
        self.chunks += 1
        self.chunk = bytearray(CHUNK_SIZE)
        self.cursor = CHUNK_HEADER_SIZE

    def finish(self) -> None:
        self._flush()
        self.output.seek(0)
        self.output.write(_file_header(self.chunks, self.last_id + 1))


def export_evtx(source: Path, destination: Path) -> EvtxExportReceipt:
    """Export completed UTF-8 Events XML; refuse replacement and partial publication.

    Source XML is immutable input. Header times copy SystemTime exactly at 100 ns
    precision; native IDs and source values are preserved. Resets, mixed sources,
    DTDs and unsupported XML shapes fail before the final path is published.
    """
    if destination.exists() or destination.is_symlink():
        raise FileExistsError(destination)
    with source.open("rb") as input_file:
        before = os.fstat(input_file.fileno())
        source_hash = hashlib.sha256()
        temporary: Path | None = None
        try:
            with tempfile.NamedTemporaryFile(
                mode="w+b", prefix=".evtx-", suffix=".tmp", dir=destination.parent, delete=False
            ) as output:
                temporary = Path(output.name)
                writer = _EvtxWriter(output)
                parser = _XmlEvents(writer.accept)
                while data := input_file.read(8192):
                    source_hash.update(data)
                    parser.feed(data)
                parser.feed(b"", final=True)
                after = os.fstat(input_file.fileno())
                if (before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (
                    after.st_size,
                    after.st_mtime_ns,
                    after.st_ctime_ns,
                ):
                    raise EvtxExportError("Source XML changed during export")
                writer.finish()
                output.flush()
                os.fsync(output.fileno())
                output.seek(0)
                output_hash = hashlib.sha256()
                while data := output.read(65536):
                    output_hash.update(data)
                receipt = EvtxExportReceipt(
                    source_sha256=source_hash.hexdigest(),
                    output_sha256=output_hash.hexdigest(),
                    records=writer.records,
                    chunks=writer.chunks,
                    computer=writer.identity[0] if writer.identity else None,
                    channel=writer.identity[1] if writer.identity else None,
                )
            # Hard-link publication is atomic and cannot overwrite a racing destination.
            os.link(temporary, destination)
            return receipt
        finally:
            if temporary is not None:
                temporary.unlink(missing_ok=True)

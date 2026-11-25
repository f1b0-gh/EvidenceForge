# Binary EVTX export

`eforge export-evtx SOURCE.xml DESTINATION.evtx` serializes finalized Windows
Security or Sysmon XML events into a binary Windows Event Log file. Generate the
normal EvidenceForge XML first, then export each host/channel separately:

```sh
eforge export-evtx generated/WS-01.example/windows_event_security.xml Security.evtx
eforge export-evtx generated/WS-01.example/windows_event_sysmon.xml Sysmon.evtx
```

The destination must not exist. The command prints a JSON receipt containing
the original XML and EVTX SHA-256 hashes, record and chunk counts, computer,
channel, and header-time policy. Keep this receipt with the source corpus and
decoder identity when passing EVTX through a separate binary decoder. A decoded
JSON record alone does not establish which binary file produced it.

The writer emits EVTX file/chunk headers, CRC32 checksums, binary record frames
and BinXML templates. It preserves event versions, provider metadata, default
XML namespace declarations, attributes, leaf values, payload order, and native
EventRecordID values. It supports both EventData and namespaced UserData,
including Security event 1102. XML indentation between elements is omitted;
normal XML entity and newline decoding applies. The input file is retained.

The record-header timestamp copies each event's SystemTime using integer
FILETIME arithmetic with up to seven fractional digits (100 ns). The original
SystemTime text remains in the payload, including its timezone spelling. This
is an explicit serialization policy: the XML input does not supply a second,
independent record-header clock. No fields or defaults are invented.

Native ID gaps are preserved. Physical record positions in chunk headers are
separate contiguous counters. IDs must increase within an export; a reset after
a log clear requires separate input files for each log epoch. Mixed hosts or
channels, duplicate/decreasing IDs and unsupported source shapes are rejected.

Input must be a complete UTF-8 XML 1.0 document with an unqualified `Events`
container and Windows `Event` children using the standard default namespace.
The exporter rejects DTDs/entities, comments, processing instructions, prefixed
element/attribute names and mixed text/element content. Default namespace
changes within UserData are supported. This is a serializer for EvidenceForge's
finalized event profile, not a general XML or forensic recovery converter.

Memory retains one XML event and one 64 KiB output chunk. Limits are 128 KiB per
input event/token, 1,024 nodes, depth 32, 128 attributes per element, and one
EVTX chunk per encoded record. An output file is limited to 65,535 chunks. A
failed export removes its temporary file and never publishes partial output.
Publication uses an atomic hard link on the destination filesystem and refuses
replacement, including a racing destination. The command does not create
missing destination directories.

The development extra includes the independent `python-evtx` reader. Focused
tests compare every Windows variant's production-rendered XML with independently
decoded EVTX, and exercise exact timestamps, native ID gaps, multi-chunk output,
malformed-input limits, deterministic bytes and CLI refusal behavior:

```sh
uv sync --locked --extra dev
uv run pytest tests/unit/test_evtx_export.py
```

These checks establish parser interoperability and preservation of the tested
events. Windows Event Viewer/provider-message rendering has not been certified.

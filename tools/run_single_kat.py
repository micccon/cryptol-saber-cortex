#!/usr/bin/env python3
from __future__ import annotations

import argparse
import re
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_EXPANDED = ROOT / "expanded_kats.txt"
DEFAULT_CRYPTOLPATH = "cryptol:SHA3:SHA3/Instantiations"

FIELD_RE = re.compile(r"^([A-Za-z_]+)\s*=\s*(.*)$")
BYTE_RE = re.compile(r"0x([0-9a-fA-F]{2})")
BOOL_RE = re.compile(r"\b(True|False)\b")


@dataclass
class KatEntry:
    count: int
    seed: str = ""
    seedAInput: str = ""
    seedS: str = ""
    z: str = ""
    mRaw: str = ""
    pk: str = ""
    sk: str = ""
    ct: str = ""
    ss: str = ""


def parse_expanded_file(path: Path) -> list[KatEntry]:
    text = path.read_text()
    blocks = [block.strip() for block in re.split(r"\n\s*\n", text) if "count =" in block]
    entries: list[KatEntry] = []

    for block in blocks:
        fields: dict[str, str] = {}
        for line in block.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            match = FIELD_RE.match(line)
            if match:
                fields[match.group(1)] = match.group(2).strip()

        entries.append(
            KatEntry(
                count=int(fields["count"]),
                seed=fields.get("seed", ""),
                seedAInput=fields.get("seedAInput", ""),
                seedS=fields.get("seedS", ""),
                z=fields.get("z", ""),
                mRaw=fields.get("mRaw", ""),
                pk=fields.get("pk", ""),
                sk=fields.get("sk", ""),
                ct=fields.get("ct", ""),
                ss=fields.get("ss", ""),
            )
        )

    return entries


def hex_to_cryptol_bytes(hex_string: str) -> str:
    bytes_ = [f"0x{hex_string[i:i+2].lower()}" for i in range(0, len(hex_string), 2)]
    return "[" + ", ".join(bytes_) + "]"


def build_module(entry: KatEntry) -> str:
    return f"""module TempSingleKAT where
import SaberKEM
import SaberTypes
import SaberConstants

mRaw_kat : ByteString keyBytes
mRaw_kat = {hex_to_cryptol_bytes(entry.mRaw)}

expected_pk : ByteString publicKeyBytes
expected_pk = {hex_to_cryptol_bytes(entry.pk)}

expected_sk : ByteString secretKeyBytes
expected_sk = {hex_to_cryptol_bytes(entry.sk)}

expected_ct : ByteString bytesCCADec
expected_ct = {hex_to_cryptol_bytes(entry.ct)}

expected_ss : ByteString keyBytes
expected_ss = {hex_to_cryptol_bytes(entry.ss)}

actual_ss : ByteString keyBytes
actual_ss = ss
  where
    (ss, _) = KEM_EncapsDet mRaw_kat expected_pk

actual_ct : ByteString bytesCCADec
actual_ct = ct
  where
    (_, ct) = KEM_EncapsDet mRaw_kat expected_pk

decaps_ss : ByteString keyBytes
decaps_ss = KEM_Decaps expected_ct expected_sk

ct_match : Bit
ct_match = actual_ct == expected_ct

ss_match : Bit
ss_match = actual_ss == expected_ss

decaps_match : Bit
decaps_match = decaps_ss == expected_ss
"""


def run_eval(module_text: str, cryptolpath: str, expr: str) -> str:
    with tempfile.TemporaryDirectory() as tmpdir:
        module_path = Path(tmpdir) / "TempSingleKAT.cry"
        module_path.write_text(module_text)
        proc = subprocess.run(
            ["env", f"CRYPTOLPATH={cryptolpath}", "cryptol", str(module_path)],
            cwd=ROOT,
            input=f":eval {expr}\n",
            text=True,
            capture_output=True,
        )
        return proc.stdout + proc.stderr


def extract_hex(output: str) -> str | None:
    if "panic" in output.lower() or "Uncaught exception" in output:
        return None
    matches = BYTE_RE.findall(output)
    if not matches:
        return None
    return "".join(matches).upper()


def extract_bool(output: str) -> bool | None:
    if "panic" in output.lower() or "Uncaught exception" in output:
        return None
    matches = BOOL_RE.findall(output)
    if not matches:
        return None
    return matches[-1] == "True"


def render_report(entry: KatEntry, module_text: str, cryptolpath: str) -> str:
    lines: list[str] = [f"count = {entry.count}"]

    checks = [
        ("ct_match", "actual_ct", entry.ct),
        ("ss_match", "actual_ss", entry.ss),
        ("decaps_match", "decaps_ss", entry.ss),
    ]

    for check_name, value_name, expected_hex in checks:
        check_output = run_eval(module_text, cryptolpath, check_name)
        check_value = extract_bool(check_output)
        lines.append(f"{check_name} = {check_value if check_value is not None else 'ERROR'}")

        value_output = run_eval(module_text, cryptolpath, value_name)
        actual_hex = extract_hex(value_output)
        if actual_hex is None:
            lines.append(f"{value_name}_actual = <unable to extract>")
            lines.append(value_output.strip())
        else:
            lines.append(f"{value_name}_actual = {actual_hex}")
        lines.append(f"{value_name}_expected = {expected_hex}")
        lines.append("")

    return "\n".join(lines).rstrip() + "\n"


def main(argv: Iterable[str]) -> int:
    parser = argparse.ArgumentParser(description="Run a single expanded Saber KAT through Cryptol.")
    parser.add_argument("--expanded", type=Path, default=DEFAULT_EXPANDED)
    parser.add_argument("--count", type=int, default=0)
    parser.add_argument("--cryptolpath", default=DEFAULT_CRYPTOLPATH)
    parser.add_argument("--out", type=Path, help="Optional report output file")
    args = parser.parse_args(list(argv))

    entries = parse_expanded_file(args.expanded)
    by_count = {entry.count: entry for entry in entries}
    entry = by_count.get(args.count)
    if entry is None:
        raise SystemExit(f"count {args.count} not found in {args.expanded}")

    module_text = build_module(entry)
    report = render_report(entry, module_text, args.cryptolpath)

    if args.out is not None:
        args.out.write_text(report)
    else:
        print(report, end="")

    return 0


if __name__ == "__main__":
    raise SystemExit(main(__import__("sys").argv[1:]))

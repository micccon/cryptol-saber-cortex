#!/usr/bin/env python3
from __future__ import annotations

import argparse
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_REQ = ROOT / "PQCkemKAT_2304.req"
DEFAULT_RSP = ROOT / "PQCkemKAT_2304.rsp"

SEED_A_LEN = 32
SEED_S_LEN = 32
Z_LEN = 32
MRAW_LEN = 32


@dataclass
class KatEntry:
    count: int
    seed: str
    pk: str = ""
    sk: str = ""
    ct: str = ""
    ss: str = ""


FIELD_RE = re.compile(r"^([A-Za-z_]+)\s*=\s*(.*)$")


def parse_kat_file(path: Path) -> list[KatEntry]:
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
                pk=fields.get("pk", ""),
                sk=fields.get("sk", ""),
                ct=fields.get("ct", ""),
                ss=fields.get("ss", ""),
            )
        )

    return entries


class AES256CtrDrbg:
    def __init__(self, entropy_input: bytes, personalization_string: bytes | None = None):
        if len(entropy_input) != 48:
            raise ValueError(f"entropy_input must be 48 bytes, got {len(entropy_input)}")
        if personalization_string is not None and len(personalization_string) != 48:
            raise ValueError("personalization_string must be 48 bytes")

        seed_material = bytearray(entropy_input)
        if personalization_string is not None:
            for i, b in enumerate(personalization_string):
                seed_material[i] ^= b

        self.key = bytes(32)
        self.v = bytes(16)
        self.reseed_counter = 0
        self._update(bytes(seed_material))
        self.reseed_counter = 1

    @staticmethod
    def _inc(counter: bytes) -> bytes:
        value = bytearray(counter)
        for i in range(15, -1, -1):
            if value[i] == 0xFF:
                value[i] = 0x00
            else:
                value[i] += 1
                break
        return bytes(value)

    @staticmethod
    def _aes256_ecb_block(key: bytes, block: bytes) -> bytes:
        cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
        encryptor = cipher.encryptor()
        return encryptor.update(block) + encryptor.finalize()

    def _update(self, provided_data: bytes | None) -> None:
        temp = bytearray()
        v = self.v

        for _ in range(3):
            v = self._inc(v)
            temp.extend(self._aes256_ecb_block(self.key, v))

        if provided_data is not None:
            if len(provided_data) != 48:
                raise ValueError("provided_data must be 48 bytes")
            temp = bytearray(a ^ b for a, b in zip(temp, provided_data))

        self.key = bytes(temp[:32])
        self.v = bytes(temp[32:48])

    def randombytes(self, xlen: int) -> bytes:
        out = bytearray()

        while xlen > 0:
            self.v = self._inc(self.v)
            block = self._aes256_ecb_block(self.key, self.v)
            take = min(16, xlen)
            out.extend(block[:take])
            xlen -= take

        self._update(None)
        self.reseed_counter += 1
        return bytes(out)


def expand_req_seed(seed_hex: str) -> dict[str, str]:
    seed = bytes.fromhex(seed_hex)
    drbg = AES256CtrDrbg(seed)

    # Mirror repeated randombytes(32) calls rather than slicing one long call.
    seed_a_input = drbg.randombytes(SEED_A_LEN)
    seed_s = drbg.randombytes(SEED_S_LEN)
    z = drbg.randombytes(Z_LEN)
    m_raw = drbg.randombytes(MRAW_LEN)

    return {
        "seedAInput": seed_a_input.hex().upper(),
        "seedS": seed_s.hex().upper(),
        "z": z.hex().upper(),
        "mRaw": m_raw.hex().upper(),
    }


def parse_counts_arg(raw: str | None, total_count: int) -> list[int]:
    if raw is None:
        return list(range(total_count))

    counts: list[int] = []
    for chunk in raw.split(","):
        chunk = chunk.strip()
        if not chunk:
            continue
        if "-" in chunk:
            start_s, end_s = chunk.split("-", 1)
            counts.extend(range(int(start_s), int(end_s) + 1))
        else:
            counts.append(int(chunk))
    return counts


def render_entry(req_entry: KatEntry, rsp_entry: KatEntry | None) -> str:
    expanded = expand_req_seed(req_entry.seed)
    lines = [
        f"count = {req_entry.count}",
        f"seed = {req_entry.seed.upper()}",
        f"seedAInput = {expanded['seedAInput']}",
        f"seedS = {expanded['seedS']}",
        f"z = {expanded['z']}",
        f"mRaw = {expanded['mRaw']}",
    ]

    if rsp_entry is not None:
        if rsp_entry.pk:
            lines.append(f"pk = {rsp_entry.pk.upper()}")
        if rsp_entry.sk:
            lines.append(f"sk = {rsp_entry.sk.upper()}")
        if rsp_entry.ct:
            lines.append(f"ct = {rsp_entry.ct.upper()}")
        if rsp_entry.ss:
            lines.append(f"ss = {rsp_entry.ss.upper()}")

    return "\n".join(lines)


def main(argv: Iterable[str]) -> int:
    parser = argparse.ArgumentParser(
        description="Expand Saber KAT seeds using the AES-256 CTR DRBG from rng.c."
    )
    parser.add_argument("--req", type=Path, default=DEFAULT_REQ, help="Path to the .req file")
    parser.add_argument("--rsp", type=Path, default=DEFAULT_RSP, help="Path to the .rsp file")
    parser.add_argument("--counts", help="Comma-separated counts or ranges, e.g. 0,1,5-7")
    parser.add_argument(
        "--no-rsp",
        action="store_true",
        help="Only emit expanded DRBG outputs, not pk/sk/ct/ss fields from the .rsp file",
    )
    parser.add_argument("--out", type=Path, help="Optional output file. Defaults to stdout.")
    args = parser.parse_args(list(argv))

    req_entries = parse_kat_file(args.req)
    rsp_entries = parse_kat_file(args.rsp) if not args.no_rsp else []
    rsp_by_count = {entry.count: entry for entry in rsp_entries}
    req_by_count = {entry.count: entry for entry in req_entries}

    selected_counts = parse_counts_arg(args.counts, len(req_entries))

    rendered: list[str] = []
    for count in selected_counts:
        req_entry = req_by_count.get(count)
        if req_entry is None:
            raise SystemExit(f"count {count} missing from {args.req}")
        rendered.append(render_entry(req_entry, None if args.no_rsp else rsp_by_count.get(count)))

    output = "\n\n".join(rendered) + "\n"
    if args.out is not None:
        args.out.write_text(output)
    else:
        print(output, end="")

    return 0


if __name__ == "__main__":
    raise SystemExit(main(__import__("sys").argv[1:]))

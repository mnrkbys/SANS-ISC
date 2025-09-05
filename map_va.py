#!/usr/bin/env python3
#
# Example:
#   yara -s rules.yar sample.exe | python map_va.py
#

import sys
import re
import os
import pefile
from decimal import Decimal

HEADER_RE = re.compile(r'^([^\s:]+)\s+(.+)$')      # "rule file"
MATCH_RE  = re.compile(r'^(0x[0-9A-Fa-f]+|\d+):\s*(\$\S+):\s*(.*)$')  # "0xOFF:$id: bytes"

pe_cache = {}  # file_path -> pefile.PE

def print_table(rows, headers):
    '''
    Display a nice output for formatted columns
    '''
    n = len(headers)
    def to_str(x):
        if x is None: return ""
        return f"{x:g}" if isinstance(x, float) else str(x)
    rows_s = [[to_str(x) for x in row[:n]] + [""]*(n - len(row)) for row in rows]

    # Decide alignment per column (numeric → right)
    def is_numeric_col(vals):
        for v in vals:
            if v == "":
                continue
            try:
                float(v)
            except ValueError:
                return False
        return True
    numeric = [is_numeric_col([r[i] for r in rows_s]) for i in range(n)]

    # Compute widths (max of header vs all row values)
    widths = [max(len(str(headers[i])), max((len(r[i]) for r in rows_s), default=0)) for i in range(n)]

    # Build format strings
    fmts = [f"{{:>{w}}}" if numeric[i] else f"{{:<{w}}}" for i, w in enumerate(widths)]

    # Print header, separator, rows
    header_line = "  ".join(fmt.format(headers[i]) for i, fmt in enumerate(fmts))
    sep_line    = "  ".join("-"*w for w in widths)
    print(header_line)
    print(sep_line)
    for r in rows_s:
        print("  ".join(fmt.format(r[i]) for i, fmt in enumerate(fmts)))

def load_pe(path):
    if path in pe_cache:
        return pe_cache[path]
    try:
        pe = pefile.PE(path, fast_load=False)
        pe_cache[path] = pe
        return pe
    except Exception as e:
        pe_cache[path] = e  # store exception to avoid retrying
        return e

def section_name(sec):
    try:
        return sec.Name.rstrip(b'\x00').decode(errors='ignore')
    except Exception:
        return None

def map_offset(pe, file_offset):
    """
    Return dict with section, rva, va, image_base, note
    """
    result = {"section": None, "rva": None, "va": None, "image_base": None, "note": ""}
    if isinstance(pe, Exception):
        result["note"] = f"PE open error: {pe}"
        return result

    ib = pe.OPTIONAL_HEADER.ImageBase
    result["image_base"] = ib

    # First check sections
    for s in pe.sections:
        start = s.PointerToRawData
        end   = start + s.SizeOfRawData
        if start <= file_offset < end:
            rva = (file_offset - start) + s.VirtualAddress
            va  = ib + rva
            result.update({
                "section": section_name(s),
                "rva": rva,
                "va": va
            })
            return result

    # If not in any section, maybe in headers
    try:
        hdr_size = pe.OPTIONAL_HEADER.SizeOfHeaders
    except Exception:
        hdr_size = 0

    if 0 <= file_offset < hdr_size:
        rva = file_offset  # headers are mapped contiguously at start
        va  = ib + rva
        result.update({
            "section": "HEADERS",
            "rva": rva,
            "va": va
        })
        return result

    # Otherwise, likely overlay / unmapped data
    result["note"] = "Offset not mapped to a section (overlay/unmapped)."
    return result

def parse_offset(s):
    s = s.strip()
    if s.lower().startswith("0x"):
        return int(s, 16)
    return int(s, 10)

def main():
    current_file = None
    current_rule = None

    # Header
    headers = ["File", "Rule", "String ID", "File Offset", "Section", "RVA", "VA", "Note"]

    rows = []
    for line in sys.stdin:
        line = line.rstrip("\n")

        # Header line: "<rule> <file>"
        m_hdr = HEADER_RE.match(line)
        if m_hdr and not line.startswith("0x") and not line[0].isdigit():
            current_rule = m_hdr.group(1)
            current_file = m_hdr.group(2)
            continue

        # Match line: "0xOFFSET:$id: ..."
        m_match = MATCH_RE.match(line)
        if not m_match:
            continue

        if not current_file:
            # YARA output should have a header line before match lines.
            # If not, we can’t map; skip.
            continue

        off_str = m_match.group(1)
        string_id = m_match.group(2)  # like $a, $b, etc.

        try:
            file_offset = parse_offset(off_str)
        except ValueError:
            # Skip malformed offsets
            continue

        pe = load_pe(current_file)
        mapping = map_offset(pe, file_offset)

        rva_hex = f"0x{mapping['rva']:X}" if mapping["rva"] is not None else ""
        va_hex  = f"0x{mapping['va']:X}"  if mapping["va"]  is not None else ""

        rows.append([current_file or "",
            current_rule or "",
            string_id or "",
            f"0x{file_offset:X}",
            mapping["section"] or "",
            rva_hex,
            va_hex,
            mapping.get("note","") or ""
        ])

    print_table(rows, headers)

if __name__ == "__main__":
    main()

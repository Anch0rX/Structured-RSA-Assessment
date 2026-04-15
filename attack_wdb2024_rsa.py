#!/usr/bin/env python3
"""
Educational lattice-based attack scaffold for structured RSA instances inspired by
public write-ups of the 2024 Wangding Cup semifinal challenge “RSA加密分析”.

This repository is intended for coursework, reproducibility, and experimentation.
It is not a black-box universal RSA breaker.

Main features
-------------
- Loads challenge parameters from JSON
- Builds a small structured lattice from three RSA instances
- Supports fpylll-based LLL or BKZ reduction
- Tries several basis augmentation heuristics automatically
- Attempts factor recovery from an approximation of p + q

Author: Anchor Cao (adapted into GitHub-ready form)
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass
from math import isqrt
from pathlib import Path
from time import perf_counter
from typing import Iterable, List, Sequence

try:
    from fpylll import BKZ, IntegerMatrix, LLL
except Exception as exc:  # pragma: no cover - import guard
    raise SystemExit(
        "fpylll is required. Install dependencies from requirements.txt first.\n"
        f"Original import error: {exc!r}"
    )


@dataclass(frozen=True)
class ChallengeInstance:
    moduli: Sequence[int]
    public_exponents: Sequence[int]
    ciphertext: int
    encryption_exponent: int
    name: str = "unnamed-instance"

    @staticmethod
    def from_json(path: Path) -> "ChallengeInstance":
        with path.open("r", encoding="utf-8") as fh:
            data = json.load(fh)
        return ChallengeInstance(
            moduli=[int(x) for x in data["moduli"]],
            public_exponents=[int(x) for x in data["public_exponents"]],
            ciphertext=int(data["ciphertext"]),
            encryption_exponent=int(data["encryption_exponent"]),
            name=str(data.get("name", path.stem)),
        )


@dataclass(frozen=True)
class ReductionConfig:
    identity_scale: int
    identity_count: int
    multiples: Sequence[int]
    method: str  # "lll" or "bkz"
    block_size: int = 20


DEFAULT_CONFIGS: Sequence[ReductionConfig] = (
    ReductionConfig(identity_scale=1, identity_count=3, multiples=(1,), method="lll"),
    ReductionConfig(identity_scale=1, identity_count=6, multiples=(1, 2), method="lll"),
    ReductionConfig(identity_scale=10**6, identity_count=6, multiples=(1, 2, 5), method="bkz", block_size=20),
    ReductionConfig(identity_scale=10**8, identity_count=6, multiples=(1, 2, 5), method="bkz", block_size=30),
    ReductionConfig(identity_scale=10**10, identity_count=6, multiples=(1, 2, 5), method="bkz", block_size=40),
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Educational structured-RSA attack scaffold using fpylll.",
    )
    parser.add_argument(
        "--input",
        type=Path,
        default=Path("examples/wdb2024_instance.json"),
        help="Path to the JSON file containing moduli/exponents/ciphertext.",
    )
    parser.add_argument(
        "--search-radius",
        type=int,
        default=1 << 18,
        help="Search radius around the recovered p+q approximation.",
    )
    parser.add_argument(
        "--max-candidates",
        type=int,
        default=20,
        help="How many reduced basis rows to test as attack candidates per configuration.",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Print more intermediate information.",
    )
    return parser.parse_args()


def is_perfect_square(value: int) -> bool:
    if value < 0:
        return False
    root = isqrt(value)
    return root * root == value


def factor_via_sum(modulus: int, sum_approx: int, search_radius: int) -> tuple[int | None, int | None]:
    for delta in range(-search_radius, search_radius + 1):
        s_val = sum_approx + delta
        discriminant = s_val * s_val - 4 * modulus
        if discriminant < 0 or not is_perfect_square(discriminant):
            continue
        root = isqrt(discriminant)
        p_val = (s_val + root) // 2
        q_val = (s_val - root) // 2
        if p_val > 1 and q_val > 1 and p_val * q_val == modulus:
            return p_val, q_val
    return None, None


def build_base_rows(moduli: Sequence[int], exponents: Sequence[int]) -> List[List[int]]:
    if len(moduli) != 3 or len(exponents) != 3:
        raise ValueError("This educational implementation expects exactly three moduli and three exponents.")

    n0, n1, n2 = moduli
    e0, e1, e2 = exponents
    rows = [
        [e1 * (n0 + 1), -e0 * (n1 + 1), 0, e1, -e0, 0],
        [e2 * (n0 + 1), 0, -e0 * (n2 + 1), e2, 0, -e0],
        [0, e2 * (n1 + 1), -e1 * (n2 + 1), 0, e2, -e1],
    ]
    return rows


def extend_with_identity(rows: List[List[int]], scale: int, count: int) -> List[List[int]]:
    cols = len(rows[0])
    for idx in range(count):
        row = [0] * cols
        row[idx % cols] = scale
        rows.append(row)
    return rows


def append_row_multiples(rows: List[List[int]], multipliers: Iterable[int]) -> List[List[int]]:
    original = list(rows)
    for mul in multipliers:
        if mul == 1:
            continue
        for row in original:
            rows.append([mul * entry for entry in row])
    return rows


def to_integer_matrix(rows: Sequence[Sequence[int]]) -> IntegerMatrix:
    nrows = len(rows)
    ncols = len(rows[0])
    mat = IntegerMatrix(nrows, ncols)
    for i in range(nrows):
        for j in range(ncols):
            mat[i, j] = int(rows[i][j])
    return mat


def reduce_basis(matrix: IntegerMatrix, config: ReductionConfig) -> IntegerMatrix:
    if config.method == "lll":
        LLL.reduction(matrix)
        return matrix
    if config.method == "bkz":
        BKZ.reduction(matrix, BKZ.Param(block_size=config.block_size))
        return matrix
    raise ValueError(f"Unknown reduction method: {config.method}")


def row_l1_norm(row: Sequence[int]) -> int:
    return sum(abs(x) for x in row)


def iter_reduced_rows(matrix: IntegerMatrix) -> List[List[int]]:
    rows: List[List[int]] = []
    for i in range(matrix.nrows):
        rows.append([int(matrix[i, j]) for j in range(matrix.ncols)])
    rows.sort(key=row_l1_norm)
    return rows


def recover_plaintext(ciphertext: int, enc_exp: int, modulus: int, p_val: int, q_val: int) -> tuple[int, bytes]:
    phi_val = (p_val - 1) * (q_val - 1)
    private_exp = pow(enc_exp, -1, phi_val)
    message = pow(ciphertext, private_exp, modulus)
    hex_str = hex(message)[2:]
    if len(hex_str) % 2:
        hex_str = "0" + hex_str
    return message, bytes.fromhex(hex_str)


def attack_instance(
    instance: ChallengeInstance,
    search_radius: int,
    max_candidates: int,
    verbose: bool,
) -> bool:
    print(f"[+] Loaded instance: {instance.name}")
    base_rows = build_base_rows(instance.moduli, instance.public_exponents)
    print(f"[+] Base lattice rows: {len(base_rows)} x {len(base_rows[0])}")

    for attempt_idx, config in enumerate(DEFAULT_CONFIGS, start=1):
        print(f"\n[===] Attempt {attempt_idx}: {config}")
        rows = [list(row) for row in base_rows]
        rows = extend_with_identity(rows, scale=config.identity_scale, count=config.identity_count)
        rows = append_row_multiples(rows, config.multiples)

        if verbose:
            print(f"[*] Augmented basis size: {len(rows)} x {len(rows[0])}")
            print(f"[*] First basis row prefix: {rows[0][:6]}")

        matrix = to_integer_matrix(rows)
        start = perf_counter()
        reduce_basis(matrix, config)
        elapsed = perf_counter() - start
        print(f"[+] Reduction completed in {elapsed:.2f}s")

        candidates = iter_reduced_rows(matrix)
        preview = min(6, len(candidates))
        print(f"[+] Preview of top {preview} reduced rows:")
        for idx in range(preview):
            row = candidates[idx]
            print(f"    {idx}: norm={row_l1_norm(row)} row={row[:6]}")

        for row in candidates[:max_candidates]:
            if len(row) < 6:
                continue
            k0, _, _, y0, _, _ = row[:6]
            if k0 == 0:
                continue
            s0_approx = -y0 // k0
            print(f"[*] Testing candidate k0={k0}, approx(p+q)={s0_approx}")
            p_val, q_val = factor_via_sum(instance.moduli[0], s0_approx, search_radius)
            if p_val is None:
                continue

            print("[+] Factorization succeeded")
            print(f"    p = {p_val}")
            print(f"    q = {q_val}")
            message, plaintext_bytes = recover_plaintext(
                instance.ciphertext,
                instance.encryption_exponent,
                instance.moduli[0],
                p_val,
                q_val,
            )
            print(f"[+] Decrypted integer: {message}")
            try:
                decoded = plaintext_bytes.decode("utf-8")
                print("[+] UTF-8 plaintext:")
                print(decoded)
            except UnicodeDecodeError:
                print("[+] Plaintext bytes (hex):")
                print(plaintext_bytes.hex())
            return True

    print("[!] No factorization was recovered with the current heuristic configurations.")
    print("[!] Consider increasing --search-radius or editing DEFAULT_CONFIGS.")
    return False


def main() -> int:
    args = parse_args()
    instance = ChallengeInstance.from_json(args.input)
    success = attack_instance(
        instance=instance,
        search_radius=args.search_radius,
        max_candidates=args.max_candidates,
        verbose=args.verbose,
    )
    return 0 if success else 1


if __name__ == "__main__":
    sys.exit(main())

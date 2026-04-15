# wdb2024-rsa-attack

Educational, GitHub-ready code for experimenting with a lattice-based attack scaffold inspired by the 2024 Wangding Cup semifinal crypto challenge **“RSA加密分析”**.

## What this repository is

This project is a **coursework-oriented reproduction scaffold**, not a universal RSA breaker. It focuses on:

- structured RSA instances with three related moduli,
- Diophantine-style elimination,
- small-d / near-square intuition,
- lattice reduction with `fpylll`.

It is suitable for:

- SE6003 Cryptography project appendices,
- reproducibility demonstrations,
- controlled CTF-style experimentation,
- studying how basis design affects LLL/BKZ outcomes.

## What this repository is not

- It is **not** a black-box implementation guaranteed to solve every challenge instance.
- It is **not** a production cryptanalysis library.
- It intentionally keeps the attack educational and transparent.

## Repository layout

```text
.
├── attack_wdb2024_rsa.py
├── examples/
│   └── wdb2024_instance.json
├── README.md
└── requirements.txt
```

## Installation

Create a clean Python environment first.

```bash
python3 -m venv rsa_venv
source rsa_venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
```

If `fpylll` fails to install on Debian/Kali/Ubuntu, install system dependencies first:

```bash
sudo apt-get update
sudo apt-get install -y build-essential libgmp-dev libmpfr-dev libmpc-dev python3-dev
pip install -r requirements.txt
```

## Input format

The script expects a JSON file with the following fields:

```json
{
  "name": "instance-name",
  "moduli": [N0, N1, N2],
  "public_exponents": [E0, E1, E2],
  "ciphertext": C,
  "encryption_exponent": e
}
```

An example file is included under `examples/wdb2024_instance.json`.

## Usage

Run with the bundled example:

```bash
python attack_wdb2024_rsa.py
```

Run with your own parameters:

```bash
python attack_wdb2024_rsa.py --input path/to/instance.json
```

Useful tuning options:

```bash
python attack_wdb2024_rsa.py --input examples/wdb2024_instance.json \
  --search-radius 262144 \
  --max-candidates 20 \
  --verbose
```

## How it works

At a high level, the script:

1. builds three elimination rows from the structured RSA relations,
2. augments the basis with scaled identity rows and row multiples,
3. runs `LLL` or `BKZ` using `fpylll`,
4. interprets short vectors as candidates for `(k_0, k_1, k_2, y_0, y_1, y_2)`,
5. recovers an approximation of `p + q`,
6. searches locally for exact factorization.

## Important caveat

This implementation is deliberately **heuristic**. If the bundled configurations do not recover a factorization, edit `DEFAULT_CONFIGS` in `attack_wdb2024_rsa.py` and experiment with:

- larger BKZ block sizes,
- different identity scales,
- larger search radii,
- alternative row combinations.

That behavior is expected in lattice cryptanalysis: the success of a practical attack can depend heavily on basis design and parameter tuning.

## Academic honesty note

If you use this repository in coursework, clearly state that it is an **independently written educational reconstruction** based on public theory and personal experimentation. Do not claim it is an official solution.

# Password Strength Checker

![Python](https://img.shields.io/badge/python-3.10%2B-3776ab?logo=python&logoColor=white)
![CI](https://img.shields.io/github/actions/workflow/status/hamzaiqbal2101/password-strength-checker/ci.yml?label=CI)
![Tests](https://img.shields.io/badge/tests-92%20passing-green)
![License](https://img.shields.io/badge/license-MIT-blue)

A production-style, modular password strength estimator built as a
cybersecurity engineering portfolio project. It combines **entropy
estimation**, **data-breach checks** (local wordlist + Have I Been Pwned
with k-anonymity), and **structural pattern detection** into a single
0-100 score with actionable feedback.

The tool is engineered around one rule: **the password itself is never
printed, stored, or transmitted.**

This is the first project in a cybersecurity portfolio:

1. **Password Strength Checker** (this project)
2. [File Integrity Checker](https://github.com/hamzaiqbal2101/file-integrity-checker)
3. [File Encryptor](https://github.com/hamzaiqbal2101/file-encryptor)
4. [Subdomain Enumerator](https://github.com/hamzaiqbal2101/subdomain-enumerator)
5. [Port Scanner](https://github.com/hamzaiqbal2101/portscanner)

## Features

- **Entropy estimation** - `entropy = length * log2(pool_size)` with
  classification bands (Weak <28, Fair 28-35, Good 36-59, Strong 60-127,
  Very Strong 128+).
- **Breach checks**:
  - Local common-passwords wordlist (SecLists / rockyou), offline-safe.
  - Have I Been Pwned range API using **k-anonymity** - only the first 5
    characters of the SHA-1 hash are ever transmitted.
- **Pattern detection** - keyboard walks (`qwerty`, `12345`), repeated
  characters (`aaaa`, `1111`), sequential characters (`abcd`, `9876`),
  leetspeak substitutions (`p@ssw0rd`), and dictionary words.
- **Weighted 0-100 scoring** with clear, actionable feedback.
- **Secure CLI** - `getpass` input (never echoed, never in shell history),
  batch mode that never echoes values, explicit memory cleanup.

## Project structure

```
password_strength_checker/
  __init__.py        # public API surface
  __main__.py        # enables `python -m password_strength_checker`
  entropy.py         # pool size, entropy formula, classification bands
  patterns.py        # keyboard/repeat/sequence/l33t/dictionary detection
  breach.py          # wordlist matching + HIBP k-anonymity client
  scoring.py         # weighted scoring model + feedback generation
  cli.py             # argparse + getpass interface (interactive & --file)
scripts/
  download_wordlists.py   # fetch SecLists top-10k (not bundled in repo)
tests/               # pytest suite (92 tests)
requirements.txt
pyproject.toml
```

## Requirements & install

- Python 3.10+
- `requests` (for the optional HIBP check). Everything else is stdlib.

```bash
pip install -r requirements.txt
# or, for an editable install with a console script:
pip install -e .
```

Download the common-passwords wordlist (recommended):

```bash
python scripts/download_wordlists.py
```

This fetches the SecLists top-10k list into `wordlists/common-passwords.txt`
(already gitignored - the repo does not bundle it). Without it, the tool
still detects a built-in set of the most common base words, and dictionary
detection keeps working.

## Usage

Interactive (password is hidden):

```bash
python -m password_strength_checker
```

Batch-check a file of passwords (one per line; values are never echoed):

```bash
python -m password_strength_checker --file batch.txt
```

Offline mode (skips the HIBP API):

```bash
python -m password_strength_checker --file batch.txt --no-network
```

Other options: `--wordlist PATH`, `--timeout SECONDS`, `--version`.

### Example output

Interactive:

```
$ python -m password_strength_checker
Enter password to check: ************

Score:      85/100 (Strong)
Length:     12 characters
Entropy:    78.66 bits (Strong)
Breach:     unknown
Patterns:   none
Feedback:
  - Strong password - no common patterns detected.
```

Batch:

```
$ python -m password_strength_checker --file batch.txt --no-network
Row | Len | Entropy | Class      | Breach      | Score | Label
----+-----+---------+------------+-------------+-------+------------
   1 |   8 |   37.60 | Good       | wordlist   |  24 | Very Weak
   2 |  10 |   47.00 | Good       | unknown    |  57 | Fair
   3 |  15 |   98.32 | Strong     | unknown    |  88 | Strong
   4 |  25 |  117.51 | Strong     | unknown    |  90 | Very Strong
```

## How the score works

The score blends three independent signals with near-equal weights:

| Component | Weight | What it measures |
|-----------|--------|------------------|
| Entropy   | 0.40   | Raw search-space size (length x log2(pool)). |
| Breach    | 0.30   | Whether the password is already public knowledge. |
| Patterns  | 0.30   | Structural weakness that collapses effective entropy. |

`score = round(100 * (0.40*E + 0.30*B + 0.30*P))`, clamped to [0, 100].

**Why these weights?** Each signal is necessary and none is sufficient alone:

- **Entropy** rewards size and variety, but a long keyboard walk can carry
  high entropy yet be guessed in milliseconds. Entropy alone is naive.
- **Breach** is the strongest real-world signal: if a password (or a close
  variant) already leaked, attackers try it before anything else, regardless
  of how clever it looks. But a novel password can still be structurally
  terrible.
- **Patterns** measure how much of the "randomness" is fake. A password
  built from dictionary words or keyboard runs has far less real strength
  than its entropy suggests.

Weights are near-equal because no signal should be able to dominate the
verdict; a password only earns a high score when it is **big, fresh, and
unstructured**.

Component details:

- **Entropy component** - maps entropy to a [0,1] value by interpolating
  between the classification band edges `(0, 28, 36, 60, 128)` bits rather
  than snapping at boundaries, so small length increases are rewarded
  smoothly.
- **Breach component** - wordlist hit = 0.0, HIBP pwned = 0.15, unknown
  (offline/API failure) = 0.70, HIBP clean = 1.0. "Unknown" is mildly
  penalized because we simply cannot vouch for the password.
- **Pattern component** - starts at 1.0 and subtracts per-detected weakness:
  keyboard walk -0.35, dictionary word -0.35, leetspeak -0.20, sequence
  -0.20, repetition -0.15, floored at 0.05.

**Hard cap:** a password found in a common-passwords wordlist (or exactly
equal to a built-in common base word, even offline) can never score above
24 - it is trivially the first thing an attacker tries.

## Security design

- **No logging/storage of the password.** The `Assessment` result stores
  only derived metrics (length, entropy, patterns, score) - never the value.
  Batch mode prints row numbers and metrics, never contents.
- **k-anonymity for HIBP.** `sha1(password)` is computed locally; only the
  first 5 hex characters are sent. The API returns candidate suffixes, and
  the match is completed locally. The full password and full hash never
  leave the machine. A descriptive User-Agent and a bounded timeout are
  used per HIBP policy.
- **`getpass` input** so the password is never echoed or written to shell
  history.
- **Memory cleanup.** Passwords are `del`eted after processing. Python
  strings are immutable, so this releases the reference for garbage
  collection rather than zeroing the buffer; for the strongest guarantees a
  language with mutable buffers (C/Rust) or an HSM is required.

## Testing

```bash
python -m pytest
```

The 92 tests cover entropy math and band boundaries, every pattern
detector, the scoring weights and edge cases, HIBP k-anonymity (verifying
only the 5-char prefix is transmitted), wordlist loading, and CLI behavior
(asserting passwords never appear in output).

## Limitations / what NOT to use this for

- **This is not a password generator, a policy enforcer, or a compliance
  tool.** It scores one password; it does not replace rate-limiting, MFA,
  or an organization's password policy.
- **The entropy formula is an upper-bound estimate**, not true per-byte
  Shannon entropy, and it cannot measure randomness of a human-chosen
  password. Two 12-character passwords can score the same yet have wildly
  different real-world strength.
- **Breach checks are best-effort.** HIBP coverage is not exhaustive, and
  without network/wordlist access the breach signal degrades to "unknown"
  (mildly penalized). "Not found" does not mean "never leaked."
- **Pattern detection is heuristic.** It targets common English/QWERTY
  patterns; a password structured around a foreign word, a name, or a
  context-specific string can slip through. It is not a full password
  cracker and cannot prove strength - only weakness.
- **Do not use it to store, transmit, or manage credentials**, and do not
  use the HIBP feature as a substitute for legitimate breach-monitoring
  services.

## License

MIT - see `pyproject.toml`. This is an educational portfolio project.
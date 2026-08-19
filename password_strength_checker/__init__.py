"""password_strength_checker - a security engineering portfolio tool.

A modular, production-style password strength estimator that combines:

* Character-class based entropy estimation
* Local common-password wordlist checks
* Have I Been Pwned k-anonymity breach checks (offline-safe)
* Structural pattern detection (keyboard walks, sequences, l33t speak, ...)
* A weighted 0-100 scoring model with actionable feedback

The password itself is never stored, logged, printed, or transmitted; only
the first five characters of its SHA-1 hash ever leave the machine (see
``breach.py``).
"""

from __future__ import annotations

from .breach import HibpClient, HibpError, check_wordlist, load_wordlist
from .entropy import (
    character_classes,
    character_pool_size,
    classify_entropy,
    shannon_entropy_bits,
)
from .patterns import (
    PatternReport,
    analyze_patterns,
    detect_dictionary_word,
    detect_keyboard_walk,
    detect_leet_substitution,
    detect_repeated_characters,
    detect_sequential_characters,
    normalize_l33t,
)
from .scoring import (
    Assessment,
    BreachStatus,
    assess,
    strength_label_from_score,
)

__version__ = "1.0.0"

__all__ = [
    "HibpClient",
    "HibpError",
    "check_wordlist",
    "load_wordlist",
    "character_classes",
    "character_pool_size",
    "classify_entropy",
    "shannon_entropy_bits",
    "PatternReport",
    "analyze_patterns",
    "detect_dictionary_word",
    "detect_keyboard_walk",
    "detect_leet_substitution",
    "detect_repeated_characters",
    "detect_sequential_characters",
    "normalize_l33t",
    "Assessment",
    "BreachStatus",
    "assess",
    "strength_label_from_score",
    "__version__",
]

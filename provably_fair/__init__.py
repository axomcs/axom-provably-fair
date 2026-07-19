"""Unified provably-fair primitives and game outcome mappings.

All in-house games must derive entropy through :class:`FairRandom`.  Game
modules may choose how those bytes become an outcome, but must not construct
their own hashes or pseudo-random generators.
"""

from .random import (
    ALGORITHM,
    FAIRNESS_VERSION,
    LEGACY_FAIRNESS_VERSION,
    FairInputs,
    FairRandom,
    SeedValidationError,
    hash_server_seed,
    validate_inputs,
    verify_server_seed_hash,
)
from .mappings import (
    GAME_ALGORITHM_VERSIONS,
    GAME_SCHEMAS,
    generate_outcome,
    normalize_game,
)
from .verifier import VerificationResult, verify
from .tokens import create_verification_token, verification_token_game

__all__ = [
    "ALGORITHM",
    "FairInputs",
    "FairRandom",
    "GAME_SCHEMAS",
    "GAME_ALGORITHM_VERSIONS",
    "FAIRNESS_VERSION",
    "LEGACY_FAIRNESS_VERSION",
    "SeedValidationError",
    "VerificationResult",
    "create_verification_token",
    "generate_outcome",
    "hash_server_seed",
    "normalize_game",
    "validate_inputs",
    "verify",
    "verification_token_game",
    "verify_server_seed_hash",
]

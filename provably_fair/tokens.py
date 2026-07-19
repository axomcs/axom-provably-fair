"""Collision-resistant, game-bound identifiers for provably-fair proofs."""

from __future__ import annotations

import re
import secrets

from .mappings import normalize_game


def create_verification_token(game: str) -> str:
    """Return a self-describing 128-bit proof ID independent of game nonces."""
    normalized_game = normalize_game(game)
    return f"pf_{normalized_game}_{secrets.token_hex(16)}"


def verification_token_game(token: str) -> str | None:
    """Extract the bound game from a current proof ID; legacy IDs return None."""
    value = str(token or "").strip().lower()
    if not value.startswith("pf_"):
        return None

    game_part, separator, entropy = value[3:].rpartition("_")
    if not separator or not re.fullmatch(r"[0-9a-f]{32}", entropy):
        return None

    try:
        return normalize_game(game_part)
    except ValueError:
        return None

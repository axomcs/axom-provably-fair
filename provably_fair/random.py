"""The only cryptographic random-byte generator used by casino games.

Protocol ``pf-v1``
==================

Each 32-byte block is::

    HMAC-SHA256(
        key=server_seed,
        message="pf-v1\ngame=<game>\nclient_seed=<seed>\nnonce=<n>\ncursor=<c>",
    )

``cursor`` starts at the value committed with the bet and increases once per
block.  Mapping functions consume this stream sequentially.  Integers use
rejection sampling, avoiding modulo bias.  This protocol is deliberately
small enough to reproduce in any language without relying on Python's PRNG.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import hmac
import re
from typing import Iterator


FAIRNESS_VERSION = "pf-v1"
LEGACY_FAIRNESS_VERSION = "hmac-sha256-v1"
# Backwards-compatible import name used throughout the application.
ALGORITHM = FAIRNESS_VERSION
SUPPORTED_FAIRNESS_VERSIONS = frozenset({FAIRNESS_VERSION, LEGACY_FAIRNESS_VERSION})
_HASH_RE = re.compile(r"^[0-9a-fA-F]{64}$")
_GAME_RE = re.compile(r"^[a-z0-9_]{1,64}$")


class SeedValidationError(ValueError):
    """Raised when public provably-fair input is malformed."""


@dataclass(frozen=True)
class FairInputs:
    server_seed: str
    client_seed: str
    nonce: int
    cursor: int = 0
    game: str = ""
    fairness_version: str = FAIRNESS_VERSION

    def validated(self) -> "FairInputs":
        validate_inputs(
            self.server_seed,
            self.client_seed,
            self.nonce,
            self.cursor,
            self.game,
            self.fairness_version,
        )
        return self


def _validate_seed(name: str, value: str) -> None:
    if not isinstance(value, str):
        raise SeedValidationError(f"{name} must be text")
    if not value:
        raise SeedValidationError(f"{name} is required")
    if len(value.encode("utf-8")) > 256:
        raise SeedValidationError(f"{name} must be at most 256 UTF-8 bytes")
    if any(ord(character) < 32 for character in value):
        raise SeedValidationError(f"{name} may not contain control characters")


def validate_inputs(
    server_seed: str,
    client_seed: str,
    nonce: int,
    cursor: int = 0,
    game: str = "",
    fairness_version: str = FAIRNESS_VERSION,
) -> None:
    _validate_seed("server_seed", server_seed)
    _validate_seed("client_seed", client_seed)
    if isinstance(nonce, bool) or not isinstance(nonce, int) or nonce < 0:
        raise SeedValidationError("nonce must be a non-negative integer")
    if isinstance(cursor, bool) or not isinstance(cursor, int) or cursor < 0:
        raise SeedValidationError("cursor must be a non-negative integer")
    if nonce > 2**63 - 1:
        raise SeedValidationError("nonce is too large")
    if cursor > 2**63 - 1:
        raise SeedValidationError("cursor is too large")
    if fairness_version not in SUPPORTED_FAIRNESS_VERSIONS:
        raise SeedValidationError(f"unsupported fairness version: {fairness_version}")
    if fairness_version == FAIRNESS_VERSION and not _GAME_RE.fullmatch(game or ""):
        raise SeedValidationError("pf-v1 requires a normalized game identifier")


def hash_server_seed(server_seed: str) -> str:
    _validate_seed("server_seed", server_seed)
    return hashlib.sha256(server_seed.encode("utf-8")).hexdigest()


def verify_server_seed_hash(server_seed: str, committed_hash: str) -> bool:
    if not isinstance(committed_hash, str) or not _HASH_RE.fullmatch(committed_hash):
        return False
    try:
        calculated = hash_server_seed(server_seed)
    except SeedValidationError:
        return False
    return hmac.compare_digest(calculated, committed_hash.lower())


def hmac_block(inputs: FairInputs, cursor: int | None = None) -> bytes:
    inputs.validated()
    block_cursor = inputs.cursor if cursor is None else cursor
    if isinstance(block_cursor, bool) or not isinstance(block_cursor, int) or block_cursor < 0:
        raise SeedValidationError("cursor must be a non-negative integer")
    if inputs.fairness_version == LEGACY_FAIRNESS_VERSION:
        message_text = f"{inputs.client_seed}:{inputs.nonce}:{block_cursor}"
    else:
        message_text = (
            f"{FAIRNESS_VERSION}\n"
            f"game={inputs.game}\n"
            f"client_seed={inputs.client_seed}\n"
            f"nonce={inputs.nonce}\n"
            f"cursor={block_cursor}"
        )
    message = message_text.encode("utf-8")
    return hmac.new(
        inputs.server_seed.encode("utf-8"),
        message,
        hashlib.sha256,
    ).digest()


def byte_stream(inputs: FairInputs) -> Iterator[int]:
    cursor = inputs.validated().cursor
    while True:
        yield from hmac_block(inputs, cursor)
        cursor += 1


class FairRandom:
    """Stateful reader over the canonical HMAC byte stream."""

    def __init__(self, inputs: FairInputs):
        self.inputs = inputs.validated()
        self._source = byte_stream(self.inputs)
        self.bytes_consumed = 0

    @property
    def proof(self) -> str:
        """First digest, useful when displaying an independently checkable proof."""
        return hmac_block(self.inputs).hex()

    def random_bytes(self, length: int) -> bytes:
        if isinstance(length, bool) or not isinstance(length, int) or length < 0:
            raise ValueError("length must be a non-negative integer")
        data = bytes(next(self._source) for _ in range(length))
        self.bytes_consumed += length
        return data

    def uint(self, byte_count: int = 8) -> int:
        if not 1 <= byte_count <= 32:
            raise ValueError("byte_count must be between 1 and 32")
        return int.from_bytes(self.random_bytes(byte_count), "big")

    def randbelow(self, upper: int) -> int:
        """Return an unbiased integer in ``range(upper)``."""
        if isinstance(upper, bool) or not isinstance(upper, int) or upper <= 0:
            raise ValueError("upper must be a positive integer")
        byte_count = max(1, ((upper - 1).bit_length() + 7) // 8)
        space = 1 << (byte_count * 8)
        ceiling = space - (space % upper)
        while True:
            candidate = self.uint(byte_count)
            if candidate < ceiling:
                return candidate % upper

    def integer(self, minimum: int, maximum: int) -> int:
        if maximum < minimum:
            raise ValueError("maximum must be greater than or equal to minimum")
        return minimum + self.randbelow(maximum - minimum + 1)

    def random_float(self) -> float:
        """Return a uniform IEEE-safe value in ``[0, 1)`` using 52 bits."""
        return (self.uint(7) >> 4) / float(1 << 52)

    def shuffle(self, values: list) -> list:
        """Shuffle a list in place with unbiased Fisher-Yates and return it."""
        for index in range(len(values) - 1, 0, -1):
            other = self.randbelow(index + 1)
            values[index], values[other] = values[other], values[index]
        return values

    def sample(self, population, count: int) -> list:
        values = list(population)
        if not 0 <= count <= len(values):
            raise ValueError("sample count is outside the population")
        for index in range(count):
            other = index + self.randbelow(len(values) - index)
            values[index], values[other] = values[other], values[index]
        return values[:count]

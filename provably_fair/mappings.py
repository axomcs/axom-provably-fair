"""Pure random-bytes-to-outcome mappings for every supported casino game."""

from __future__ import annotations

from dataclasses import replace
import hashlib
import math
from typing import Any, Callable, Mapping

from .random import (
    FAIRNESS_VERSION,
    LEGACY_FAIRNESS_VERSION,
    FairInputs,
    FairRandom,
)


DEFAULT_WHEEL_SEGMENTS = (
    5.0, 0.0, 0.2, 0.0, 1.5, 0.0, 0.3, 3.0, 0.0, 0.5,
    0.0, 2.0, 0.2, 0.0, 0.8, 0.0, 4.0, 0.0, 1.5, 0.0,
)
SUITS = ("S", "H", "D", "C")
RANKS = ("A", "2", "3", "4", "5", "6", "7", "8", "9", "10", "J", "Q", "K")

GAME_ALIASES = {
    "coin": "coinflip",
    "coin_flip": "coinflip",
    "coin flip": "coinflip",
    "black jack": "blackjack",
    "blackjack split": "blackjack",
    "blackjack_split": "blackjack",
    "russian roulette": "revolver",
    "russian_roulette": "revolver",
    "hi-lo": "hilo",
    "hi_lo": "hilo",
    "hi lo": "hilo",
    "seven up": "dice",
    "seven_up": "dice",
    "money tree": "money_tree",
    "money-tree": "money_tree",
    "daily jackpot": "jackpot",
    "horse race": "horse",
    "horse_race": "horse",
}

GAME_SCHEMAS: dict[str, dict[str, Any]] = {
    "roulette": {"label": "Roulette", "params": {}},
    "coinflip": {"label": "Coin Flip", "params": {}},
    "blackjack": {"label": "Blackjack", "params": {"decks": 6}},
    "limbo": {"label": "Limbo", "params": {"house_edge": 0.96, "max_multiplier": 1000}},
    "wheel": {"label": "Wheel", "params": {}},
    "revolver": {"label": "Revolver", "params": {"bullets": 1, "chambers": 6}},
    "plinko": {"label": "Plinko", "params": {"rows": 12}},
    "crash": {"label": "Crash", "params": {"house_edge_divisor": 33}},
    "dice": {
        "label": "Dice", "params": {"count": 1, "sides": 6},
        "externally_resolved": True,
    },
    "hilo": {"label": "Hi-Lo", "params": {}},
    "mines": {"label": "Mines", "params": {"grid_size": 5, "mines": 3}},
    "keno": {"label": "Keno", "params": {"pool_size": 40, "draws": 10}},
    "ladder": {"label": "Ladder", "params": {}},
    "money_tree": {"label": "Money Tree", "params": {}},
    "tower": {"label": "Tower", "params": {"rows": 9, "columns": 3}},
    "jackpot": {
        "label": "Jackpot",
        "params": {"participants": [{"user_id": 1, "tickets": 1}]},
    },
    "horse": {"label": "Horse Race", "params": {"horse_count": 8}},
}

GAME_ALGORITHM_VERSIONS = {
    "roulette": "roulette-v2",
    "coinflip": "coinflip-v2",
    "blackjack": "blackjack-v3",
    "limbo": "limbo-v2",
    "wheel": "wheel-v2",
    "revolver": "revolver-v2",
    "plinko": "plinko-v2",
    "crash": "crash-v3",
    "dice": "dice-v2",
    "hilo": "hilo-v2",
    "mines": "mines-v2",
    "keno": "keno-v2",
    "ladder": "ladder-v2",
    "money_tree": "money-tree-v2",
    "tower": "tower-v2",
    "jackpot": "jackpot-v2",
    "horse": "horse-v2",
}


def normalize_game(game: str) -> str:
    if not isinstance(game, str) or not game.strip():
        raise ValueError("game is required")
    normalized = game.strip().lower().replace("-", "_")
    normalized = GAME_ALIASES.get(normalized, GAME_ALIASES.get(game.strip().lower(), normalized))
    if normalized not in GAME_SCHEMAS:
        raise ValueError(f"unsupported game: {game}")
    return normalized


def _bounded_int(params: Mapping[str, Any], key: str, default: int, minimum: int, maximum: int) -> int:
    try:
        value = int(params.get(key, default))
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{key} must be an integer") from exc
    if not minimum <= value <= maximum:
        raise ValueError(f"{key} must be between {minimum} and {maximum}")
    return value


def roulette(rng: FairRandom, _params: Mapping[str, Any]) -> dict[str, Any]:
    number = rng.randbelow(37)
    red = {1, 3, 5, 7, 9, 12, 14, 16, 18, 19, 21, 23, 25, 27, 30, 32, 34, 36}
    return {"number": number, "color": "green" if number == 0 else "red" if number in red else "black"}


def coinflip(rng: FairRandom, _params: Mapping[str, Any]) -> dict[str, Any]:
    roll = rng.randbelow(2)
    return {"roll": roll, "result": "heads" if roll == 0 else "tails"}


def wheel(rng: FairRandom, params: Mapping[str, Any]) -> dict[str, Any]:
    raw_segments = params.get("segments", DEFAULT_WHEEL_SEGMENTS)
    if not isinstance(raw_segments, (list, tuple)) or not raw_segments:
        raise ValueError("segments must be a non-empty list")
    if len(raw_segments) > 256:
        raise ValueError("segments may contain at most 256 entries")
    segments = [float(value) for value in raw_segments]
    index = rng.randbelow(len(segments))
    return {
        "segment_index": index,
        "segment_number": index + 1,
        "multiplier": segments[index],
        "uniform_index": index,
    }


def _legacy_wheel(rng: FairRandom, params: Mapping[str, Any]) -> dict[str, Any]:
    raw_segments = params.get("segments", DEFAULT_WHEEL_SEGMENTS)
    segments = [float(value) for value in raw_segments]
    random_value = rng.random_float()
    index = min(len(segments) - 1, int(random_value * len(segments)))
    return {
        "segment_index": index,
        "segment_number": index + 1,
        "multiplier": segments[index],
        "random_value": random_value,
    }


def revolver(rng: FairRandom, params: Mapping[str, Any]) -> dict[str, Any]:
    chambers = _bounded_int(params, "chambers", 6, 2, 64)
    bullets = _bounded_int(params, "bullets", 1, 1, chambers - 1)
    chamber_index = rng.randbelow(chambers)
    safe_chambers = chambers - bullets
    safe = chamber_index < safe_chambers
    return {
        "chamber_index": chamber_index,
        "chamber_number": chamber_index + 1,
        "bullets": bullets,
        "safe": safe,
        "result": "survived" if safe else "hit",
    }


def _legacy_revolver(rng: FairRandom, params: Mapping[str, Any]) -> dict[str, Any]:
    chambers = _bounded_int(params, "chambers", 6, 2, 64)
    bullets = _bounded_int(params, "bullets", 1, 1, chambers - 1)
    chamber_index = (rng.uint(8) * chambers) // (1 << 64)
    safe = chamber_index < chambers - bullets
    return {
        "chamber_index": chamber_index,
        "chamber_number": chamber_index + 1,
        "bullets": bullets,
        "safe": safe,
        "result": "survived" if safe else "hit",
    }


def plinko(rng: FairRandom, params: Mapping[str, Any]) -> dict[str, Any]:
    rows = _bounded_int(params, "rows", 12, 1, 64)
    path = [rng.randbelow(2) for _ in range(rows)]
    slot = sum(path)
    result: dict[str, Any] = {"path": path, "slot_index": slot}
    table = params.get("multipliers")
    if table is not None:
        if not isinstance(table, (list, tuple)) or len(table) != rows + 1:
            raise ValueError("multipliers must contain rows + 1 entries")
        result["multiplier"] = float(table[slot])
    return result


def _limbo_multiplier(rng: FairRandom, params: Mapping[str, Any], default_edge: float) -> dict[str, Any]:
    house_edge = float(params.get("house_edge", default_edge))
    if not 0 < house_edge <= 1:
        raise ValueError("house_edge must be greater than 0 and at most 1")
    roll = rng.random_float()
    maximum = float(params.get("max_multiplier", 1_000_000))
    if maximum < 1:
        raise ValueError("max_multiplier must be at least 1")
    value = maximum if roll == 0 else min(maximum, max(1.0, math.floor((house_edge / roll) * 100) / 100))
    return {"roll": roll, "multiplier": value}


def limbo(rng: FairRandom, params: Mapping[str, Any]) -> dict[str, Any]:
    return _limbo_multiplier(rng, params, 0.96)


def crash(rng: FairRandom, params: Mapping[str, Any]) -> dict[str, Any]:
    """Map the canonical stream through the established 52-bit crash curve."""
    divisor = _bounded_int(params, "house_edge_divisor", 33, 2, 1_000_000)
    instant_roll = rng.randbelow(divisor)
    value_52 = rng.uint(7) >> 4
    space = 1 << 52
    instant_crash = instant_roll == 0
    if instant_crash:
        multiplier = 1.0
    else:
        raw = (100 * space - value_52) / (space - value_52)
        multiplier = max(1.0, math.floor(raw) / 100)
    return {
        "value_52": value_52,
        "instant_roll": instant_roll,
        "instant_crash": instant_crash,
        "multiplier": multiplier,
    }


def _legacy_crash(rng: FairRandom, params: Mapping[str, Any]) -> dict[str, Any]:
    divisor = _bounded_int(params, "house_edge_divisor", 33, 2, 1_000_000)
    value_52 = rng.uint(7) >> 4
    space = 1 << 52
    instant_crash = value_52 % divisor == 0
    if instant_crash:
        multiplier = 1.0
    else:
        raw = (100 * space - value_52) / (space - value_52)
        multiplier = max(1.0, math.floor(raw) / 100)
    return {
        "value_52": value_52,
        "instant_crash": instant_crash,
        "multiplier": multiplier,
    }


def blackjack(rng: FairRandom, params: Mapping[str, Any]) -> dict[str, Any]:
    decks = _bounded_int(params, "decks", 6, 1, 12)
    shoe_index = _bounded_int(params, "shoe_index", 0, 0, 15)
    shoe: list[str] = []
    # Reconstruct and consume every earlier shoe in the same byte stream. This
    # lets an exhausted game continue without inventing another bet nonce.
    for _ in range(shoe_index + 1):
        shoe = [f"{rank}{suit}" for _ in range(decks) for suit in SUITS for rank in RANKS]
        rng.shuffle(shoe)
    preview = list(shoe)
    if str(params.get("draw_from", "start")).lower() == "end":
        initial_player = [preview.pop(), preview.pop()]
        initial_dealer = [preview.pop(), preview.pop()]
    else:
        initial_player = [preview[0], preview[2]]
        initial_dealer = [preview[1], preview[3]]
    return {
        "decks": decks,
        "shoe_index": shoe_index,
        "shoe": shoe,
        "initial_player": initial_player,
        "initial_dealer": initial_dealer,
    }


def dice(rng: FairRandom, params: Mapping[str, Any]) -> dict[str, Any]:
    count = _bounded_int(params, "count", 1, 1, 100)
    sides = _bounded_int(params, "sides", 6, 2, 1_000_000)
    rolls = [rng.integer(1, sides) for _ in range(count)]
    return {"rolls": rolls, "total": sum(rolls)}


def hilo(rng: FairRandom, _params: Mapping[str, Any]) -> dict[str, Any]:
    rank_index = rng.randbelow(13)
    suit_index = rng.randbelow(4)
    return {"rank_index": rank_index, "rank": RANKS[rank_index], "suit": SUITS[suit_index]}


def mines(rng: FairRandom, params: Mapping[str, Any]) -> dict[str, Any]:
    grid_size = _bounded_int(params, "grid_size", 5, 2, 20)
    tiles = grid_size * grid_size
    mine_count = _bounded_int(params, "mines", 3, 1, tiles - 1)
    positions = sorted(rng.sample(range(tiles), mine_count))
    return {"grid_size": grid_size, "mine_count": mine_count, "mine_positions": positions}


def keno(rng: FairRandom, params: Mapping[str, Any]) -> dict[str, Any]:
    pool_size = _bounded_int(params, "pool_size", 40, 2, 1000)
    draws = _bounded_int(params, "draws", 10, 1, pool_size - 1)
    numbers = sorted(rng.sample(range(1, pool_size + 1), draws))
    return {"numbers": numbers}


def ladder(rng: FairRandom, params: Mapping[str, Any]) -> dict[str, Any]:
    outcomes = params.get("outcomes", ("AC", "AD", "BC", "BD"))
    if not isinstance(outcomes, (list, tuple)) or not outcomes:
        raise ValueError("outcomes must be a non-empty list")
    result = str(outcomes[rng.randbelow(len(outcomes))])
    rungs = 4 if result in {"AC", "BD"} else 3
    return {"result": result, "path": [1] * rungs}


def money_tree(rng: FairRandom, _params: Mapping[str, Any]) -> dict[str, Any]:
    rolls = [rng.integer(1, 6) for _ in range(3)]
    return {"dice": rolls, "sum": sum(rolls)}


def tower(rng: FairRandom, params: Mapping[str, Any]) -> dict[str, Any]:
    rows = _bounded_int(params, "rows", 9, 1, 64)
    columns = _bounded_int(params, "columns", 3, 2, 64)
    return {"snake_positions": [rng.randbelow(columns) for _ in range(rows)]}


def jackpot(rng: FairRandom, params: Mapping[str, Any]) -> dict[str, Any]:
    """Choose an unbiased ticket from a published, ordered participant list."""
    raw_participants = params.get("participants")
    if not isinstance(raw_participants, (list, tuple)) or not raw_participants:
        raise ValueError("participants must be a non-empty list")
    participants: list[dict[str, int]] = []
    total_tickets = 0
    for entry in raw_participants:
        if not isinstance(entry, Mapping):
            raise ValueError("each participant must be an object")
        try:
            user_id = int(entry["user_id"])
            tickets = int(entry["tickets"])
        except (KeyError, TypeError, ValueError) as exc:
            raise ValueError("participants require integer user_id and tickets") from exc
        if tickets <= 0:
            raise ValueError("participant tickets must be positive")
        participants.append({"user_id": user_id, "tickets": tickets})
        total_tickets += tickets
    participants_csv = ",".join(
        f"{participant['user_id']}:{participant['tickets']}"
        for participant in participants
    )
    participant_hash = hashlib.sha256(participants_csv.encode("utf-8")).hexdigest()
    if rng.inputs.client_seed.startswith("jackpot:") and not rng.inputs.client_seed.endswith(
        f":{participant_hash}"
    ):
        raise ValueError("jackpot client_seed does not bind the participant list")
    target = rng.randbelow(total_tickets)
    cumulative = 0
    for index, participant in enumerate(participants):
        cumulative += participant["tickets"]
        if target < cumulative:
            return {
                "winner_id": participant["user_id"],
                "winner_index": index,
                "target_ticket": target,
                "total_tickets": total_tickets,
            }
    raise RuntimeError("ticket selection fell outside the published ranges")


def horse(rng: FairRandom, params: Mapping[str, Any]) -> dict[str, Any]:
    """Return an unbiased finish permutation bound to every accepted bet seed."""
    horse_count = _bounded_int(params, "horse_count", 8, 2, 32)
    raw_components = params.get("client_seed_components")
    if raw_components is not None:
        if not isinstance(raw_components, (list, tuple)) or not raw_components:
            raise ValueError("client_seed_components must be a non-empty list")
        canonical: list[str] = []
        for index, entry in enumerate(raw_components):
            if not isinstance(entry, Mapping):
                raise ValueError("each client seed component must be an object")
            try:
                bet_index = int(entry["bet_index"])
                user_id = int(entry["user_id"])
                client_seed = str(entry["client_seed"])
            except (KeyError, TypeError, ValueError) as exc:
                raise ValueError(
                    "client seed components require bet_index, user_id, and client_seed"
                ) from exc
            if bet_index != index:
                raise ValueError("client seed component indexes must be contiguous")
            seed_hex = client_seed.encode("utf-8").hex()
            canonical.append(f"{bet_index}:{user_id}:{seed_hex}")
        component_hash = hashlib.sha256("\n".join(canonical).encode("utf-8")).hexdigest()
        if (
            not rng.inputs.client_seed.startswith("horse:")
            or not rng.inputs.client_seed.endswith(f":{component_hash}")
        ):
            raise ValueError("horse client_seed does not bind the accepted bet seeds")
    finish_order = list(range(1, horse_count + 1))
    rng.shuffle(finish_order)
    return {"horse_count": horse_count, "finish_order": finish_order}


MAPPINGS: dict[str, Callable[[FairRandom, Mapping[str, Any]], dict[str, Any]]] = {
    "roulette": roulette,
    "coinflip": coinflip,
    "blackjack": blackjack,
    "limbo": limbo,
    "wheel": wheel,
    "revolver": revolver,
    "plinko": plinko,
    "crash": crash,
    "dice": dice,
    "hilo": hilo,
    "mines": mines,
    "keno": keno,
    "ladder": ladder,
    "money_tree": money_tree,
    "tower": tower,
    "jackpot": jackpot,
    "horse": horse,
}

# Registry keys are immutable public contracts. A future mapping change must
# add another version rather than replacing any existing key.
GAME_VERSION_REGISTRY = {
    game: {
        GAME_ALGORITHM_VERSIONS[game]: mapping,
        f"{game}-legacy-v1": mapping,
    }
    for game, mapping in MAPPINGS.items()
}
GAME_VERSION_REGISTRY["wheel"]["wheel-legacy-v1"] = _legacy_wheel
GAME_VERSION_REGISTRY["revolver"]["revolver-legacy-v1"] = _legacy_revolver
GAME_VERSION_REGISTRY["crash"]["crash-legacy-v1"] = _legacy_crash


def generate_outcome(
    game: str,
    inputs: FairInputs,
    params: Mapping[str, Any] | None = None,
    game_algorithm_version: str | None = None,
) -> dict[str, Any]:
    normalized = normalize_game(game)
    version = game_algorithm_version or (
        f"{normalized}-legacy-v1"
        if inputs.fairness_version == LEGACY_FAIRNESS_VERSION
        else GAME_ALGORITHM_VERSIONS[normalized]
    )
    mapping = GAME_VERSION_REGISTRY[normalized].get(version)
    if mapping is None:
        raise ValueError(f"unsupported {normalized} algorithm version: {version}")
    domain_inputs = replace(inputs, game=normalized)
    rng = FairRandom(domain_inputs)
    outcome = mapping(rng, params or {})
    return {
        "game": normalized,
        "algorithm": inputs.fairness_version,
        "fairness_version": inputs.fairness_version,
        "game_algorithm_version": version,
        "cursor": inputs.cursor,
        "proof": rng.proof,
        "bytes_consumed": rng.bytes_consumed,
        "outcome": outcome,
    }

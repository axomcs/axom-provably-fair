"""Universal verifier used by HTTP, Telegram, tests, and internal tooling."""

from __future__ import annotations

from dataclasses import asdict, dataclass
import json
import math
from decimal import Decimal, InvalidOperation, ROUND_HALF_UP
from typing import Any, Mapping

from .mappings import generate_outcome, normalize_game
from .random import ALGORITHM, SUPPORTED_FAIRNESS_VERSIONS, FairInputs, verify_server_seed_hash


@dataclass(frozen=True)
class VerificationResult:
    verified: bool
    commitment_matches: bool
    outcome_matches: bool | None
    randomness_matches: bool | None
    payout_matches: bool | None
    game: str
    algorithm: str
    generated: dict[str, Any]
    recorded: Any
    errors: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["errors"] = list(self.errors)
        return data


def _equal(generated: Any, recorded: Any) -> bool:
    """Recorded objects may be partial; every recorded leaf must match."""
    if isinstance(recorded, Mapping):
        return isinstance(generated, Mapping) and all(
            key in generated and _equal(generated[key], value)
            for key, value in recorded.items()
        )
    if isinstance(recorded, list):
        return isinstance(generated, list) and len(generated) == len(recorded) and all(
            _equal(left, right) for left, right in zip(generated, recorded)
        )
    if isinstance(recorded, float) or isinstance(generated, float):
        try:
            return math.isclose(float(generated), float(recorded), rel_tol=0.0, abs_tol=1e-12)
        except (TypeError, ValueError):
            return False
    return generated == recorded


def parse_json_object(value: Any, field: str) -> dict[str, Any]:
    if value in (None, ""):
        return {}
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except json.JSONDecodeError as exc:
            raise ValueError(f"{field} must be valid JSON") from exc
    if not isinstance(value, dict):
        raise ValueError(f"{field} must be a JSON object")
    return value


def verify(
    *,
    game: str,
    server_seed: str,
    server_seed_hash: str,
    client_seed: str,
    nonce: int,
    cursor: int = 0,
    params: Mapping[str, Any] | None = None,
    recorded: Any = None,
    algorithm: str = ALGORITHM,
    fairness_version: str | None = None,
    game_algorithm_version: str | None = None,
    expected_proof: str | None = None,
    payout_context: Mapping[str, Any] | None = None,
    recorded_payout: float | None = None,
) -> VerificationResult:
    normalized = normalize_game(game)
    version = fairness_version or algorithm
    if version not in SUPPORTED_FAIRNESS_VERSIONS:
        raise ValueError(f"unsupported fairness version: {version}")
    commitment_matches = verify_server_seed_hash(server_seed, server_seed_hash)
    generated = generate_outcome(
        normalized,
        FairInputs(
            server_seed,
            client_seed,
            int(nonce),
            int(cursor),
            normalized,
            version,
        ),
        params,
        game_algorithm_version,
    )
    outcome_matches = None if recorded is None else _equal(generated["outcome"], recorded)
    randomness_matches = None
    if expected_proof:
        randomness_matches = expected_proof.lower() == generated["proof"].lower()
    payout_matches = _verify_payout(
        payout_context, recorded_payout, generated["outcome"]
    )
    errors: list[str] = []
    if not commitment_matches:
        errors.append("The revealed server seed does not match the committed SHA-256 hash.")
    if outcome_matches is False:
        errors.append("The generated outcome does not match the recorded outcome.")
    if randomness_matches is False:
        errors.append("The generated HMAC proof does not match the recorded random value.")
    if payout_matches is False:
        errors.append("The recorded payout does not match the committed payout rules.")
    return VerificationResult(
        verified=(
            commitment_matches
            and outcome_matches is not False
            and randomness_matches is not False
            and payout_matches is not False
        ),
        commitment_matches=commitment_matches,
        outcome_matches=outcome_matches,
        randomness_matches=randomness_matches,
        payout_matches=payout_matches,
        game=normalized,
        algorithm=version,
        generated=generated["outcome"],
        recorded=recorded,
        errors=tuple(errors),
    )


def _verify_payout(
    context: Mapping[str, Any] | None,
    recorded_payout: float | None,
    generated_outcome: Mapping[str, Any] | None = None,
) -> bool | None:
    if not context or recorded_payout is None:
        return None
    try:
        formula = context.get("formula")
        if formula == "fixed":
            return math.isclose(
                float(context["amount"]), float(recorded_payout),
                rel_tol=0.0, abs_tol=1e-9,
            )
        if formula == "roulette":
            number = int((generated_outcome or {}).get("number", context["number"]))
            unit = Decimal(str(context["unit_wager"]))
            red = {1, 3, 5, 7, 9, 12, 14, 16, 18, 19, 21, 23, 25, 27, 30, 32, 34, 36}
            expected = unit * 36 if number in context.get("numbers", ()) else Decimal(0)
            if "Red" in context.get("colors", ()) and number in red:
                expected += unit * Decimal("1.92")
            if "Black" in context.get("colors", ()) and number and number not in red:
                expected += unit * Decimal("1.92")
            if number:
                if "Even" in context.get("evens", ()) and number % 2 == 0:
                    expected += unit * Decimal("1.92")
                if "Odd" in context.get("evens", ()) and number % 2 == 1:
                    expected += unit * Decimal("1.92")
                if "1 to 18" in context.get("ranges", ()) and number <= 18:
                    expected += unit * Decimal("1.92")
                if "19 to 36" in context.get("ranges", ()) and number >= 19:
                    expected += unit * Decimal("1.92")
                if "1 to 12" in context.get("dozens", ()) and number <= 12:
                    expected += unit * Decimal("2.88")
                if "13 to 24" in context.get("dozens", ()) and 13 <= number <= 24:
                    expected += unit * Decimal("2.88")
                if "25 to 36" in context.get("dozens", ()) and number >= 25:
                    expected += unit * Decimal("2.88")
            precision = int(context.get("precision", 6))
            quantum = Decimal(1).scaleb(-precision)
            expected = expected.quantize(quantum, rounding=ROUND_HALF_UP)
            return abs(expected - Decimal(str(recorded_payout))) <= quantum
        if formula == "horse":
            order = [int(value) for value in (generated_outcome or {}).get("finish_order", ())]
            bet = context["bet"]
            bet_type = str(bet["type"])
            horses = [int(value) for value in bet.get("horses", ())]
            if not order:
                return False
            winner = order[0]
            if bet_type == "win":
                won = horses[0] == winner
            elif bet_type == "place":
                won = horses[0] in order[:2]
            elif bet_type == "show":
                won = horses[0] in order[:3]
            elif bet_type == "last":
                won = horses[0] == order[-1]
            elif bet_type == "vs":
                won = order.index(horses[0]) < order.index(horses[1])
            elif bet_type == "fc":
                won = order[:2] == horses[:2]
            elif bet_type == "qn":
                won = set(order[:2]) == set(horses[:2])
            elif bet_type == "odd":
                won = winner % 2 == 1
            elif bet_type == "even":
                won = winner % 2 == 0
            elif bet_type == "low":
                won = winner <= len(order) // 2
            elif bet_type == "high":
                won = winner > len(order) // 2
            else:
                return False
            wager = Decimal(str(context["wager"]))
            multiplier = Decimal(str(context["multiplier"]))
            precision = int(context.get("precision", 6))
            quantum = Decimal(1).scaleb(-precision)
            expected = (
                (wager * multiplier).quantize(quantum, rounding=ROUND_HALF_UP)
                if won else Decimal(0)
            )
            if context.get("max_payout") is not None:
                expected = min(expected, Decimal(str(context["max_payout"])))
            return abs(expected - Decimal(str(recorded_payout))) <= quantum
        if formula != "multiplier":
            return None
        wager = Decimal(str(context["wager"]))
        multiplier = Decimal(str(context["multiplier"]))
        won = bool(context.get("won", multiplier > 0))
        precision = int(context.get("precision", 6))
        quantum = Decimal(1).scaleb(-precision)
        expected = (
            (wager * multiplier).quantize(quantum, rounding=ROUND_HALF_UP)
            if won else Decimal(0)
        )
        if context.get("max_payout") is not None:
            expected = min(expected, Decimal(str(context["max_payout"])))
        return abs(expected - Decimal(str(recorded_payout))) <= quantum
    except (IndexError, KeyError, TypeError, ValueError, InvalidOperation):
        return False

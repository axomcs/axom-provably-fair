import hashlib
import json
import unittest

from provably_fair import (
    ALGORITHM,
    FAIRNESS_VERSION,
    LEGACY_FAIRNESS_VERSION,
    FairInputs,
    FairRandom,
    GAME_SCHEMAS,
    create_verification_token,
    generate_outcome,
    hash_server_seed,
    normalize_game,
    verification_token_game,
    verify,
)


INPUTS = FairInputs(
    server_seed="0123456789abcdef" * 4,
    client_seed="player-selected-seed",
    nonce=42,
    cursor=0,
    game="roulette",
)


class ProvablyFairTests(unittest.TestCase):
    def test_current_proof_tokens_are_unique_and_game_bound(self):
        mines_token = create_verification_token("mines")
        roulette_token = create_verification_token("roulette")
        self.assertNotEqual(mines_token, create_verification_token("mines"))
        self.assertEqual(verification_token_game(mines_token), "mines")
        self.assertEqual(verification_token_game(roulette_token), "roulette")
        self.assertIsNone(verification_token_game("provablyfair_2"))
        self.assertIsNone(verification_token_game("pf_mines_not-random"))

    def test_all_published_game_labels_normalize_to_their_mapping(self):
        labels = {
            "Roulette": "roulette", "Coinflip": "coinflip",
            "Blackjack": "blackjack", "Blackjack (Split)": "blackjack",
            "Limbo": "limbo", "Wheel": "wheel",
            "Russian Roulette": "revolver", "Plinko": "plinko",
            "Crash": "crash", "Mines": "mines", "Ladder": "ladder",
            "Money Tree": "money_tree", "Tower": "tower",
            "Jackpot": "jackpot", "Horse": "horse",
        }
        for label, expected in labels.items():
            with self.subTest(label=label):
                self.assertEqual(normalize_game(label), expected)

    def test_every_mapping_is_deterministic_and_json_serializable(self):
        for game in sorted(GAME_SCHEMAS):
            with self.subTest(game=game):
                params = dict(GAME_SCHEMAS[game]["params"])
                first = generate_outcome(game, INPUTS, params)
                second = generate_outcome(game, INPUTS, params)
                self.assertEqual(first, second)
                self.assertEqual(first["algorithm"], ALGORITHM)
                json.dumps(first)

    def test_cursor_and_nonce_change_the_stream(self):
        base = FairRandom(INPUTS).random_bytes(64)
        next_cursor = FairRandom(
            FairInputs(INPUTS.server_seed, INPUTS.client_seed, 42, 1, "roulette")
        ).random_bytes(32)
        next_nonce = FairRandom(
            FairInputs(INPUTS.server_seed, INPUTS.client_seed, 43, 0, "roulette")
        ).random_bytes(64)
        self.assertEqual(base[32:], next_cursor)
        self.assertNotEqual(base, next_nonce)

    def test_integer_generation_stays_in_bounds(self):
        rng = FairRandom(INPUTS)
        for upper in (1, 2, 3, 6, 37, 255, 256, 10_000):
            for _ in range(100):
                self.assertTrue(0 <= rng.randbelow(upper) < upper)

    def test_verifier_checks_commitment_and_partial_recorded_outcome(self):
        generated = generate_outcome("roulette", INPUTS)["outcome"]
        valid = verify(
            game="roulette",
            server_seed=INPUTS.server_seed,
            server_seed_hash=hash_server_seed(INPUTS.server_seed),
            client_seed=INPUTS.client_seed,
            nonce=INPUTS.nonce,
            recorded={"number": generated["number"]},
        )
        self.assertTrue(valid.verified)
        self.assertTrue(valid.commitment_matches)
        self.assertTrue(valid.outcome_matches)

        invalid = verify(
            game="roulette",
            server_seed=INPUTS.server_seed,
            server_seed_hash="0" * 64,
            client_seed=INPUTS.client_seed,
            nonce=INPUTS.nonce,
            recorded={"number": (generated["number"] + 1) % 37},
        )
        self.assertFalse(invalid.verified)
        self.assertFalse(invalid.commitment_matches)
        self.assertFalse(invalid.outcome_matches)

    def test_known_protocol_vector(self):
        rng = FairRandom(INPUTS)
        self.assertEqual(
            rng.proof,
            "29c2c3b6a94034849de3391da547d6e139062310cdd9a2294b2fddf3d887a9f5",
        )
        self.assertEqual(rng.random_bytes(8).hex(), "29c2c3b6a9403484")

    def test_domain_separation_changes_the_stream(self):
        roulette = FairRandom(INPUTS).random_bytes(64)
        coinflip = FairRandom(FairInputs(
            INPUTS.server_seed, INPUTS.client_seed, INPUTS.nonce, 0, "coinflip"
        )).random_bytes(64)
        self.assertNotEqual(roulette, coinflip)

    def test_legacy_protocol_vector_remains_stable(self):
        legacy = FairRandom(FairInputs(
            INPUTS.server_seed, INPUTS.client_seed, INPUTS.nonce, 0, "",
            LEGACY_FAIRNESS_VERSION,
        ))
        self.assertEqual(
            legacy.proof,
            "90068f0eb8d36d2781165ec01c420284ba49c7e83ce157f9ecb62856aa261941",
        )

    def test_every_game_replays_and_input_mutations_change_randomness(self):
        variants = (
            FairInputs("f" * 64, INPUTS.client_seed, INPUTS.nonce),
            FairInputs(INPUTS.server_seed, "different-client", INPUTS.nonce),
            FairInputs(INPUTS.server_seed, INPUTS.client_seed, INPUTS.nonce + 1),
        )
        for game, schema in GAME_SCHEMAS.items():
            with self.subTest(game=game):
                params = dict(schema["params"])
                generated = generate_outcome(game, INPUTS, params)
                replay = verify(
                    game=game,
                    server_seed=INPUTS.server_seed,
                    server_seed_hash=hash_server_seed(INPUTS.server_seed),
                    client_seed=INPUTS.client_seed,
                    nonce=INPUTS.nonce,
                    params=params,
                    recorded=generated["outcome"],
                    fairness_version=FAIRNESS_VERSION,
                    game_algorithm_version=generated["game_algorithm_version"],
                    expected_proof=generated["proof"],
                )
                self.assertTrue(replay.verified)
                for changed in variants:
                    changed_result = generate_outcome(game, changed, params)
                    self.assertNotEqual(generated["proof"], changed_result["proof"])

    def test_verifier_checks_randomness_and_payout_stages(self):
        generated = generate_outcome("coinflip", INPUTS)
        result = verify(
            game="coinflip",
            server_seed=INPUTS.server_seed,
            server_seed_hash=hash_server_seed(INPUTS.server_seed),
            client_seed=INPUTS.client_seed,
            nonce=INPUTS.nonce,
            recorded=generated["outcome"],
            expected_proof=generated["proof"],
            payout_context={
                "formula": "multiplier", "wager": 10, "multiplier": 1.9,
                "won": True, "precision": 2,
            },
            recorded_payout=19,
        )
        self.assertTrue(result.verified)
        self.assertTrue(result.randomness_matches)
        self.assertTrue(result.payout_matches)

        tampered = verify(
            game="coinflip",
            server_seed=INPUTS.server_seed,
            server_seed_hash=hash_server_seed(INPUTS.server_seed),
            client_seed=INPUTS.client_seed,
            nonce=INPUTS.nonce,
            recorded=generated["outcome"],
            expected_proof="0" * 64,
            payout_context={
                "formula": "multiplier", "wager": 10, "multiplier": 1.9,
                "won": True, "precision": 2,
            },
            recorded_payout=18,
        )
        self.assertFalse(tampered.verified)
        self.assertFalse(tampered.randomness_matches)
        self.assertFalse(tampered.payout_matches)

    def test_jackpot_participants_are_bound_to_client_seed(self):
        participants = [
            {"user_id": 100, "tickets": 5},
            {"user_id": 200, "tickets": 15},
        ]
        participants_csv = "100:5,200:15"
        client_seed = (
            "jackpot:2026-07-18:"
            + hashlib.sha256(participants_csv.encode()).hexdigest()
        )
        inputs = FairInputs(INPUTS.server_seed, client_seed, 0)
        result = generate_outcome("jackpot", inputs, {"participants": participants})
        self.assertIn(result["outcome"]["winner_id"], {100, 200})
        self.assertLess(result["outcome"]["target_ticket"], 20)

        with self.assertRaisesRegex(ValueError, "bind the participant list"):
            generate_outcome(
                "jackpot",
                inputs,
                {"participants": participants + [{"user_id": 300, "tickets": 1}]},
            )

    def test_horse_binds_player_seeds_and_verifies_bet_payout(self):
        components = [
            {"bet_index": 0, "user_id": 100, "client_seed": "alice-seed"},
            {"bet_index": 1, "user_id": 200, "client_seed": "बॉब-seed"},
        ]
        canonical = "\n".join(
            f"{entry['bet_index']}:{entry['user_id']}:"
            f"{entry['client_seed'].encode('utf-8').hex()}"
            for entry in components
        )
        client_seed = (
            "horse:RACE42:"
            + hashlib.sha256(canonical.encode("utf-8")).hexdigest()
        )
        params = {"horse_count": 8, "client_seed_components": components}
        inputs = FairInputs(INPUTS.server_seed, client_seed, 99)
        generated = generate_outcome("horse", inputs, params)
        winner = generated["outcome"]["finish_order"][0]
        valid = verify(
            game="horse",
            server_seed=inputs.server_seed,
            server_seed_hash=hash_server_seed(inputs.server_seed),
            client_seed=inputs.client_seed,
            nonce=inputs.nonce,
            params=params,
            recorded=generated["outcome"],
            expected_proof=generated["proof"],
            payout_context={
                "formula": "horse", "wager": 10, "multiplier": 7.68,
                "bet": {"type": "win", "horses": [winner]}, "precision": 2,
            },
            recorded_payout=76.8,
        )
        self.assertTrue(valid.verified)
        self.assertTrue(valid.payout_matches)

        tampered_loser = next(value for value in range(1, 9) if value != winner)
        invalid = verify(
            game="horse",
            server_seed=inputs.server_seed,
            server_seed_hash=hash_server_seed(inputs.server_seed),
            client_seed=inputs.client_seed,
            nonce=inputs.nonce,
            params=params,
            recorded=generated["outcome"],
            expected_proof=generated["proof"],
            payout_context={
                "formula": "horse", "wager": 10, "multiplier": 7.68,
                "bet": {"type": "win", "horses": [tampered_loser]}, "precision": 2,
            },
            recorded_payout=76.8,
        )
        self.assertFalse(invalid.verified)
        self.assertFalse(invalid.payout_matches)


if __name__ == "__main__":
    unittest.main()

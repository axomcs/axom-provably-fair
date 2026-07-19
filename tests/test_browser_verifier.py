import json
from pathlib import Path
import shutil
import subprocess
import unittest

from provably_fair import (
    FairInputs,
    GAME_SCHEMAS,
    LEGACY_FAIRNESS_VERSION,
    generate_outcome,
)


ROOT = Path(__file__).parents[1]


@unittest.skipUnless(shutil.which("node"), "Node.js is required for browser parity")
class BrowserVerifierTests(unittest.TestCase):
    def test_browser_mapping_registry_matches_python(self):
        javascript = r"""
global.window = globalThis;
require('./provably_fair_webapp/verifier.js');
(async () => {
  const results = {};
  for (const [game, schema] of Object.entries(ProvablyFair.GAME_SCHEMAS)) {
    results[game] = await ProvablyFair.generateOutcome(game, {
      server_seed: '0123456789abcdef'.repeat(4),
      client_seed: 'player-selected-seed', nonce: 42, cursor: 0,
      fairness_version: 'pf-v1'
    }, schema.params);
  }
  for (const game of ['wheel', 'revolver', 'crash']) {
    results[game + '_legacy'] = await ProvablyFair.generateOutcome(game, {
      server_seed: '0123456789abcdef'.repeat(4),
      client_seed: 'player-selected-seed', nonce: 42, cursor: 0,
      fairness_version: 'hmac-sha256-v1'
    }, ProvablyFair.GAME_SCHEMAS[game].params, game + '-legacy-v1');
  }
  process.stdout.write(JSON.stringify(results));
})().catch(error => { console.error(error); process.exit(1); });
"""
        completed = subprocess.run(
            ["node", "-e", javascript], cwd=ROOT, check=True,
            text=True, capture_output=True,
        )
        browser = json.loads(completed.stdout)
        inputs = FairInputs(
            "0123456789abcdef" * 4, "player-selected-seed", 42,
        )
        for game, schema in GAME_SCHEMAS.items():
            with self.subTest(game=game):
                self.assertEqual(
                    browser[game],
                    generate_outcome(game, inputs, dict(schema["params"])),
                )
        legacy_inputs = FairInputs(
            inputs.server_seed, inputs.client_seed, inputs.nonce, 0, "",
            LEGACY_FAIRNESS_VERSION,
        )
        for game in ("wheel", "revolver", "crash"):
            with self.subTest(game=f"{game}-legacy"):
                self.assertEqual(
                    browser[f"{game}_legacy"],
                    generate_outcome(
                        game, legacy_inputs, dict(GAME_SCHEMAS[game]["params"]),
                        f"{game}-legacy-v1",
                    ),
                )

    def test_verifier_has_no_backend_calculation_dependency(self):
        source = (ROOT / "provably_fair_webapp" / "verifier.js").read_text()
        page = (ROOT / "provably_fair_webapp" / "index.html").read_text()
        self.assertNotIn("fetch(", source)
        self.assertNotIn("fetch(", page)
        self.assertNotIn("/api/provably-fair/verify", page)
        self.assertIn("ProvablyFair.verifyRecord", page)
        self.assertIn('id="proofBootstrap"', page)
        self.assertIn("shortProofUrl", page)
        self.assertIn('new URL(`/v/${encodeURIComponent', page)
        self.assertNotIn("new URL(location.href)", page)
        self.assertIn("Mines · replayed board", page)
        self.assertIn("Tower · replayed board", page)
        self.assertIn("Download verifier source", page)
        self.assertIn("https://github.com/axomcs/axom-provably-fair", page)

    def test_horse_browser_verifies_seed_binding_result_and_payout(self):
        javascript = r"""
global.window = globalThis;
require('./provably_fair_webapp/verifier.js');
(async () => {
  const components = [
    {bet_index:0,user_id:100,client_seed:'alice-seed'},
    {bet_index:1,user_id:200,client_seed:'बॉब-seed'}
  ];
  const canonical = components.map((entry, index) => `${index}:${entry.user_id}:${Array.from(new TextEncoder().encode(entry.client_seed), value => value.toString(16).padStart(2, '0')).join('')}`).join('\n');
  const componentHash = Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(canonical))), value => value.toString(16).padStart(2, '0')).join('');
  const serverSeed = '0123456789abcdef'.repeat(4), clientSeed = `horse:RACE42:${componentHash}`;
  const generated = await ProvablyFair.generateOutcome('horse', {server_seed:serverSeed,client_seed:clientSeed,nonce:99,cursor:0,fairness_version:'pf-v1'}, {horse_count:8,client_seed_components:components});
  const serverHash = Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(serverSeed))), value => value.toString(16).padStart(2, '0')).join('');
  const winner = generated.outcome.finish_order[0];
  const record = {game:'horse',server_seed:serverSeed,server_seed_hash:serverHash,client_seed:clientSeed,nonce:99,cursor:0,fairness_version:'pf-v1',game_algorithm_version:'horse-v2',params:{horse_count:8,client_seed_components:components},recorded_result:generated.outcome,generated_random_values:{proof:generated.proof},bet_amount:10,payout:76.8,payout_context:{formula:'horse',wager:10,multiplier:7.68,bet:{type:'win',horses:[winner]},precision:2}};
  const valid = await ProvablyFair.verifyRecord(record);
  record.payout_context.bet.horses = [winner === 1 ? 2 : 1];
  const tampered = await ProvablyFair.verifyRecord(record);
  process.stdout.write(JSON.stringify({valid,tampered}));
})().catch(error => { console.error(error); process.exit(1); });
"""
        completed = subprocess.run(
            ["node", "-e", javascript], cwd=ROOT, check=True,
            text=True, capture_output=True,
        )
        result = json.loads(completed.stdout)
        self.assertTrue(result["valid"]["verified"])
        self.assertFalse(result["tampered"]["verified"])
        self.assertFalse(result["tampered"]["payout_matches"])

    def test_blackjack_browser_replays_split_double_insurance_and_dealer(self):
        javascript = r"""
global.window = globalThis;
require('./provably_fair_webapp/verifier.js');
const splitShoe = ['8S','6S','8H','10S','3S','2S','10H','9H','5H'];
const splitContract = {
  actions: ['deal','split','double','hit','stand'], initial_bet: 10,
  rules: {dealer_hits_soft_17:false, dealer_peeks:true, blackjack_payout:'1.5', insurance_payout:'2', split_aces_one_card:true},
  final_dealer: ['6S','10S','5H'],
  final_hands: [
    {cards:['8S','3S','10H'],bet:20,status:'push',result:'push',payout:20,after_split:true,split_aces:false},
    {cards:['8H','2S','9H'],bet:10,status:'lost',result:'loss',payout:0,after_split:true,split_aces:false}
  ],
  total_wager:30, insurance_bet:0, insurance_payout:0, total_payout:20, outcome:'LOSS'
};
const insuranceShoe = ['10S','AS','9H','KS'];
const insuranceContract = {
  actions:['deal','insurance'], initial_bet:10,
  rules:{dealer_peeks:true,blackjack_payout:'1.5',insurance_payout:'2'},
  final_dealer:['AS','KS'],
  final_hands:[{cards:['10S','9H'],bet:10,status:'lost',result:'loss',payout:0,after_split:false,split_aces:false}],
  total_wager:15,insurance_bet:5,insurance_payout:15,total_payout:15,outcome:'DEALER_BLACKJACK'
};
const split = ProvablyFair.replayBlackjack(splitShoe, splitContract);
const insurance = ProvablyFair.replayBlackjack(insuranceShoe, insuranceContract);
const telegramShoe = ['5H','9H','2S','10H','3S','10S','6S','8H','8S'];
const telegramContract = {
  engine:'telegram-v1',precision:6,actions:['deal','split','double','hit','stand'],initial_bet:10,
  rules:{dealer_hits_soft_17:true,dealer_peeks:false,blackjack_payout:1.5,insurance_payout:2,split_aces_one_card:true},
  final_dealer:['6S','10S','5H'],
  final_hands:[
    {cards:['8S','3S','10H'],bet:20,status:'push',result:'push',payout:20,after_split:true,split_aces:false},
    {cards:['8H','2S','9H'],bet:10,status:'lost',result:'loss',payout:0,after_split:true,split_aces:false}
  ],total_wager:30,insurance_bet:0,insurance_payout:0,total_payout:20,outcome:'LOSS'
};
const telegram = ProvablyFair.replayBlackjack(telegramShoe, telegramContract);
splitContract.final_dealer = ['6S','10S'];
const tampered = ProvablyFair.replayBlackjack(splitShoe, splitContract);
process.stdout.write(JSON.stringify({split,insurance,telegram,tampered}));
"""
        completed = subprocess.run(
            ["node", "-e", javascript], cwd=ROOT, check=True,
            text=True, capture_output=True,
        )
        result = json.loads(completed.stdout)
        self.assertTrue(result["split"]["matches"])
        self.assertTrue(result["insurance"]["matches"])
        self.assertTrue(result["telegram"]["matches"])
        self.assertFalse(result["tampered"]["matches"])


if __name__ == "__main__":
    unittest.main()

# Axom Casino Provably Fair Specification

Status: public protocol specification

Current fairness version: `pf-v1`
Reference implementations: `provably_fair/random.py`, `provably_fair/mappings.py`, and the downloadable browser implementation `provably_fair_webapp/verifier.js`

## 1. Commitment and seed lifecycle

The server generates a 32-byte value with the operating system CSPRNG and publishes:

```text
server_seed_hash = lowercase_hex(SHA-256(UTF8(server_seed)))
```

Only the hash is public while the seed is active. Active seeds are stored in an AES-256-GCM envelope and are never returned by an API or written to application logs. A player may view, edit, randomize, or reset the client seed; such a change applies only to later bets and does not change the already-published server commitment.

After a completed bet or seed rotation, the old server seed is revealed and a fresh 256-bit seed and commitment replace it. Nonces are database-reserved monotonically and are never reset during rotation.

## 2. `pf-v1` byte stream

All strings use UTF-8 without a byte-order mark. For each cursor value `c`, calculate:

```text
message = "pf-v1\n" +
          "game=" + normalized_game_id + "\n" +
          "client_seed=" + client_seed + "\n" +
          "nonce=" + base10_nonce + "\n" +
          "cursor=" + base10_c

block = HMAC-SHA256(key=UTF8(server_seed), message=UTF8(message))
```

The 32 bytes of `block` are appended in digest order. The next block uses `c + 1`. A bet stores its starting cursor, normally zero. Consumers read bytes sequentially from the concatenated blocks. The displayed `proof` is the lowercase hexadecimal first block at the bet's starting cursor.

The `game` line is mandatory domain separation. Consequently identical server seed, client seed, nonce, and cursor inputs produce different streams for different games.

### Unsigned integers

`uint(n)` consumes `n` bytes and interprets them as one unsigned big-endian integer.

### Unbiased bounded integers

To choose uniformly in `[0, upper)`:

1. Set `n = max(1, ceil(bit_length(upper - 1) / 8))`.
2. Set `space = 2^(8n)` and `ceiling = space - (space mod upper)`.
3. Read `candidate = uint(n)`.
4. Reject and repeat when `candidate >= ceiling`.
5. Return `candidate mod upper`.

The modulo is applied only after rejection has made every remaining residue equally likely. No game uses a raw modulo shortcut.

### Uniform float

Consume seven bytes, interpret them as a 56-bit unsigned integer, discard the low four bits, and divide the remaining 52-bit integer by `2^52`. The result is uniform over the representable grid in `[0, 1)`.

### Shuffle and sample

Fisher-Yates iterates from the last array index down to one and swaps index `i` with `randbelow(i + 1)`. Sampling performs a partial Fisher-Yates: at output position `i`, swap it with `i + randbelow(length - i)`, then return the requested prefix.

## 3. Versioning and historical records

Every bet stores both `fairness_version` and `game_algorithm_version`. Mapping changes create a new immutable version key; they never edit an old mapping. Current versions are:

| Game | Version |
|---|---|
| Roulette | `roulette-v2` |
| Coin Flip | `coinflip-v2` |
| Blackjack | `blackjack-v3` |
| Limbo | `limbo-v2` |
| Wheel | `wheel-v2` |
| Revolver | `revolver-v2` |
| Plinko | `plinko-v2` |
| Crash | `crash-v3` |
| Dice | `dice-v2` |
| Hi-Lo | `hilo-v2` |
| Mines | `mines-v2` |
| Keno | `keno-v2` |
| Ladder | `ladder-v2` |
| Money Tree | `money-tree-v2` |
| Tower | `tower-v2` |
| Jackpot | `jackpot-v2` |
| Horse Race | `horse-v2` |

Historical `hmac-sha256-v1` records use `HMAC-SHA256(server_seed, UTF8(client_seed + ":" + nonce + ":" + cursor))` and the corresponding `<game>-legacy-v1` mapping. The legacy Wheel, Revolver, and Crash mappings are preserved separately because those formulas changed. The browser verifier selects the versions stored with the bet.

## 4. Game mappings

Unless stated otherwise, a mapping itself has no house edge; the separately published payout table creates any edge. The exact table or multiplier used by a bet is stored in its parameters and payout context.

### Roulette — `roulette-v2`

Choose `number = randbelow(37)`. This is European single-zero Roulette: 0 is green. Red numbers are `{1,3,5,7,9,12,14,16,18,19,21,23,25,27,30,32,34,36}` and every other non-zero number is black. Each number has probability `1/37`. Standard straight-up payouts have a `1/37` hit probability and 36x gross return, for a house edge of `1/37` (about 2.7027%). American double-zero is not supported by this mapping.

### Coin Flip — `coinflip-v2`

Choose `roll = randbelow(2)`. Zero is heads and one is tails. Both probabilities are exactly 1/2. The current gross win multiplier is stored with each bet; a 1.9x gross return has a 5% house edge.

### Blackjack — `blackjack-v3`

Build each deck in this exact order: suits `S,H,D,C`; within each suit ranks `A,2,3,4,5,6,7,8,9,10,J,Q,K`. Concatenate `decks` copies, then apply the shared Fisher-Yates shuffle. Cards are normally drawn from index zero. The initial order is player, dealer up-card, player, dealer hole-card. Historical Telegram-engine contracts declare `engine: "telegram-v1"` and `draw_from: "end"`; for those records cards are popped from the end of the shuffled shoe and the initial deal order is player, player, dealer up-card, dealer hole-card (`PPDD`). The stored engine and draw direction are versioned replay inputs, never verifier guesses.

The stored replay contract contains the ordered player actions and the complete rule object. `hit` draws one card. `stand` advances to the next hand. `double` adds the current hand bet, doubles that hand's bet, draws exactly one card, and stands. `split` replaces the hand with left and right hands and draws one card to the left followed by one to the right. Split aces receive one card when `split_aces_one_card` is true. Insurance is half the initial wager and its gross return is `1 + insurance_payout` when the dealer has Blackjack.

An ace begins at 11 and is reduced by 10 as often as necessary to avoid a bust. A hand is soft when at least one ace still counts as 11. The dealer hits below 17 and also hits soft 17 only when `dealer_hits_soft_17` is true. A natural is a two-card 21 not created after a split. A natural gross return is `1 + blackjack_payout` (normally 2.5x), an ordinary win is 2x, a push is 1x, and a loss is 0. All monetary values use decimal round-half-up to two places. The verifier recreates the shoe, executes every stored action, runs the dealer, and compares every final card, hand wager, hand result, insurance value, total wager, outcome, and payout.

### Limbo — `limbo-v2`

Read uniform `roll`. With published `house_edge` factor `e` and `max_multiplier` `M`:

```text
multiplier = M                                      if roll == 0
multiplier = min(M, max(1, floor((e / roll)*100)/100)) otherwise
```

The minimum is 1.00x, precision is two decimal places rounded downward, and the default maximum is recorded per product (1,000x in the main Limbo game). For target `t` below the cap, the approximate win probability is `e/t`, so the expected gross return is `e` and the house edge is `1-e` (4% when `e=0.96`).

### Wheel — `wheel-v2`

The ordered `segments` array is public. Choose `segment_index = randbelow(number_of_segments)` and return that segment's prize multiplier. Every array position has equal weight; repeated prize values create larger aggregate prize weights. `segment_number` is the one-based display index. The edge is the difference between 1 and the arithmetic mean of all segment multipliers.

### Revolver — `revolver-v2`

Choose `chamber_index = randbelow(chambers)`. Chambers are ordered from zero for calculation and shown as one through `chambers`. The first `chambers - bullets` are safe and the remaining chambers contain bullets. A spin is a fresh independent selection; there is no hidden rotation state or reload state between bets. Survival probability is `(chambers-bullets)/chambers`. Any payout edge follows from the recorded gross multiplier.

### Plinko — `plinko-v2`

For each of `rows`, choose `randbelow(2)`: zero means left and one means right. The full ordered bit array is the peg path. `slot_index = sum(path)`, so valid slots are zero through `rows`. If a `rows + 1` multiplier array is supplied, the prize is `multipliers[slot_index]`. The exact payout is wager times that multiplier under the stored rounding rule. The probability of slot `k` is `C(rows,k)/2^rows`; the payout-table house edge is `1 - sum(P(k)*multiplier[k])`.

### Crash — `crash-v3`

With published divisor `d` (normally 33), first choose `instant_roll = randbelow(d)`. Next consume seven bytes, discard four low bits, and call the resulting 52-bit integer `h`; let `E=2^52`.

```text
instant_crash = (instant_roll == 0)
multiplier = 1.00                                      if instant_crash
multiplier = max(1.00, floor((100*E-h)/(E-h))/100)    otherwise
```

Thus rounding is downward to two decimals, the minimum is 1.00x, and the implementation's maximum is the largest finite two-decimal result produced by the 52-bit formula. The instant-crash component has exact probability `1/d`; with `d=33` it supplies the approximately 3.03% edge. A cashout wins only if its target is reached before the stored crash multiplier.

### Dice — `dice-v2`

For each die choose `1 + randbelow(sides)`. Store the ordered rolls and their sum. Every face is uniform. Bet-specific choice and payout tables determine the edge.

This mapping is reserved for products whose dice are generated by the Axom byte stream. Telegram Dice Rush, Seven Up, and Triple Dice use Telegram's native dice result instead; those products deliberately do not create Axom provably-fair records or verification links.

### Hi-Lo — `hilo-v2`

Choose `rank_index = randbelow(13)`, then `suit_index = randbelow(4)`. Ranks and suits use the Blackjack order above. Comparison rules and multipliers are bet-specific.

### Mines — `mines-v2`

For a `grid_size × grid_size` grid, partially Fisher-Yates sample `mines` distinct zero-based tile indexes, then sort them ascending for display. Every mine subset of that size is equally likely. Cashout multipliers and their edge are stored by the Mines product.

### Keno — `keno-v2`

Partially Fisher-Yates sample `draws` distinct integers from one through `pool_size`, then sort them ascending. Every draw subset is equally likely. The selected-number payout table defines the edge.

### Ladder — `ladder-v2`

Choose one element uniformly from the published ordered `outcomes` array, normally `AC,AD,BC,BD`. Results `AC` and `BD` have four crossing rungs; `AD` and `BC` have three. The returned path contains one for each crossing. The selected choice multiplier is stored with the bet.

### Money Tree — `money-tree-v2`

Generate three independent six-sided dice with `1 + randbelow(6)` and store both ordered dice and sum. Choice and payout rules are stored with the bet.

### Tower — `tower-v2`

For every row choose one hidden snake column with `randbelow(columns)`. Store the ordered zero-based snake positions. Difficulty supplies the published row and column counts; the cashout schedule supplies the edge.

### Jackpot — `jackpot-v2`

Participants are ordered objects containing integer `user_id` and positive `tickets`. Publish `participants_csv` as comma-separated `user_id:tickets` entries and bind its SHA-256 digest into `client_seed = "jackpot:" + draw_id + ":" + digest`. Choose `target_ticket = randbelow(total_tickets)`. Walking participants in order, the winner is the first whose cumulative ticket count exceeds the target. Every ticket is exactly equiprobable.

### Horse Race — `horse-v2`

The eight numbered horses begin as the ordered array `[1,2,3,4,5,6,7,8]`, which is shuffled with the shared unbiased Fisher-Yates algorithm. The resulting array is the exact first-to-last finish order, so every one of the `8!` permutations is equiprobable.

For a multiplayer race, every accepted bet snapshots that player's current client seed. In acceptance order, publish each component as `bet_index:user_id:lowercase_hex(UTF8(client_seed))`, join the components with LF, and SHA-256 the result. The round input is `client_seed = "horse:" + round_id + ":" + component_hash`. This prevents the house from replacing or reordering player seed inputs after bets close. The server-seed commitment is created when the lobby opens, the round nonce is atomically reserved, and no post-bet seed search or rig path exists.

Winner, last-place, place, show, head-to-head, odd/even, low/high, forecast, and quinella bets are evaluated directly against the reproduced finish array. Gross multipliers are stored per bet; normal win/place/show/side-bet returns use a 4% edge, while forecast and quinella use their published variance-capped returns. Any payout cap applied at settlement is stored in that bet's payout context.

## 5. Immutable verification record

A completed record contains bet ID, round ID, normalized game, bet amount, currency, client seed, committed server-seed hash, revealed server seed, nonce, starting cursor, fairness and game versions, mapping parameters, generated proof and byte count, final recorded result, payout context, payout, reveal time, and completion time. Blackjack additionally stores its action/rule/final-state replay contract. Inserts use conflict-do-nothing semantics; an existing token is never updated.

The universal browser verifier reports four independent stages:

1. **Seed** — SHA-256 of the reveal equals the commitment.
2. **Randomness** — the locally generated first HMAC block equals the stored proof.
3. **Game** — the local mapping/replay equals the stored result.
4. **Payout** — the local payout calculation equals the stored payout.

Overall status is `VERIFIED` only when all four stages are present and true. The backend does not calculate any stage; it only returns stored data. The dependency-free JavaScript source is downloadable from `/provably-fair/verifier.js` and remains functional after the page and bet record have loaded, even if the browser disconnects.

/*
 * Axom Casino browser-side provably-fair verifier.
 *
 * This file is deliberately dependency-free.  It uses only Web Crypto and
 * performs every cryptographic, random-mapping, game, and payout calculation
 * in the browser.  The server is used only to download an immutable bet record.
 */
(function (root) {
  "use strict";

  const FAIRNESS_VERSION = "pf-v1";
  const LEGACY_FAIRNESS_VERSION = "hmac-sha256-v1";
  const encoder = new TextEncoder();
  const TWO_52 = 2 ** 52;
  const SUITS = ["S", "H", "D", "C"];
  const RANKS = ["A", "2", "3", "4", "5", "6", "7", "8", "9", "10", "J", "Q", "K"];
  const DEFAULT_WHEEL_SEGMENTS = [
    5, 0, 0.2, 0, 1.5, 0, 0.3, 3, 0, 0.5,
    0, 2, 0.2, 0, 0.8, 0, 4, 0, 1.5, 0,
  ];

  const GAME_SCHEMAS = {
    roulette: {label: "Roulette", params: {}},
    coinflip: {label: "Coin Flip", params: {}},
    blackjack: {label: "Blackjack", params: {decks: 6}},
    limbo: {label: "Limbo", params: {house_edge: 0.96, max_multiplier: 1000}},
    wheel: {label: "Wheel", params: {}},
    revolver: {label: "Revolver", params: {bullets: 1, chambers: 6}},
    plinko: {label: "Plinko", params: {rows: 12}},
    crash: {label: "Crash", params: {house_edge_divisor: 33}},
    dice: {label: "Dice", params: {count: 1, sides: 6}, externally_resolved: true},
    hilo: {label: "Hi-Lo", params: {}},
    mines: {label: "Mines", params: {grid_size: 5, mines: 3}},
    keno: {label: "Keno", params: {pool_size: 40, draws: 10}},
    ladder: {label: "Ladder", params: {}},
    money_tree: {label: "Money Tree", params: {}},
    tower: {label: "Tower", params: {rows: 9, columns: 3}},
    jackpot: {label: "Jackpot", params: {participants: [{user_id: 1, tickets: 1}]}},
    horse: {label: "Horse Race", params: {horse_count: 8}},
  };
  const GAME_VERSIONS = {
    roulette: "roulette-v2", coinflip: "coinflip-v2", blackjack: "blackjack-v3",
    limbo: "limbo-v2", wheel: "wheel-v2", revolver: "revolver-v2",
    plinko: "plinko-v2", crash: "crash-v3", dice: "dice-v2", hilo: "hilo-v2",
    mines: "mines-v2", keno: "keno-v2", ladder: "ladder-v2",
    money_tree: "money-tree-v2", tower: "tower-v2", jackpot: "jackpot-v2",
    horse: "horse-v2",
  };
  const ALIASES = {
    coin: "coinflip", coin_flip: "coinflip", "coin flip": "coinflip",
    "black jack": "blackjack", blackjack_split: "blackjack", "blackjack split": "blackjack",
    russian_roulette: "revolver", "russian roulette": "revolver",
    "hi-lo": "hilo", hi_lo: "hilo", "hi lo": "hilo",
    seven_up: "dice", "seven up": "dice", "money-tree": "money_tree",
    "money tree": "money_tree", "daily jackpot": "jackpot",
    horse_race: "horse", "horse race": "horse",
  };

  function normalizeGame(game) {
    if (typeof game !== "string" || !game.trim()) throw new Error("game is required");
    const raw = game.trim().toLowerCase();
    const key = raw.replaceAll("-", "_");
    const normalized = ALIASES[key] || ALIASES[raw] || key;
    if (!GAME_SCHEMAS[normalized]) throw new Error(`unsupported game: ${game}`);
    return normalized;
  }

  function bytesToHex(bytes) {
    return Array.from(bytes, value => value.toString(16).padStart(2, "0")).join("");
  }

  async function sha256Hex(value) {
    return bytesToHex(new Uint8Array(await crypto.subtle.digest("SHA-256", encoder.encode(value))));
  }

  function hmacMessage(inputs, cursor) {
    if (inputs.fairness_version === LEGACY_FAIRNESS_VERSION) {
      return `${inputs.client_seed}:${inputs.nonce}:${cursor}`;
    }
    if (inputs.fairness_version !== FAIRNESS_VERSION) {
      throw new Error(`unsupported fairness version: ${inputs.fairness_version}`);
    }
    return `${FAIRNESS_VERSION}\ngame=${inputs.game}\nclient_seed=${inputs.client_seed}\nnonce=${inputs.nonce}\ncursor=${cursor}`;
  }

  async function hmacBlock(inputs, cursor) {
    const key = await crypto.subtle.importKey(
      "raw", encoder.encode(inputs.server_seed), {name: "HMAC", hash: "SHA-256"}, false, ["sign"],
    );
    return new Uint8Array(await crypto.subtle.sign("HMAC", key, encoder.encode(hmacMessage(inputs, cursor))));
  }

  class FairRandom {
    constructor(inputs) {
      this.inputs = {...inputs};
      this.cursor = Number(inputs.cursor || 0);
      this.buffer = [];
      this.bytes_consumed = 0;
      this._proof = null;
      if (!Number.isSafeInteger(this.cursor) || this.cursor < 0) throw new Error("cursor must be a non-negative safe integer");
      if (!Number.isSafeInteger(Number(inputs.nonce)) || Number(inputs.nonce) < 0) throw new Error("nonce must be a non-negative safe integer");
    }

    async proof() {
      if (!this._proof) this._proof = bytesToHex(await hmacBlock(this.inputs, Number(this.inputs.cursor || 0)));
      return this._proof;
    }

    async randomBytes(length) {
      if (!Number.isSafeInteger(length) || length < 0) throw new Error("length must be a non-negative integer");
      while (this.buffer.length < length) {
        this.buffer.push(...await hmacBlock(this.inputs, this.cursor));
        this.cursor += 1;
      }
      this.bytes_consumed += length;
      return new Uint8Array(this.buffer.splice(0, length));
    }

    async uint(byteCount = 8) {
      if (!Number.isSafeInteger(byteCount) || byteCount < 1 || byteCount > 32) throw new Error("byteCount must be between 1 and 32");
      let value = 0n;
      for (const byte of await this.randomBytes(byteCount)) value = (value << 8n) | BigInt(byte);
      return value;
    }

    async randbelow(upper) {
      if (!Number.isSafeInteger(upper) || upper <= 0) throw new Error("upper must be a positive safe integer");
      const target = BigInt(upper);
      let byteCount = 1;
      while ((1n << BigInt(byteCount * 8)) < target) byteCount += 1;
      const space = 1n << BigInt(byteCount * 8);
      const ceiling = space - (space % target);
      while (true) {
        const candidate = await this.uint(byteCount);
        if (candidate < ceiling) return Number(candidate % target);
      }
    }

    async integer(minimum, maximum) {
      if (!Number.isSafeInteger(minimum) || !Number.isSafeInteger(maximum) || maximum < minimum) throw new Error("invalid integer range");
      return minimum + await this.randbelow(maximum - minimum + 1);
    }

    async randomFloat() {
      return Number((await this.uint(7)) >> 4n) / TWO_52;
    }

    async shuffle(values) {
      for (let index = values.length - 1; index > 0; index -= 1) {
        const other = await this.randbelow(index + 1);
        [values[index], values[other]] = [values[other], values[index]];
      }
      return values;
    }

    async sample(population, count) {
      const values = Array.from(population);
      if (!Number.isSafeInteger(count) || count < 0 || count > values.length) throw new Error("sample count is outside the population");
      for (let index = 0; index < count; index += 1) {
        const other = index + await this.randbelow(values.length - index);
        [values[index], values[other]] = [values[other], values[index]];
      }
      return values.slice(0, count);
    }
  }

  function boundedInt(params, key, fallback, minimum, maximum) {
    const value = Number(params[key] ?? fallback);
    if (!Number.isSafeInteger(value) || value < minimum || value > maximum) throw new Error(`${key} must be between ${minimum} and ${maximum}`);
    return value;
  }

  function makeRange(start, end) {
    return Array.from({length: end - start}, (_, index) => start + index);
  }

  async function mapOutcome(game, rng, params, version) {
    if (game === "roulette") {
      const number = await rng.randbelow(37);
      const red = new Set([1,3,5,7,9,12,14,16,18,19,21,23,25,27,30,32,34,36]);
      return {number, color: number === 0 ? "green" : red.has(number) ? "red" : "black"};
    }
    if (game === "coinflip") {
      const roll = await rng.randbelow(2);
      return {roll, result: roll === 0 ? "heads" : "tails"};
    }
    if (game === "wheel") {
      const segments = Array.from(params.segments || DEFAULT_WHEEL_SEGMENTS, Number);
      if (!segments.length || segments.length > 256) throw new Error("segments must contain 1 to 256 entries");
      if (version === "wheel-legacy-v1") {
        const random_value = await rng.randomFloat();
        const segment_index = Math.min(segments.length - 1, Math.trunc(random_value * segments.length));
        return {segment_index, segment_number: segment_index + 1, multiplier: segments[segment_index], random_value};
      }
      const segment_index = await rng.randbelow(segments.length);
      return {segment_index, segment_number: segment_index + 1, multiplier: segments[segment_index], uniform_index: segment_index};
    }
    if (game === "revolver") {
      const chambers = boundedInt(params, "chambers", 6, 2, 64);
      const bullets = boundedInt(params, "bullets", 1, 1, chambers - 1);
      let chamber_index;
      if (version === "revolver-legacy-v1") {
        chamber_index = Number(((await rng.uint(8)) * BigInt(chambers)) / (1n << 64n));
      } else {
        chamber_index = await rng.randbelow(chambers);
      }
      const safe = chamber_index < chambers - bullets;
      return {chamber_index, chamber_number: chamber_index + 1, bullets, safe, result: safe ? "survived" : "hit"};
    }
    if (game === "plinko") {
      const rows = boundedInt(params, "rows", 12, 1, 64);
      const path = [];
      for (let index = 0; index < rows; index += 1) path.push(await rng.randbelow(2));
      const slot_index = path.reduce((sum, value) => sum + value, 0);
      const result = {path, slot_index};
      if (params.multipliers != null) {
        if (!Array.isArray(params.multipliers) || params.multipliers.length !== rows + 1) throw new Error("multipliers must contain rows + 1 entries");
        result.multiplier = Number(params.multipliers[slot_index]);
      }
      return result;
    }
    if (game === "limbo") {
      const house_edge = Number(params.house_edge ?? 0.96);
      const max_multiplier = Number(params.max_multiplier ?? 1000000);
      if (!(house_edge > 0 && house_edge <= 1) || max_multiplier < 1) throw new Error("invalid Limbo parameters");
      const roll = await rng.randomFloat();
      const multiplier = roll === 0 ? max_multiplier : Math.min(max_multiplier, Math.max(1, Math.floor((house_edge / roll) * 100) / 100));
      return {roll, multiplier};
    }
    if (game === "crash") {
      const divisor = boundedInt(params, "house_edge_divisor", 33, 2, 1000000);
      let instant_roll = null;
      let value_52;
      let instant_crash;
      if (version === "crash-legacy-v1") {
        value_52 = Number((await rng.uint(7)) >> 4n);
        instant_crash = value_52 % divisor === 0;
      } else {
        instant_roll = await rng.randbelow(divisor);
        value_52 = Number((await rng.uint(7)) >> 4n);
        instant_crash = instant_roll === 0;
      }
      const raw = (100 * TWO_52 - value_52) / (TWO_52 - value_52);
      const multiplier = instant_crash ? 1 : Math.max(1, Math.floor(raw) / 100);
      return instant_roll == null
        ? {value_52, instant_crash, multiplier}
        : {value_52, instant_roll, instant_crash, multiplier};
    }
    if (game === "blackjack") {
      const decks = boundedInt(params, "decks", 6, 1, 12);
      const shoe_index = boundedInt(params, "shoe_index", 0, 0, 15);
      let shoe = [];
      for (let pass = 0; pass <= shoe_index; pass += 1) {
        shoe = [];
        for (let deck = 0; deck < decks; deck += 1) for (const suit of SUITS) for (const rank of RANKS) shoe.push(`${rank}${suit}`);
        await rng.shuffle(shoe);
      }
      const preview = shoe.slice();
      let initial_player, initial_dealer;
      if (String(params.draw_from || "start").toLowerCase() === "end") {
        initial_player = [preview.pop(), preview.pop()];
        initial_dealer = [preview.pop(), preview.pop()];
      } else {
        initial_player = [preview[0], preview[2]];
        initial_dealer = [preview[1], preview[3]];
      }
      return {decks, shoe_index, shoe, initial_player, initial_dealer};
    }
    if (game === "dice") {
      const count = boundedInt(params, "count", 1, 1, 100);
      const sides = boundedInt(params, "sides", 6, 2, 1000000);
      const rolls = [];
      for (let index = 0; index < count; index += 1) rolls.push(await rng.integer(1, sides));
      return {rolls, total: rolls.reduce((sum, value) => sum + value, 0)};
    }
    if (game === "hilo") {
      const rank_index = await rng.randbelow(13);
      const suit_index = await rng.randbelow(4);
      return {rank_index, rank: RANKS[rank_index], suit: SUITS[suit_index]};
    }
    if (game === "mines") {
      const grid_size = boundedInt(params, "grid_size", 5, 2, 20);
      const mine_count = boundedInt(params, "mines", 3, 1, grid_size * grid_size - 1);
      const mine_positions = (await rng.sample(makeRange(0, grid_size * grid_size), mine_count)).sort((a, b) => a - b);
      return {grid_size, mine_count, mine_positions};
    }
    if (game === "keno") {
      const pool_size = boundedInt(params, "pool_size", 40, 2, 1000);
      const draws = boundedInt(params, "draws", 10, 1, pool_size - 1);
      const numbers = (await rng.sample(makeRange(1, pool_size + 1), draws)).sort((a, b) => a - b);
      return {numbers};
    }
    if (game === "ladder") {
      const outcomes = params.outcomes || ["AC", "AD", "BC", "BD"];
      if (!Array.isArray(outcomes) || !outcomes.length) throw new Error("outcomes must be a non-empty list");
      const result = String(outcomes[await rng.randbelow(outcomes.length)]);
      return {result, path: Array(result === "AC" || result === "BD" ? 4 : 3).fill(1)};
    }
    if (game === "money_tree") {
      const dice = [];
      for (let index = 0; index < 3; index += 1) dice.push(await rng.integer(1, 6));
      return {dice, sum: dice.reduce((total, value) => total + value, 0)};
    }
    if (game === "tower") {
      const rows = boundedInt(params, "rows", 9, 1, 64);
      const columns = boundedInt(params, "columns", 3, 2, 64);
      const snake_positions = [];
      for (let index = 0; index < rows; index += 1) snake_positions.push(await rng.randbelow(columns));
      return {snake_positions};
    }
    if (game === "jackpot") {
      if (!Array.isArray(params.participants) || !params.participants.length) throw new Error("participants must be a non-empty list");
      const participants = params.participants.map(entry => ({user_id: Number(entry.user_id), tickets: Number(entry.tickets)}));
      if (participants.some(entry => !Number.isSafeInteger(entry.user_id) || !Number.isSafeInteger(entry.tickets) || entry.tickets <= 0)) throw new Error("invalid jackpot participant");
      const participantText = participants.map(entry => `${entry.user_id}:${entry.tickets}`).join(",");
      const participantHash = await sha256Hex(participantText);
      if (rng.inputs.client_seed.startsWith("jackpot:") && !rng.inputs.client_seed.endsWith(`:${participantHash}`)) throw new Error("jackpot client seed does not bind the participant list");
      const total_tickets = participants.reduce((sum, entry) => sum + entry.tickets, 0);
      const target_ticket = await rng.randbelow(total_tickets);
      let cumulative = 0;
      for (let winner_index = 0; winner_index < participants.length; winner_index += 1) {
        cumulative += participants[winner_index].tickets;
        if (target_ticket < cumulative) return {winner_id: participants[winner_index].user_id, winner_index, target_ticket, total_tickets};
      }
    }
    if (game === "horse") {
      const horse_count = boundedInt(params, "horse_count", 8, 2, 32);
      if (params.client_seed_components != null) {
        if (!Array.isArray(params.client_seed_components) || !params.client_seed_components.length) throw new Error("client_seed_components must be a non-empty list");
        const canonical = params.client_seed_components.map((entry, index) => {
          const betIndex = Number(entry.bet_index), userId = Number(entry.user_id);
          if (!Number.isSafeInteger(betIndex) || betIndex !== index || !Number.isSafeInteger(userId) || entry.client_seed == null) throw new Error("invalid horse client seed component");
          return `${betIndex}:${userId}:${bytesToHex(encoder.encode(String(entry.client_seed)))}`;
        }).join("\n");
        const componentHash = await sha256Hex(canonical);
        if (!rng.inputs.client_seed.startsWith("horse:") || !rng.inputs.client_seed.endsWith(`:${componentHash}`)) throw new Error("horse client_seed does not bind the accepted bet seeds");
      }
      const finish_order = makeRange(1, horse_count + 1);
      await rng.shuffle(finish_order);
      return {horse_count, finish_order};
    }
    throw new Error(`no mapping for ${game}`);
  }

  async function generateOutcome(game, inputs, params = {}, gameAlgorithmVersion = null) {
    const normalized = normalizeGame(game);
    const fairnessVersion = inputs.fairness_version || inputs.algorithm || FAIRNESS_VERSION;
    const version = gameAlgorithmVersion || (fairnessVersion === LEGACY_FAIRNESS_VERSION ? `${normalized}-legacy-v1` : GAME_VERSIONS[normalized]);
    const current = GAME_VERSIONS[normalized];
    if (version !== current && version !== `${normalized}-legacy-v1`) throw new Error(`unsupported ${normalized} algorithm version: ${version}`);
    const rng = new FairRandom({...inputs, game: normalized, fairness_version: fairnessVersion});
    const outcome = await mapOutcome(normalized, rng, params || {}, version);
    return {
      game: normalized, algorithm: fairnessVersion, fairness_version: fairnessVersion,
      game_algorithm_version: version, cursor: Number(inputs.cursor || 0),
      proof: await rng.proof(), bytes_consumed: rng.bytes_consumed, outcome,
    };
  }

  function partialEqual(generated, recorded) {
    if (recorded && typeof recorded === "object" && !Array.isArray(recorded)) {
      if (!generated || typeof generated !== "object" || Array.isArray(generated)) return false;
      return Object.keys(recorded).every(key => Object.prototype.hasOwnProperty.call(generated, key) && partialEqual(generated[key], recorded[key]));
    }
    if (Array.isArray(recorded)) return Array.isArray(generated) && generated.length === recorded.length && recorded.every((value, index) => partialEqual(generated[index], value));
    if (typeof recorded === "number" || typeof generated === "number") return Number.isFinite(Number(recorded)) && Math.abs(Number(generated) - Number(recorded)) <= 1e-12;
    return generated === recorded;
  }

  function cardRank(card) { return String(card).slice(0, -1); }
  function cardValue(card) { const rank = cardRank(card); return rank === "A" ? 11 : ["10", "J", "Q", "K"].includes(rank) ? 10 : Number(rank); }
  function handValue(cards) { let total = cards.reduce((sum, card) => sum + cardValue(card), 0); let aces = cards.filter(card => cardRank(card) === "A").length; while (total > 21 && aces) { total -= 10; aces -= 1; } return total; }
  function isSoft(cards) { const rawAces = cards.filter(card => cardRank(card) === "A").length; let aces = rawAces; let total = cards.reduce((sum, card) => sum + cardValue(card), 0); let reductions = 0; while (total > 21 && aces) { total -= 10; aces -= 1; reductions += 1; } return total <= 21 && rawAces - reductions > 0; }
  function isBlackjack(cards, afterSplit = false) { return !afterSplit && cards.length === 2 && handValue(cards) === 21; }
  function money(value, precision = 2) { const factor = 10 ** precision; return Math.round((Number(value) + Number.EPSILON) * factor) / factor; }

  function replayBlackjack(shoe, contract) {
    const errors = [];
    const rules = {
      blackjack_payout: 1.5, insurance_payout: 2, dealer_hits_soft_17: false,
      dealer_peeks: true, split_aces_one_card: true,
      ...((contract.rules || contract.game_config?.rules) || {}),
    };
    const telegramEngine = contract.engine === "telegram-v1";
    const precision = Number(contract.precision ?? 2);
    const cash = value => money(value, precision);
    const deck = shoe.slice();
    const draw = () => { if (!deck.length) throw new Error("Blackjack shoe exhausted"); return telegramEngine ? deck.pop() : deck.shift(); };
    const initialBet = cash(contract.initial_bet);
    const state = {
      dealer: [], hands: [{cards: [], bet: initialBet, status: "playing", result: null, payout: 0, after_split: false}],
      active: 0, total_wager: initialBet, insurance_bet: 0, insurance_payout: 0,
      total_payout: 0, outcome: null, complete: false,
    };
    if (telegramEngine) {
      state.hands[0].cards.push(draw(), draw()); state.dealer.push(draw(), draw());
    } else {
      state.hands[0].cards.push(draw()); state.dealer.push(draw()); state.hands[0].cards.push(draw()); state.dealer.push(draw());
    }
    const dealerBlackjack = () => isBlackjack(state.dealer);
    const settle = () => {
      while (state.hands.some(hand => handValue(hand.cards) <= 21) && !dealerBlackjack() && (handValue(state.dealer) < 17 || (handValue(state.dealer) === 17 && Boolean(rules.dealer_hits_soft_17) && isSoft(state.dealer)))) state.dealer.push(draw());
      let payout = 0;
      for (const hand of state.hands) {
        const player = handValue(hand.cards), dealer = handValue(state.dealer);
        if (player > 21) { hand.result = "bust"; hand.status = "busted"; hand.payout = 0; }
        else if (dealerBlackjack()) { hand.result = "loss"; hand.status = "lost"; hand.payout = 0; }
        else if (dealer > 21 || player > dealer) { hand.result = "win"; hand.status = "won"; hand.payout = cash(hand.bet * 2); }
        else if (player === dealer) { hand.result = "push"; hand.status = "push"; hand.payout = cash(hand.bet); }
        else { hand.result = "loss"; hand.status = "lost"; hand.payout = 0; }
        payout += hand.payout;
      }
      if (dealerBlackjack() && state.insurance_bet > 0) state.insurance_payout = cash(state.insurance_bet * (1 + Number(rules.insurance_payout)));
      state.total_payout = cash(payout + state.insurance_payout);
      const net = cash(state.total_payout - state.total_wager);
      state.outcome = dealerBlackjack() ? "DEALER_BLACKJACK" : net > 0 ? "WIN" : net < 0 ? "LOSS" : "PUSH";
      state.complete = true;
    };
    const settleNaturals = () => {
      const playerNatural = isBlackjack(state.hands[0].cards, state.hands[0].after_split);
      const dealerNatural = dealerBlackjack();
      const hand = state.hands[0];
      if (playerNatural && dealerNatural) { hand.result = "push"; hand.status = "push"; hand.payout = hand.bet; state.outcome = state.insurance_bet > 0 ? "WIN" : "PUSH"; }
      else if (playerNatural) { hand.result = "blackjack"; hand.status = "blackjack"; hand.payout = cash(hand.bet * (1 + Number(rules.blackjack_payout))); state.outcome = "BLACKJACK"; }
      else { hand.result = "loss"; hand.status = "lost"; hand.payout = 0; state.outcome = "DEALER_BLACKJACK"; }
      if (dealerNatural && state.insurance_bet > 0) state.insurance_payout = cash(state.insurance_bet * (1 + Number(rules.insurance_payout)));
      state.total_payout = cash(hand.payout + state.insurance_payout); state.complete = true;
    };
    const advance = () => {
      for (let index = state.active + 1; index < state.hands.length; index += 1) if (state.hands[index].status === "playing") { state.active = index; if (telegramEngine && state.hands[index].cards.length === 1) state.hands[index].cards.push(draw()); return; }
      settle();
    };
    const actions = (contract.actions || contract.action_log || []).map(item => typeof item === "string" ? item : item.action).filter(Boolean);
    let phase = cardRank(state.dealer[0]) === "A" ? "insurance" : "player";
    if (telegramEngine && isBlackjack(state.hands[0].cards)) settleNaturals();
    else if (phase === "player" && ((Boolean(rules.dealer_peeks) && ["10", "J", "Q", "K"].includes(cardRank(state.dealer[0])) && dealerBlackjack()) || isBlackjack(state.hands[0].cards))) settleNaturals();
    for (const action of actions.filter(value => value !== "deal")) {
      if (state.complete) { errors.push(`action ${action} occurred after settlement`); break; }
      if (action === "insurance" || action === "no_insurance") {
        if (phase !== "insurance") { errors.push(`unexpected ${action}`); break; }
        if (action === "insurance") { state.insurance_bet = cash(initialBet / 2); state.total_wager = cash(state.total_wager + state.insurance_bet); }
        if (((telegramEngine || Boolean(rules.dealer_peeks)) && dealerBlackjack()) || isBlackjack(state.hands[0].cards)) settleNaturals(); else phase = "player";
        continue;
      }
      if (phase !== "player") { errors.push(`player action ${action} before insurance decision`); break; }
      const hand = state.hands[state.active];
      if (!hand || hand.status !== "playing") { errors.push(`invalid ${action} action`); break; }
      if (action === "hit") {
        hand.cards.push(draw());
        if (handValue(hand.cards) > 21) { hand.status = "busted"; hand.result = "bust"; advance(); }
        else if (handValue(hand.cards) === 21) { hand.status = "stood"; advance(); }
      } else if (action === "stand") { hand.status = "stood"; advance(); }
      else if (action === "double") { state.total_wager = cash(state.total_wager + hand.bet); hand.bet = cash(hand.bet * 2); hand.cards.push(draw()); hand.status = handValue(hand.cards) > 21 ? "busted" : "stood"; if (hand.status === "busted") hand.result = "bust"; advance(); }
      else if (action === "split") {
        if (hand.cards.length !== 2) { errors.push("invalid split action"); break; }
        const splitAces = cardRank(hand.cards[0]) === "A" && cardRank(hand.cards[1]) === "A";
        const left = {cards: [hand.cards[0], draw()], bet: hand.bet, status: "playing", result: null, payout: 0, after_split: true, split_aces: splitAces};
        const right = {cards: [hand.cards[1]], bet: hand.bet, status: "playing", result: null, payout: 0, after_split: true, split_aces: splitAces};
        if (!telegramEngine || (splitAces && Boolean(rules.split_aces_one_card))) right.cards.push(draw());
        state.hands.splice(state.active, 1, left, right); state.total_wager = cash(state.total_wager + hand.bet);
        if (splitAces && Boolean(rules.split_aces_one_card)) { left.status = right.status = "stood"; advance(); }
      } else { errors.push(`unknown action: ${action}`); break; }
    }
    if (!state.complete && contract.final_dealer) errors.push("action log did not settle the round");
    const finalHands = state.hands.map(hand => ({cards: hand.cards, bet: cash(hand.bet), status: hand.status, result: hand.result, payout: cash(hand.payout), after_split: Boolean(hand.after_split), split_aces: Boolean(hand.split_aces)}));
    const comparable = {
      final_dealer: state.dealer, final_hands: finalHands, total_wager: cash(state.total_wager),
      insurance_bet: cash(state.insurance_bet), insurance_payout: cash(state.insurance_payout),
      total_payout: cash(state.total_payout), outcome: state.outcome,
    };
    const expected = {
      final_dealer: contract.final_dealer, final_hands: contract.final_hands,
      total_wager: contract.total_wager, insurance_bet: contract.insurance_bet,
      insurance_payout: contract.insurance_payout, total_payout: contract.total_payout,
      outcome: contract.outcome,
    };
    const matches = errors.length === 0 && partialEqual(comparable, expected);
    if (!matches && !errors.length) errors.push("replayed Blackjack state differs from the stored final state");
    return {matches, expected_payout: state.total_payout, replayed: comparable, errors};
  }

  function verifyPayout(context, recordedPayout, generatedOutcome, record) {
    if (!context || !context.formula || recordedPayout == null) return {matches: null, expected: null, details: null};
    if (context.formula === "blackjack") {
      const replay = replayBlackjack(generatedOutcome.shoe, record.blackjack_replay || context);
      return {matches: replay.matches && Math.abs(Number(recordedPayout) - replay.expected_payout) <= 0.001, expected: replay.expected_payout, details: replay};
    }
    if (context.formula === "multiplier") {
      const precision = Number(context.precision ?? 6);
      let expected = context.won === false ? 0 : Number(context.wager) * Number(context.multiplier);
      const factor = 10 ** precision;
      expected = Math.round((expected + Number.EPSILON) * factor) / factor;
      if (context.max_payout != null) expected = Math.min(expected, Number(context.max_payout));
      return {matches: Math.abs(Number(recordedPayout) - expected) <= 10 ** (-precision), expected, details: null};
    }
    if (context.formula === "fixed") {
      const expected = Number(context.amount);
      return {matches: Number.isFinite(expected) && Math.abs(Number(recordedPayout) - expected) <= 1e-9, expected, details: null};
    }
    if (context.formula === "horse") {
      const order = (generatedOutcome.finish_order || []).map(Number);
      const bet = context.bet || {}, horses = (bet.horses || []).map(Number);
      const winner = order[0], type = String(bet.type || "");
      let won;
      if (!order.length) won = false;
      else if (["win", "place", "show", "last"].includes(type) && (horses.length !== 1 || !order.includes(horses[0]))) won = false;
      else if (["vs", "fc", "qn"].includes(type) && (horses.length !== 2 || horses[0] === horses[1] || horses.some(value => !order.includes(value)))) won = false;
      else if (type === "win") won = horses[0] === winner;
      else if (type === "place") won = order.slice(0, 2).includes(horses[0]);
      else if (type === "show") won = order.slice(0, 3).includes(horses[0]);
      else if (type === "last") won = horses[0] === order[order.length - 1];
      else if (type === "vs") won = order.indexOf(horses[0]) < order.indexOf(horses[1]);
      else if (type === "fc") won = order[0] === horses[0] && order[1] === horses[1];
      else if (type === "qn") won = order.slice(0, 2).sort((a, b) => a - b).join(",") === horses.slice(0, 2).sort((a, b) => a - b).join(",");
      else if (type === "odd") won = winner % 2 === 1;
      else if (type === "even") won = winner % 2 === 0;
      else if (type === "low") won = winner <= Math.floor(order.length / 2);
      else if (type === "high") won = winner > Math.floor(order.length / 2);
      else return {matches: false, expected: null, details: {warning: `unsupported horse bet: ${type}`}};
      const precision = Number(context.precision ?? 6), factor = 10 ** precision;
      let expected = won ? Number(context.wager) * Number(context.multiplier) : 0;
      expected = Math.round((expected + Number.EPSILON) * factor) / factor;
      if (context.max_payout != null) expected = Math.min(expected, Number(context.max_payout));
      return {matches: Math.abs(Number(recordedPayout) - expected) <= 10 ** (-precision), expected, details: {won}};
    }
    if (context.formula === "roulette") {
      const number = Number(generatedOutcome.number);
      const unit = Number(context.unit_wager);
      const includes = (key, value) => Array.isArray(context[key]) && context[key].includes(value);
      const red = new Set([1,3,5,7,9,12,14,16,18,19,21,23,25,27,30,32,34,36]);
      let expected = includes("numbers", number) ? unit * 36 : 0;
      if (includes("colors", "Red") && red.has(number)) expected += unit * 1.92;
      if (includes("colors", "Black") && number !== 0 && !red.has(number)) expected += unit * 1.92;
      if (number !== 0) {
        if (includes("evens", "Even") && number % 2 === 0) expected += unit * 1.92;
        if (includes("evens", "Odd") && number % 2 === 1) expected += unit * 1.92;
        if (includes("ranges", "1 to 18") && number <= 18) expected += unit * 1.92;
        if (includes("ranges", "19 to 36") && number >= 19) expected += unit * 1.92;
        if (includes("dozens", "1 to 12") && number <= 12) expected += unit * 2.88;
        if (includes("dozens", "13 to 24") && number >= 13 && number <= 24) expected += unit * 2.88;
        if (includes("dozens", "25 to 36") && number >= 25) expected += unit * 2.88;
      }
      const precision = Number(context.precision ?? 6), factor = 10 ** precision;
      expected = Math.round((expected + Number.EPSILON) * factor) / factor;
      return {matches: Math.abs(Number(recordedPayout) - expected) <= 10 ** (-precision), expected, details: null};
    }
    return {matches: null, expected: null, details: {warning: `unsupported payout formula: ${context.formula}`}};
  }

  async function verifyRecord(record) {
    const game = normalizeGame(record.game);
    const fairnessVersion = record.fairness_version || record.algorithm || LEGACY_FAIRNESS_VERSION;
    const generated = await generateOutcome(game, {
      server_seed: record.server_seed, client_seed: record.client_seed,
      nonce: Number(record.nonce), cursor: Number(record.cursor || 0), fairness_version: fairnessVersion,
    }, record.params || {}, record.game_algorithm_version || null);
    const commitmentMatches = (await sha256Hex(record.server_seed)) === String(record.server_seed_hash || "").toLowerCase();
    const expectedRandom = record.generated_random_values || {};
    const expectedProof = expectedRandom.proof || record.hash || null;
    const randomnessMatches = expectedProof ? generated.proof.toLowerCase() === String(expectedProof).toLowerCase() : null;
    const hasRecordedResult = record.recorded_result != null && (
      typeof record.recorded_result !== "object" || Array.isArray(record.recorded_result) || Object.keys(record.recorded_result).length > 0
    );
    let outcomeMatches = hasRecordedResult ? partialEqual(generated.outcome, record.recorded_result) : null;
    const payout = verifyPayout(record.payout_context, record.payout, generated.outcome, record);
    if (game === "blackjack" && payout.details?.matches === false) outcomeMatches = false;
    const checks = {
      seed: commitmentMatches, randomness: randomnessMatches,
      game: outcomeMatches, payout: payout.matches,
    };
    const verified = Object.values(checks).every(value => value === true);
    return {
      game, verified, complete: Object.values(checks).every(value => value !== null), checks,
      commitment_matches: commitmentMatches, randomness_matches: randomnessMatches,
      outcome_matches: outcomeMatches, payout_matches: payout.matches,
      generated, recorded: record.recorded_result, recorded_payout: record.payout,
      expected_payout: payout.expected, payout_details: payout.details,
    };
  }

  root.ProvablyFair = Object.freeze({
    FAIRNESS_VERSION, LEGACY_FAIRNESS_VERSION, GAME_SCHEMAS, GAME_VERSIONS,
    FairRandom, normalizeGame, sha256Hex, hmacBlock, generateOutcome,
    partialEqual, replayBlackjack, verifyRecord,
  });
})(window);

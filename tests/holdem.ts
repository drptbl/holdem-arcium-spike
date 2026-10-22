/**
 * Latency and cost benchmark for heads-up Hold'em on Arcium, in three modes:
 *
 * - baseline: newHand (deal) -> nextStreet x3 -> showdown, 5 MPC calls per hand.
 * - fast: newFastHand (deal_fast), then both players postReveal each street and their
 *   hole cards at the same time. One MPC call per hand.
 * - fallback: newFastHand, then nobody posts, so every street and the showdown fall
 *   back to MPC (nextStreet / showdown). The worst case for a fast hand.
 *
 * MPC steps are timed from sending the queue transaction to the callback landing;
 * posted reveals from sending both posts to both confirming. Costs come from the
 * payer's balance after reclaiming computation rent. Every hand checks that each
 * player decrypts only their own cards, that showdown shows exactly those cards, and
 * for deal_fast hands that the commitments and the masked board agree with the deck.
 *
 * Env: MODES (default "baseline,fast"; "mode:count" overrides HANDS per mode),
 * HANDS (default 3), ARCIUM_CLUSTER_OFFSET (set by `arcium test`),
 * CIRCUIT_BASE_URL (public URL serving build/*.arcis; required on devnet).
 * Results: bench/results/<cluster offset>-<timestamp>.json plus a printed summary.
 */
import * as anchor from "@anchor-lang/core";
import { Program } from "@anchor-lang/core";
import { PublicKey, Keypair } from "@solana/web3.js";
import { Holdem } from "../target/types/holdem";
import { createHash, randomBytes } from "crypto";
import {
  awaitComputationFinalization,
  claimComputationRent,
  getArciumEnv,
  getCompDefAccOffset,
  getArciumProgramId,
  getArciumProgram,
  uploadCircuit,
  RescueCipher,
  deserializeLE,
  getMXEAccAddress,
  getMempoolAccAddress,
  getCompDefAccAddress,
  getExecutingPoolAccAddress,
  x25519,
  getComputationAccAddress,
  getArciumAccountBaseSeed,
  getMXEPublicKey,
  getClusterAccAddress,
  getLookupTableAddress,
} from "@arcium-hq/client";
import { getComputationFee } from "@arcium-hq/reader";
import * as fs from "fs";
import { expect } from "chai";

const CIRCUITS = ["deal", "reveal_board", "showdown_reveal", "deal_fast"] as const;
type Circuit = (typeof CIRCUITS)[number];
const MODES = ["baseline", "fast", "fallback"] as const;
type Mode = (typeof MODES)[number];
const STEPS = ["deal", "flop", "turn", "river", "showdown"] as const;
type Step = (typeof STEPS)[number];

/** `post_reveal` kinds: hole cards, then the flop, turn and river shares. */
const STREET_KINDS = { flop: 1, turn: 2, river: 3 } as const;
const HOLE_CARDS = 0;

type Sample = {
  mode: Mode;
  hand: number;
  step: Step;
  /** The queue transaction, or both post transactions joined by a comma. */
  queueSig: string;
  callbackSig: string;
  callbackOk: boolean;
  failedCallbackAttempts: number;
  failedCallbackTxs: { sig: string; err: unknown }[];
  clientSendMs: number;
  clientTotalMs: number;
  queueSlot: number;
  callbackSlot: number;
  queueBlockTime: number | null;
  callbackBlockTime: number | null;
  queueTxFeeLamports: number;
  queueTxCu: number | null;
  callbackTxCu: number | null;
  payerQueueDeltaLamports: number;
  payerSettledDeltaLamports: number;
  payerNetCostLamports: number;
  arciumBaseFeeLamports: string | null;
  arciumPriorityFeeLamports: string | null;
};

/** Pack<[u8; N]> stores u8 lanes at 8-bit boundaries, 26 per field element. */
function unpackU8(fields: bigint[], n: number): number[] {
  return Array.from({ length: n }, (_, i) =>
    Number((fields[Math.floor(i / 26)] >> BigInt(8 * (i % 26))) & 0xffn)
  );
}

/**
 * What a seat posts for `kind`, from its decrypted deal_fast secrets laid out as
 * [hole a, hole b, flop shares x3, turn share, river share, salts x4 of 8 bytes].
 */
function revealFor(secrets: number[], kind: number): { payload: number[]; salt: number[] } {
  const payload =
    kind === HOLE_CARDS ? [secrets[0], secrets[1], 0] : kind === 1 ? secrets.slice(2, 5) : [secrets[3 + kind], 0, 0];
  return { payload, salt: secrets.slice(7 + 8 * kind, 15 + 8 * kind) };
}

/** Same commitment the circuit and the program compute. */
function commitment(seat: number, kind: number, payload: number[], salt: number[]): number[] {
  const digest = createHash("sha3-256")
    .update(Uint8Array.from([seat, kind, ...payload, ...salt]))
    .digest();
  return Array.from(digest.subarray(0, 16));
}

function cardName(card: number): string {
  return "A23456789TJQK"[card % 13] + "cdhs"[Math.floor(card / 13)];
}

function percentile(sorted: number[], p: number): number {
  return sorted[Math.min(sorted.length - 1, Math.floor((p / 100) * sorted.length))];
}

function median(xs: number[]): number {
  return percentile([...xs].sort((a, b) => a - b), 50);
}

describe("Holdem benchmark", () => {
  const owner = readKpJson(process.env.ANCHOR_WALLET!);
  // Confirmed rather than Anchor's default "processed": load-balanced RPCs otherwise
  // hand out blockhashes that the node running preflight has not seen yet.
  anchor.setProvider(
    new anchor.AnchorProvider(
      new anchor.web3.Connection(process.env.ANCHOR_PROVIDER_URL!, "confirmed"),
      new anchor.Wallet(owner),
      { commitment: "confirmed", preflightCommitment: "confirmed" }
    )
  );
  const program = anchor.workspace.Holdem as Program<Holdem>;
  const provider = anchor.getProvider() as anchor.AnchorProvider;
  const conn = provider.connection;
  const arciumProgram = getArciumProgram(provider);
  // Untyped: the Arcium IDL's account types are too deep for tsc to instantiate.
  const arciumAccounts = arciumProgram.account as any;
  const opponent = Keypair.generate();

  const arciumEnv = getArciumEnv();
  const clusterOffset = arciumEnv.arciumClusterOffset;
  const defaultHands = Number(process.env.HANDS ?? 3);
  const plan = (process.env.MODES ?? "baseline,fast").split(",").map((entry) => {
    const [mode, count] = entry.trim().split(":");
    if (!MODES.includes(mode as Mode)) {
      throw new Error(`Unknown mode "${mode}" in MODES; expected ${MODES.join(", ")}`);
    }
    return { mode: mode as Mode, hands: count === undefined ? defaultHands : Number(count) };
  });
  // Public base URL serving build/*.arcis; unset means circuits are uploaded on-chain.
  const circuitBaseUrl = process.env.CIRCUIT_BASE_URL?.replace(/\/$/, "");

  const queueAccounts = (offset: anchor.BN, circuit: Circuit) => ({
    computationAccount: getComputationAccAddress(clusterOffset, offset),
    clusterAccount: getClusterAccAddress(clusterOffset),
    mxeAccount: getMXEAccAddress(program.programId),
    mempoolAccount: getMempoolAccAddress(clusterOffset),
    executingPool: getExecutingPoolAccAddress(clusterOffset),
    compDefAccount: getCompDefAccAddress(
      program.programId,
      Buffer.from(getCompDefAccOffset(circuit)).readUInt32LE()
    ),
  });

  const handPda = (handId: bigint) => {
    const id = Buffer.alloc(8);
    id.writeBigUInt64LE(handId);
    return PublicKey.findProgramAddressSync([Buffer.from("hand"), id], program.programId)[0];
  };

  /**
   * Finds the callback: the successful transaction after the queue that writes the
   * hand account. Signature indexing can trail finalization, so retry briefly.
   */
  async function findCallback(handAccount: PublicKey, queueSig: string) {
    const opts = { commitment: "confirmed" as const, maxSupportedTransactionVersion: 0 };
    for (let attempt = 0; attempt < 30; attempt++) {
      const newer = await conn.getSignaturesForAddress(handAccount, { until: queueSig }, "confirmed");
      const ok = newer.filter((s) => s.err === null);
      if (ok.length > 0) {
        const callbackSig = ok[ok.length - 1].signature;
        const failed = newer.filter((s) => s.err !== null).map((s) => ({ sig: s.signature, err: s.err }));
        return { callbackSig, failed, tx: await conn.getTransaction(callbackSig, opts) };
      }
      await new Promise((r) => setTimeout(r, 500));
    }
    return null;
  }

  /** Sends one queue transaction and waits for its callback to land. */
  async function measure(
    mode: Mode,
    hand: number,
    step: Step,
    offset: anchor.BN,
    handAccount: PublicKey,
    send: () => Promise<string>
  ): Promise<Sample> {
    const before = await conn.getBalance(owner.publicKey, "confirmed");
    const t0 = performance.now();
    const queueSig = await send();
    const t1 = performance.now();
    const fee = await getComputationFee(arciumProgram as any, program.programId, offset, "confirmed").catch(
      () => null
    );
    await awaitComputationFinalization(provider, offset, program.programId, "confirmed", 600_000);
    const t2 = performance.now();

    const callback = await findCallback(handAccount, queueSig);
    const callbackTx = callback?.tx;
    const queueTx = await conn.getTransaction(queueSig, {
      commitment: "confirmed",
      maxSupportedTransactionVersion: 0,
    });
    const after = await conn.getBalance(owner.publicKey, "confirmed");
    // The payer deposits rent for the computation account and must reclaim it.
    await claimComputationRent(provider, clusterOffset, offset, { commitment: "confirmed" });
    const afterClaim = await conn.getBalance(owner.publicKey, "confirmed");
    // The deal also funds the Hand PDA's rent, which is not part of the MPC cost.
    const handRentLamports = step === "deal" ? (await conn.getAccountInfo(handAccount, "confirmed"))!.lamports : 0;
    const payerIndex = queueTx!.transaction.message.staticAccountKeys.findIndex((k) =>
      k.equals(owner.publicKey)
    );

    return {
      mode,
      hand,
      step,
      queueSig,
      callbackSig: callback?.callbackSig ?? "",
      callbackOk: !!callbackTx && callbackTx.meta?.err === null,
      failedCallbackAttempts: callback?.failed.length ?? 0,
      failedCallbackTxs: callback?.failed ?? [],
      clientSendMs: Math.round(t1 - t0),
      clientTotalMs: Math.round(t2 - t0),
      queueSlot: queueTx!.slot,
      callbackSlot: callbackTx?.slot ?? -1,
      queueBlockTime: queueTx!.blockTime ?? null,
      callbackBlockTime: callbackTx?.blockTime ?? null,
      queueTxFeeLamports: queueTx!.meta!.fee,
      queueTxCu: queueTx!.meta!.computeUnitsConsumed ?? null,
      callbackTxCu: callbackTx?.meta?.computeUnitsConsumed ?? null,
      payerQueueDeltaLamports: queueTx!.meta!.preBalances[payerIndex] - queueTx!.meta!.postBalances[payerIndex],
      payerSettledDeltaLamports: before - after,
      // Includes the queue tx, Arcium fees and the reclaim tx; excludes the refunded rent.
      payerNetCostLamports: before - afterClaim - handRentLamports,
      arciumBaseFeeLamports: fee ? fee.baseFee.toString() : null,
      arciumPriorityFeeLamports: fee ? fee.priorityFee.toString() : null,
    };
  }

  /** Sends plain transactions at once (both players' posts) and waits for all of them. */
  async function measurePosts(mode: Mode, hand: number, step: Step, sends: (() => Promise<string>)[]): Promise<Sample> {
    const before = await conn.getBalance(owner.publicKey, "confirmed");
    const t0 = performance.now();
    const sigs = await Promise.all(sends.map((send) => send()));
    const t1 = performance.now();
    const txs = await Promise.all(
      sigs.map((sig) => conn.getTransaction(sig, { commitment: "confirmed", maxSupportedTransactionVersion: 0 }))
    );
    const after = await conn.getBalance(owner.publicKey, "confirmed");
    const slots = txs.map((tx) => tx!.slot);
    const times = txs.map((tx) => tx!.blockTime ?? 0);

    return {
      mode,
      hand,
      step,
      queueSig: sigs.join(","),
      callbackSig: "",
      callbackOk: txs.every((tx) => tx?.meta?.err === null),
      failedCallbackAttempts: 0,
      failedCallbackTxs: [],
      clientSendMs: Math.round(t1 - t0),
      clientTotalMs: Math.round(t1 - t0),
      queueSlot: Math.min(...slots),
      callbackSlot: Math.max(...slots),
      queueBlockTime: Math.min(...times),
      callbackBlockTime: Math.max(...times),
      queueTxFeeLamports: txs.reduce((n, tx) => n + tx!.meta!.fee, 0),
      queueTxCu: txs.reduce((n, tx) => n + (tx!.meta!.computeUnitsConsumed ?? 0), 0),
      callbackTxCu: null,
      payerQueueDeltaLamports: before - after,
      payerSettledDeltaLamports: before - after,
      payerNetCostLamports: before - after,
      arciumBaseFeeLamports: null,
      arciumPriorityFeeLamports: null,
    };
  }

  it("plays heads-up hands and records latency and cost per step", async () => {
    console.log(
      `Payer ${owner.publicKey.toBase58()}, cluster offset ${clusterOffset}, ` +
        plan.map((p) => `${p.mode} x${p.hands}`).join(", ")
    );
    const mxePublicKey = await getMXEPublicKeyWithRetry(provider, program.programId);

    for (const circuit of CIRCUITS) {
      console.log(`Comp def ${circuit}: ${await initCompDef(circuit)}`);
    }
    const circuitInfo = await describeCircuits();
    console.log("Circuits:", circuitInfo);

    const samples: Sample[] = [];
    // Interleave modes hand by hand so they see the same network conditions.
    const rounds = Math.max(...plan.map((p) => p.hands));
    for (let h = 0; h < rounds; h++) {
      for (const { mode, hands } of plan) {
        if (h < hands) {
          await playHand(mode, h, mxePublicKey, samples);
        }
      }
    }

    const report = summarize(samples);
    console.table(report.steps);
    console.table(report.hands);
    fs.mkdirSync("bench/results", { recursive: true });
    const file = `bench/results/${clusterOffset}-${new Date().toISOString().replace(/[:.]/g, "-")}.json`;
    fs.writeFileSync(
      file,
      JSON.stringify(
        { clusterOffset, rpcHost: new URL(conn.rpcEndpoint).host, programId: program.programId.toBase58(), circuitInfo, report, samples },
        null,
        2
      )
    );
    console.log(`Wrote ${file}`);

    const missing = samples
      .filter((s) => !s.callbackOk)
      .map((s) => `${s.mode}/${s.hand}/${s.step} ${s.queueSig}`);
    expect(missing, "every callback and post landed without error").to.deep.equal([]);
  });

  async function playHand(mode: Mode, h: number, mxePublicKey: Uint8Array, samples: Sample[]) {
    const players = [0, 1].map(() => {
      const secret = x25519.utils.randomSecretKey();
      return {
        pubkey: x25519.getPublicKey(secret),
        cipher: new RescueCipher(x25519.getSharedSecret(secret, mxePublicKey)),
      };
    });
    const handId = deserializeLE(randomBytes(8));
    const handIdBn = new anchor.BN(handId.toString());
    const hand = handPda(handId);
    const record = async (sample: Promise<Sample>) => samples.push(await sample);
    const mpc = (step: Step, circuit: Circuit, build: (offset: anchor.BN) => any) => {
      const offset = new anchor.BN(randomBytes(8), "hex");
      return record(
        measure(mode, h, step, offset, hand, () =>
          build(offset)
            .accountsPartial({ ...queueAccounts(offset, circuit), hand })
            .signers([owner])
            .rpc({ skipPreflight: true, commitment: "confirmed" })
        )
      );
    };
    const decrypt = (seat: number, ciphertexts: number[][], nonce: anchor.BN) =>
      players[seat].cipher.decrypt(ciphertexts, Uint8Array.from(nonce.toArray("le", 16)));

    const fast = mode !== "baseline";
    const dealArgs = [
      handIdBn,
      opponent.publicKey,
      Array.from(players[0].pubkey),
      new anchor.BN(deserializeLE(randomBytes(16)).toString()),
      Array.from(players[1].pubkey),
      new anchor.BN(deserializeLE(randomBytes(16)).toString()),
    ] as const;
    await mpc("deal", fast ? "deal_fast" : "deal", (offset) =>
      fast ? program.methods.newFastHand(offset, ...dealArgs) : program.methods.newHand(offset, ...dealArgs)
    );

    let state = await program.account.hand.fetch(hand);
    let holes: number[][];
    let secrets: number[][] = [];
    if (fast) {
      secrets = [0, 1].map((seat) =>
        unpackU8(decrypt(seat, state.seatCiphertexts[seat], state.seatNonces[seat]), 39)
      );
      holes = secrets.map((s) => s.slice(0, 2));
      // Player 1's key cannot open player 0's secrets.
      const crossRead = unpackU8(
        players[1].cipher.decrypt(state.seatCiphertexts[0], Uint8Array.from(state.seatNonces[0].toArray("le", 16))),
        39
      );
      expect(crossRead.slice(0, 2)).to.not.deep.equal(holes[0]);
      for (const seat of [0, 1]) {
        for (const kind of [HOLE_CARDS, 1, 2, 3]) {
          const { payload, salt } = revealFor(secrets[seat], kind);
          expect(commitment(seat, kind, payload, salt), `commitment seat ${seat} kind ${kind}`).to.deep.equal(
            Array.from(state.commitments[4 * seat + kind])
          );
        }
      }
    } else {
      holes = [0, 1].map((seat) => unpackU8(decrypt(seat, [state.holeCiphertexts[seat]], state.holeNonces[seat]), 2));
      const crossRead = unpackU8(decrypt(1, [state.holeCiphertexts[0]], state.holeNonces[0]), 2);
      expect(crossRead).to.not.deep.equal(holes[0]);
    }

    const post = (seat: number, kind: number) => () => {
      const { payload, salt } = revealFor(secrets[seat], kind);
      const player = seat === 0 ? owner : opponent;
      return program.methods
        .postReveal(handIdBn, kind, payload, salt)
        .accountsPartial({ player: player.publicKey, hand })
        .signers([player])
        .rpc({ skipPreflight: true, commitment: "confirmed" });
    };

    for (const step of ["flop", "turn", "river"] as const) {
      if (mode === "fast") {
        await record(measurePosts(mode, h, step, [post(0, STREET_KINDS[step]), post(1, STREET_KINDS[step])]));
      } else {
        await mpc(step, "reveal_board", (offset) =>
          program.methods.nextStreet(offset, handIdBn).accountsPartial({ payer: owner.publicKey })
        );
      }
    }
    if (mode === "fast") {
      await record(measurePosts(mode, h, "showdown", [post(0, HOLE_CARDS), post(1, HOLE_CARDS)]));
    } else {
      await mpc("showdown", "showdown_reveal", (offset) =>
        program.methods.showdown(offset, handIdBn).accountsPartial({ payer: owner.publicKey })
      );
    }

    state = await program.account.hand.fetch(hand);
    expect(state.stage).to.deep.equal({ complete: {} });
    expect(state.holeCards).to.deep.equal([...holes[0], ...holes[1]]);
    const dealt = [...state.holeCards, ...state.board];
    expect(new Set(dealt).size, "every dealt card is distinct").to.equal(9);
    expect(dealt.every((c) => c >= 0 && c < 52)).to.equal(true);
    if (fast) {
      // Shares unmask exactly the cards the MPC deck holds, whichever path revealed them.
      const unmasked = state.maskedBoard.map((m, i) => m ^ secrets[0][2 + i] ^ secrets[1][2 + i]);
      expect(unmasked).to.deep.equal(Array.from(state.board));
    }
    const [s0, s1] = state.scores;
    expect(state.winner).to.equal(s0 > s1 ? 0 : s1 > s0 ? 1 : 2);

    console.log(
      `${mode} hand ${h}: p0 ${holes[0].map(cardName).join(" ")} | p1 ${holes[1].map(cardName).join(" ")} | ` +
        `board ${Array.from(state.board).map(cardName).join(" ")} | winner ${["p0", "p1", "split"][state.winner]} | ` +
        samples
          .filter((s) => s.mode === mode && s.hand === h)
          .map((s) => `${s.step} ${(s.clientTotalMs / 1000).toFixed(1)}s`)
          .join(", ")
    );
  }

  function summarize(samples: Sample[]) {
    const steps = plan.flatMap(({ mode }) =>
      STEPS.map((step) => {
        const rows = samples.filter((s) => s.mode === mode && s.step === step);
        const total = rows.map((s) => s.clientTotalMs).sort((a, b) => a - b);
        return {
          mode,
          step,
          n: rows.length,
          p50_ms: percentile(total, 50),
          p90_ms: percentile(total, 90),
          max_ms: total[total.length - 1],
          p50_slots: median(rows.map((s) => s.callbackSlot - s.queueSlot)),
          failed_callback_txs: rows.reduce((n, s) => n + s.failedCallbackAttempts, 0),
          p50_net_cost_lamports: median(rows.map((s) => s.payerNetCostLamports)),
          arcium_base_fee_lamports: rows.find((s) => s.arciumBaseFeeLamports)?.arciumBaseFeeLamports ?? "n/a",
        };
      })
    );
    const hands = plan.map(({ mode, hands: n }) => {
      const perHand = Array.from({ length: n }, (_, h) => samples.filter((s) => s.mode === mode && s.hand === h));
      return {
        mode,
        hands: n,
        p50_wait_ms: median(perHand.map((rows) => rows.reduce((t, s) => t + s.clientTotalMs, 0))),
        p50_net_cost_lamports: median(perHand.map((rows) => rows.reduce((t, s) => t + s.payerNetCostLamports, 0))),
      };
    });
    return { steps, hands };
  }

  /** Circuit weight (cuAmount), cluster CU price, and compiled circuit size. */
  async function describeCircuits() {
    const cluster = await arciumAccounts.cluster.fetch(getClusterAccAddress(clusterOffset));
    const out: Record<string, unknown> = { clusterCuPriceMicroLamports: cluster.cuPrice.toString() };
    for (const circuit of CIRCUITS) {
      const compDef = await arciumAccounts.computationDefinitionAccount.fetch(compDefPda(circuit));
      out[circuit] = {
        cuAmount: compDef.cuAmount.toString(),
        circuitBytes: fs.statSync(`build/${circuit}.arcis`).size,
      };
    }
    return out;
  }

  function compDefPda(circuit: Circuit): PublicKey {
    return PublicKey.findProgramAddressSync(
      [getArciumAccountBaseSeed("ComputationDefinitionAccount"), program.programId.toBuffer(), getCompDefAccOffset(circuit)],
      getArciumProgramId()
    )[0];
  }

  async function initCompDef(circuit: Circuit): Promise<string> {
    const compDefPDA = compDefPda(circuit);
    if (await arciumAccounts.computationDefinitionAccount.fetchNullable(compDefPDA)) {
      return "already initialized";
    }
    const mxeAccount = getMXEAccAddress(program.programId);
    const mxeAcc = await arciumAccounts.mxeAccount.fetch(mxeAccount);
    const accounts = {
      compDefAccount: compDefPDA,
      payer: owner.publicKey,
      mxeAccount,
      addressLookupTable: getLookupTableAddress(program.programId, mxeAcc.lutOffsetSlot),
    };
    const url = circuitBaseUrl ? `${circuitBaseUrl}/${circuit}.arcis` : null;
    const init = {
      deal: () => program.methods.initDealCompDef(url),
      reveal_board: () => program.methods.initRevealBoardCompDef(url),
      showdown_reveal: () => program.methods.initShowdownRevealCompDef(url),
      deal_fast: () => program.methods.initDealFastCompDef(url),
    }[circuit];
    const sig = await init().accounts(accounts).signers([owner]).rpc({ commitment: "confirmed" });

    if (!url) {
      await uploadCircuit(provider, circuit, program.programId, fs.readFileSync(`build/${circuit}.arcis`), true, 500, {
        skipPreflight: true,
        preflightCommitment: "confirmed",
        commitment: "confirmed",
      });
    }
    return url ? `${sig} (off-chain: ${url})` : sig;
  }
});

async function getMXEPublicKeyWithRetry(
  provider: anchor.AnchorProvider,
  programId: PublicKey,
  // MXE keygen on a public cluster can take a while after `arcium deploy`.
  maxRetries: number = 120,
  retryDelayMs: number = 1000
): Promise<Uint8Array> {
  for (let attempt = 1; attempt <= maxRetries; attempt++) {
    try {
      const mxePublicKey = await getMXEPublicKey(provider, programId);
      if (mxePublicKey) {
        return mxePublicKey;
      }
    } catch (error) {
      console.log(`Attempt ${attempt} failed to fetch MXE public key:`, error);
    }
    if (attempt < maxRetries) {
      await new Promise((resolve) => setTimeout(resolve, retryDelayMs));
    }
  }
  throw new Error(`Failed to fetch MXE public key after ${maxRetries} attempts`);
}

function readKpJson(path: string): anchor.web3.Keypair {
  return anchor.web3.Keypair.fromSecretKey(new Uint8Array(JSON.parse(fs.readFileSync(path).toString())));
}

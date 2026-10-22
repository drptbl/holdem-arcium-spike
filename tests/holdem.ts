/**
 * Latency and cost benchmark for heads-up Hold'em on Arcium.
 *
 * Flow per hand: newHand (deal) -> nextStreet x3 (flop, turn, river) -> showdown.
 * Every queued computation is timed from sending the queue transaction to the
 * callback landing on-chain, and costed from the payer's balance and the fee the
 * Arcium program recorded for it. Each hand also checks that each player decrypts
 * their own hole cards and that showdown reveals exactly those cards.
 *
 * Env: HANDS (default 3), ARCIUM_CLUSTER_OFFSET (set by `arcium test`),
 * CIRCUIT_BASE_URL (public URL serving build/*.arcis; required on devnet).
 * Results: bench/results/<cluster offset>-<timestamp>.json plus a printed summary.
 */
import * as anchor from "@anchor-lang/core";
import { Program } from "@anchor-lang/core";
import { PublicKey, Keypair } from "@solana/web3.js";
import { Holdem } from "../target/types/holdem";
import { randomBytes } from "crypto";
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

const CIRCUITS = ["deal", "reveal_board", "showdown_reveal"] as const;
type Circuit = (typeof CIRCUITS)[number];
type Step = "deal" | "flop" | "turn" | "river" | "showdown";

type Sample = {
  hand: number;
  step: Step;
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

/** Pack<[u8; N]> stores u8 lanes at 8-bit boundaries of one field element. */
function unpackU8(packed: bigint, n: number): number[] {
  return Array.from({ length: n }, (_, i) => Number((packed >> BigInt(8 * i)) & 0xffn));
}

function cardName(card: number): string {
  return "A23456789TJQK"[card % 13] + "cdhs"[Math.floor(card / 13)];
}

function percentile(sorted: number[], p: number): number {
  return sorted[Math.min(sorted.length - 1, Math.floor((p / 100) * sorted.length))];
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
  const hands = Number(process.env.HANDS ?? 3);
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

  it("plays heads-up hands and records latency and cost per computation", async () => {
    console.log(`Payer ${owner.publicKey.toBase58()}, cluster offset ${clusterOffset}, ${hands} hand(s)`);
    const mxePublicKey = await getMXEPublicKeyWithRetry(provider, program.programId);

    for (const circuit of CIRCUITS) {
      console.log(`Comp def ${circuit}: ${await initCompDef(circuit)}`);
    }
    const circuitInfo = await describeCircuits();
    console.log("Circuits:", circuitInfo);

    const samples: Sample[] = [];
    for (let h = 0; h < hands; h++) {
      const players = [0, 1].map(() => {
        const secret = x25519.utils.randomSecretKey();
        return {
          pubkey: x25519.getPublicKey(secret),
          cipher: new RescueCipher(x25519.getSharedSecret(secret, mxePublicKey)),
        };
      });
      const handId = deserializeLE(randomBytes(8));
      const hand = handPda(handId);

      let offset = new anchor.BN(randomBytes(8), "hex");
      const dealOffset = offset;
      samples.push(
        await measure(h, "deal", offset, hand, () =>
          program.methods
            .newHand(
              dealOffset,
              new anchor.BN(handId.toString()),
              opponent.publicKey,
              Array.from(players[0].pubkey),
              new anchor.BN(deserializeLE(randomBytes(16)).toString()),
              Array.from(players[1].pubkey),
              new anchor.BN(deserializeLE(randomBytes(16)).toString())
            )
            .accountsPartial({ ...queueAccounts(dealOffset, "deal"), hand })
            .signers([owner])
            .rpc({ skipPreflight: true, commitment: "confirmed" })
        )
      );

      let state = await program.account.hand.fetch(hand);
      const holes = [0, 1].map((seat) =>
        unpackU8(
          players[seat].cipher.decrypt(
            [state.holeCiphertexts[seat]],
            Uint8Array.from(state.holeNonces[seat].toArray("le", 16))
          )[0],
          2
        )
      );
      // Player 1's key cannot open player 0's cards.
      const crossRead = unpackU8(
        players[1].cipher.decrypt(
          [state.holeCiphertexts[0]],
          Uint8Array.from(state.holeNonces[0].toArray("le", 16))
        )[0],
        2
      );
      expect(crossRead).to.not.deep.equal(holes[0]);

      for (const step of ["flop", "turn", "river"] as const) {
        offset = new anchor.BN(randomBytes(8), "hex");
        const streetOffset = offset;
        samples.push(
          await measure(h, step, offset, hand, () =>
            program.methods
              .nextStreet(streetOffset, new anchor.BN(handId.toString()))
              .accountsPartial({ ...queueAccounts(streetOffset, "reveal_board"), hand, payer: owner.publicKey })
              .signers([owner])
              .rpc({ skipPreflight: true, commitment: "confirmed" })
          )
        );
      }

      offset = new anchor.BN(randomBytes(8), "hex");
      const showdownOffset = offset;
      samples.push(
        await measure(h, "showdown", offset, hand, () =>
          program.methods
            .showdown(showdownOffset, new anchor.BN(handId.toString()))
            .accountsPartial({ ...queueAccounts(showdownOffset, "showdown_reveal"), hand, payer: owner.publicKey })
            .signers([owner])
            .rpc({ skipPreflight: true, commitment: "confirmed" })
        )
      );

      state = await program.account.hand.fetch(hand);
      expect(state.stage).to.deep.equal({ complete: {} });
      expect(state.holeCards).to.deep.equal([...holes[0], ...holes[1]]);
      const dealt = [...state.holeCards, ...state.board];
      expect(new Set(dealt).size, "every dealt card is distinct").to.equal(9);
      expect(dealt.every((c) => c >= 0 && c < 52)).to.equal(true);
      const [s0, s1] = state.scores;
      expect(state.winner).to.equal(s0 > s1 ? 0 : s1 > s0 ? 1 : 2);

      console.log(
        `Hand ${h}: p0 ${holes[0].map(cardName).join(" ")} | p1 ${holes[1].map(cardName).join(" ")} | ` +
          `board ${Array.from(state.board).map(cardName).join(" ")} | winner ${["p0", "p1", "split"][state.winner]} | ` +
          samples
            .filter((s) => s.hand === h)
            .map((s) => `${s.step} ${(s.clientTotalMs / 1000).toFixed(1)}s`)
            .join(", ")
      );
    }

    const report = summarize(samples);
    console.table(report);
    fs.mkdirSync("bench/results", { recursive: true });
    const file = `bench/results/${clusterOffset}-${new Date().toISOString().replace(/[:.]/g, "-")}.json`;
    fs.writeFileSync(
      file,
      JSON.stringify(
        { clusterOffset, rpc: conn.rpcEndpoint, programId: program.programId.toBase58(), circuitInfo, report, samples },
        null,
        2
      )
    );
    console.log(`Wrote ${file}`);

    const missing = samples.filter((s) => !s.callbackOk).map((s) => `${s.hand}/${s.step} ${s.queueSig}`);
    expect(missing, "every callback landed without error").to.deep.equal([]);
  });

  function summarize(samples: Sample[]) {
    const steps: Step[] = ["deal", "flop", "turn", "river", "showdown"];
    return steps.map((step) => {
      const rows = samples.filter((s) => s.step === step);
      const total = rows.map((s) => s.clientTotalMs).sort((a, b) => a - b);
      const slots = rows.map((s) => s.callbackSlot - s.queueSlot).sort((a, b) => a - b);
      const mean = (xs: number[]) => Math.round(xs.reduce((a, b) => a + b, 0) / xs.length);
      return {
        step,
        n: rows.length,
        p50_ms: percentile(total, 50),
        p90_ms: percentile(total, 90),
        max_ms: total[total.length - 1],
        p50_slots: percentile(slots, 50),
        failed_callback_txs: rows.reduce((n, s) => n + s.failedCallbackAttempts, 0),
        mean_send_ms: mean(rows.map((s) => s.clientSendMs)),
        mean_payer_settled_lamports: mean(rows.map((s) => s.payerSettledDeltaLamports)),
        mean_net_cost_lamports: mean(rows.map((s) => s.payerNetCostLamports)),
        mean_queue_tx_fee_lamports: mean(rows.map((s) => s.queueTxFeeLamports)),
        arcium_base_fee_lamports: rows.find((s) => s.arciumBaseFeeLamports)?.arciumBaseFeeLamports ?? "n/a",
        mean_callback_cu: mean(rows.map((s) => s.callbackTxCu ?? 0)),
      };
    });
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
  maxRetries: number = 20,
  retryDelayMs: number = 500
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

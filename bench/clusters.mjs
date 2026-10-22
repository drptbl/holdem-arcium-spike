// Read-only: prints compute-unit price and trusted-dealer config of the public Arcium clusters.
import * as anchor from "@anchor-lang/core";
import { getArciumProgram, getClusterAccAddress } from "@arcium-hq/client";

const targets = [
  { name: "devnet", offset: 456, rpc: "https://api.devnet.solana.com" },
  { name: "mainnet", offset: 2026, rpc: "https://api.mainnet-beta.solana.com" },
];

const out = {};
for (const t of targets) {
  const conn = new anchor.web3.Connection(t.rpc, "confirmed");
  const provider = new anchor.AnchorProvider(conn, new anchor.Wallet(anchor.web3.Keypair.generate()), {});
  const program = getArciumProgram(provider);
  const addr = getClusterAccAddress(t.offset);
  try {
    const c = await program.account.cluster.fetch(addr);
    out[t.name] = {
      clusterAccount: addr.toBase58(),
      clusterSize: c.clusterSize,
      cuPriceMicroLamports: c.cuPrice.toString(),
      cuPriceProposals: c.cuPriceProposals.map((x) => x.toString()).filter((x) => x !== "0"),
      trustedDealerConfigured: c.tdInfo !== null,
      tdInfo: c.tdInfo,
      nodes: c.nodes.length,
      activation: c.activation,
      epoch: c.epoch?.toString?.() ?? c.epoch,
    };
  } catch (e) {
    out[t.name] = { clusterAccount: addr.toBase58(), error: String(e) };
  }
}
console.log(JSON.stringify(out, (k, v) => (typeof v === "bigint" ? v.toString() : v), 2));

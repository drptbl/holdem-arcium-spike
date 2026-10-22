# holdem-arcium-spike

Throwaway heads-up Texas Hold'em on [Arcium](https://arcium.com), built to measure how long each MPC step takes and what it costs. Forked from the `blackjack` example in https://github.com/arcium-hq/examples at `fe15384`.

Every hand checks down to showdown. There is no betting, no chips, no timeouts and no refunds, so don't use it for anything real.

A hand is 5 MPC computations:

1. `deal` shuffles the deck inside MPC, keeps it encrypted to the MXE and gives each player their two hole cards encrypted to their own x25519 key.
2. `reveal_board` reveals the flop, then the turn, then the river.
3. `showdown_reveal` reveals both hands. The program ranks them on-chain in plain Rust (`score_seven`).

## Results

Arcium `0.15.0`, Anchor `1.0.2`, Solana CLI `3.1.10`.

Latency is measured by the client from sending the queue transaction to the callback landing. The SDK polls every 500 ms, so read it as ±0.5 s. Slots count from the queue transaction to the callback. Cost is what the payer is down after reclaiming the computation account rent with `claimComputationRent`: the queue and reclaim transaction fees plus Arcium's fee.

Devnet, cluster offset `456` with 2 Arx nodes, Helius RPC, 10 hands on 2026-10-22:

| step | median | max | slots (median) | net cost |
| --- | --- | --- | --- | --- |
| `deal` | 4.5 s | 4.6 s | 12.5 | 22,032 lamports |
| flop | 4.0 s | 5.0 s | 10 | 20,164 lamports |
| turn | 3.8 s | 4.4 s | 10 | 20,164 lamports |
| river | 3.8 s | 3.8 s | 10 | 20,164 lamports |
| showdown | 3.8 s | 4.4 s | 10 | 20,127 lamports |

A hand that goes to showdown waits about 20 s on MPC and costs 102,651 lamports. Each computation is 5,000 for the queue transaction, 5,000 for the reclaim, Arcium's base fee and 10,000 more. The base fee is weight × 1 micro-lamport: 2,032 for `deal`, 164 and 127 for the reveals. The 10,000 matches the callback reserve, which Arcium's docs say scales with the node count. I couldn't confirm the per-node amount. The first hand also pays a one-time rent for Arcium's signer PDA.

Localnet, 2 Arx nodes in Docker on an Apple Silicon laptop, 5 hands:

| step | median | max | slots (median) | net cost |
| --- | --- | --- | --- | --- |
| `deal` | 4.0 s | 17.1 s | 6 | 19,984 lamports |
| flop | 3.6 s | 3.6 s | 5 | 19,968 lamports |
| turn | 3.6 s | 3.6 s | 5 | 20,032 lamports |
| river | 3.6 s | 3.6 s | 5 | 20,032 lamports |
| showdown | 3.6 s | 3.6 s | 5 | 19,968 lamports |

The 17.1 s `deal` is the first computation after the local cluster starts. Localnet prices compute at 0, so these costs leave out Arcium's base fee.

| circuit | compiled size | weight (`cuAmount`) |
| --- | --- | --- |
| `deal` | 4.0 MB | 2,032,530,414 |
| `reveal_board` | 236 KB | 164,577,984 |
| `showdown_reveal` | 84 KB | 127,371,896 |

Both Arx nodes submit each callback. The second one fails with `alreadyCallbackedComputation` (`6204`), which is expected.

`deal` is too big to store on-chain on devnet, about 20 SOL of rent. The compiled circuits sit in `circuits/` and the computation definitions point at their raw GitHub URLs. Arx nodes check each file against the hash compiled into the program.

## Run it

```bash
pnpm install
arcium build
arcium test
```

`arcium test` runs on localnet and needs Docker. `HANDS` sets how many hands to play (default 3). Results go to `bench/results/`.

For devnet you need about 7 SOL and a dedicated RPC. The public devnet RPC rate-limits the program upload with `429 Too Many Requests`. Deploy the program, initialise the MXE on cluster offset `456`, then run the bench with the circuit URLs:

```bash
solana program deploy target/deploy/holdem.so --program-id target/deploy/holdem-keypair.json --buffer <buffer.json> -k <payer.json> --url <devnet rpc> --use-rpc
arcium deploy --skip-deploy --cluster-offset 456 --recovery-set-size 4 --keypair-path <payer.json> --program-keypair target/deploy/holdem-keypair.json --program-name holdem --rpc-url <devnet rpc>
ANCHOR_PROVIDER_URL=<devnet rpc> ANCHOR_WALLET=<payer.json> ARCIUM_CLUSTER_OFFSET=456 CIRCUIT_BASE_URL=https://raw.githubusercontent.com/drptbl/holdem-arcium-spike/08b2a012eca9bb5879acda3da1bb694359b28a3b/circuits HANDS=10 pnpm bench
```

Passing your own `--buffer` keypair lets you rerun the upload and resume it if it fails halfway.

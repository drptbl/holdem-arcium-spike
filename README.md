# holdem-arcium-spike

Throwaway heads-up Texas Hold'em on [Arcium](https://arcium.com), built to measure how long each MPC step takes and what it costs. Forked from the `blackjack` example in https://github.com/arcium-hq/examples at `fe15384`.

Every hand checks down to showdown. There is no betting, no chips, no timeouts and no refunds, so don't use it for anything real.

A hand is 5 MPC computations:

1. `deal` shuffles the deck inside MPC, keeps it encrypted to the MXE and gives each player their two hole cards encrypted to their own x25519 key.
2. `reveal_board` reveals the flop, then the turn, then the river.
3. `showdown_reveal` reveals both hands. The program ranks them on-chain in plain Rust (`score_seven`).

## Results

Arcium `0.15.0`, Anchor `1.0.2`, Solana CLI `3.1.10`.

Latency is measured by the client from sending the queue transaction to the callback landing. The SDK polls every 500 ms, so read it as ±0.5 s. Cost is what the payer is down after reclaiming the computation account rent with `claimComputationRent`: the queue and reclaim transaction fees plus Arcium's fee.

Localnet, 2 Arx nodes in Docker on an Apple Silicon laptop, 5 hands:

| step | median | max | slots (median) | net cost |
| --- | --- | --- | --- | --- |
| `deal` | 4.0 s | 17.1 s | 6 | 19,984 lamports |
| flop | 3.6 s | 3.6 s | 5 | 19,968 lamports |
| turn | 3.6 s | 3.6 s | 5 | 20,032 lamports |
| river | 3.6 s | 3.6 s | 5 | 20,032 lamports |
| showdown | 3.6 s | 3.6 s | 5 | 19,968 lamports |

The 17.1 s `deal` is the first computation after the cluster starts. The first hand also pays a one-time rent for Arcium's signer PDA. Localnet prices compute at 0, so these costs are transaction fees only.

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

For devnet, deploy to cluster offset `456` and pass the circuit URLs:

```bash
arcium deploy --cluster-offset 456 --recovery-set-size 4 --keypair-path <payer.json> --rpc-url <devnet rpc>
CIRCUIT_BASE_URL=https://raw.githubusercontent.com/drptbl/holdem-arcium-spike/<commit>/circuits HANDS=10 arcium test --cluster devnet
```

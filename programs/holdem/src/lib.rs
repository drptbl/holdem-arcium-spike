//! Heads-up Hold'em against an MPC dealer: a throwaway spike for measuring Arcium
//! latency and cost per computation. Forked from the arcium-hq blackjack example.
//!
//! One `Hand` PDA per hand stores the encrypted deck; each street and the showdown
//! feed it back into a circuit by byte offset. Layout after the 8-byte
//! discriminator: deck at offset 8 (2 x 32-byte ciphertexts, since `Pack<[u8; 52]>`
//! packs 26 bytes per field element). Betting, chips, timeouts and refunds are out
//! of scope: every hand checks down to showdown.
//!
//! Two modes: `new_hand` makes 5 MPC calls per hand (deal, flop, turn, river,
//! showdown). `new_fast_hand` makes one (`deal_fast`); players then reveal each street
//! and their hole cards with `post_reveal`, and `next_street` / `showdown` are the MPC
//! fallback when a player does not post. The spike lets either player call the
//! fallback at any time; a real table would gate it behind a timeout.

use anchor_lang::prelude::*;
use arcium_anchor::prelude::*;
use arcium_client::idl::arcium::types::{CallbackAccount, CircuitSource, OffChainCircuitSource};
use arcium_macros::circuit_hash;
use sha3::{Digest, Sha3_256};

const COMP_DEF_OFFSET_DEAL: u32 = comp_def_offset("deal");
const COMP_DEF_OFFSET_DEAL_FAST: u32 = comp_def_offset("deal_fast");
const COMP_DEF_OFFSET_REVEAL_BOARD: u32 = comp_def_offset("reveal_board");
const COMP_DEF_OFFSET_SHOWDOWN_REVEAL: u32 = comp_def_offset("showdown_reveal");

/// Byte offset and length of `Hand::deck` inside the account data.
const DECK_OFFSET: u32 = 8;
const DECK_LEN: u32 = 32 * 2;

/// Marks a card slot that has not been revealed.
const NO_CARD: u8 = 255;

declare_id!("58WSqBPM7wYJTkJg9rC9215yagvXQRphMctZoA6WUC8v");

#[arcium_program]
pub mod holdem {
    use super::*;

    // Each init takes an optional public URL of the compiled circuit. `None` stores the
    // circuit on-chain (fine on localnet); a URL keeps it off-chain, which devnet needs
    // because `deal` compiles to ~4 MB. Arx nodes check the file against the build hash.

    pub fn init_deal_comp_def(ctx: Context<InitDealCompDef>, circuit_url: Option<String>) -> Result<()> {
        init_computation_def(ctx.accounts, circuit_url.map(|url| off_chain(url, circuit_hash!("deal"))))?;
        Ok(())
    }

    pub fn init_reveal_board_comp_def(
        ctx: Context<InitRevealBoardCompDef>,
        circuit_url: Option<String>,
    ) -> Result<()> {
        init_computation_def(
            ctx.accounts,
            circuit_url.map(|url| off_chain(url, circuit_hash!("reveal_board"))),
        )?;
        Ok(())
    }

    pub fn init_showdown_reveal_comp_def(
        ctx: Context<InitShowdownRevealCompDef>,
        circuit_url: Option<String>,
    ) -> Result<()> {
        init_computation_def(
            ctx.accounts,
            circuit_url.map(|url| off_chain(url, circuit_hash!("showdown_reveal"))),
        )?;
        Ok(())
    }

    /// Creates the `Hand` PDA and queues `deal`, which shuffles and deals inside MPC.
    /// The payer is player 0; `opponent` is player 1.
    #[allow(clippy::too_many_arguments)]
    pub fn new_hand(
        ctx: Context<NewHand>,
        computation_offset: u64,
        hand_id: u64,
        opponent: Pubkey,
        p0_enc_pubkey: [u8; 32],
        p0_nonce: u128,
        p1_enc_pubkey: [u8; 32],
        p1_nonce: u128,
    ) -> Result<()> {
        let payer = ctx.accounts.payer.key();
        ctx.accounts.hand.start(ctx.bumps.hand, hand_id, [payer, opponent], false);

        // One pubkey/nonce pair per `Shared` parameter of `deal`, in order.
        let args = ArgBuilder::new()
            .x25519_pubkey(p0_enc_pubkey)
            .plaintext_u128(p0_nonce)
            .x25519_pubkey(p1_enc_pubkey)
            .plaintext_u128(p1_nonce)
            .build();

        ctx.accounts.sign_pda_account.bump = ctx.bumps.sign_pda_account;

        queue_computation(
            ctx.accounts,
            computation_offset,
            args,
            vec![DealCallback::callback_ix(
                computation_offset,
                &ctx.accounts.mxe_account,
                &[CallbackAccount {
                    pubkey: ctx.accounts.hand.key(),
                    is_writable: true,
                }],
            )?],
            1,
            0,
            0,
        )?;
        Ok(())
    }

    /// Stores the encrypted deck and both players' encrypted hole cards.
    #[arcium_callback(encrypted_ix = "deal")]
    pub fn deal_callback(
        ctx: Context<DealCallback>,
        output: SignedComputationOutputs<DealOutput>,
    ) -> Result<()> {
        let (deck, p0_cards, p1_cards) = match output.verify_output(
            &ctx.accounts.cluster_account,
            &ctx.accounts.computation_account,
        ) {
            Ok(DealOutput {
                field_0:
                    DealOutputStruct0 {
                        field_0: deck,
                        field_1: p0_cards,
                        field_2: p1_cards,
                    },
            }) => (deck, p0_cards, p1_cards),
            Err(_) => return Err(ErrorCode::AbortedComputation.into()),
        };

        let hand = &mut ctx.accounts.hand;
        hand.deck = deck.ciphertexts;
        hand.deck_nonce = deck.nonce;
        hand.hole_ciphertexts = [p0_cards.ciphertexts[0], p1_cards.ciphertexts[0]];
        hand.hole_nonces = [p0_cards.nonce, p1_cards.nonce];
        hand.stage = Stage::Preflop;
        hand.pending = false;

        emit!(HandDealtEvent {
            hand_id: hand.hand_id
        });
        Ok(())
    }

    /// Queues `reveal_board` for the next street: flop, turn, then river.
    pub fn next_street(ctx: Context<NextStreet>, computation_offset: u64, _hand_id: u64) -> Result<()> {
        let hand = &ctx.accounts.hand;
        require!(!hand.pending, ErrorCode::ComputationPending);
        let (start, count): (u8, u8) = match hand.stage {
            Stage::Preflop => (4, 3),
            Stage::Flop => (7, 1),
            Stage::Turn => (8, 1),
            _ => return Err(ErrorCode::InvalidStage.into()),
        };

        let args = ArgBuilder::new()
            .plaintext_u128(hand.deck_nonce)
            .account(hand.key(), DECK_OFFSET, DECK_LEN)
            .plaintext_u8(start)
            .plaintext_u8(count)
            .build();

        ctx.accounts.hand.pending = true;
        ctx.accounts.sign_pda_account.bump = ctx.bumps.sign_pda_account;

        queue_computation(
            ctx.accounts,
            computation_offset,
            args,
            vec![RevealBoardCallback::callback_ix(
                computation_offset,
                &ctx.accounts.mxe_account,
                &[CallbackAccount {
                    pubkey: ctx.accounts.hand.key(),
                    is_writable: true,
                }],
            )?],
            1,
            0,
            0,
        )?;
        Ok(())
    }

    #[arcium_callback(encrypted_ix = "reveal_board")]
    pub fn reveal_board_callback(
        ctx: Context<RevealBoardCallback>,
        output: SignedComputationOutputs<RevealBoardOutput>,
    ) -> Result<()> {
        let cards = match output.verify_output(
            &ctx.accounts.cluster_account,
            &ctx.accounts.computation_account,
        ) {
            Ok(RevealBoardOutput { field_0 }) => field_0,
            Err(_) => return Err(ErrorCode::AbortedComputation.into()),
        };

        let hand = &mut ctx.accounts.hand;
        let (first, count, next) = street_slots(hand.stage)?;
        hand.board[first..first + count].copy_from_slice(&cards[..count]);
        hand.finish_street(next);
        Ok(())
    }

    /// Queues `showdown_reveal`; the callback ranks both hands on-chain.
    pub fn showdown(ctx: Context<Showdown>, computation_offset: u64, _hand_id: u64) -> Result<()> {
        let hand = &ctx.accounts.hand;
        require!(!hand.pending, ErrorCode::ComputationPending);
        require!(hand.stage == Stage::River, ErrorCode::InvalidStage);

        let args = ArgBuilder::new()
            .plaintext_u128(hand.deck_nonce)
            .account(hand.key(), DECK_OFFSET, DECK_LEN)
            .build();

        ctx.accounts.hand.pending = true;
        ctx.accounts.sign_pda_account.bump = ctx.bumps.sign_pda_account;

        queue_computation(
            ctx.accounts,
            computation_offset,
            args,
            vec![ShowdownRevealCallback::callback_ix(
                computation_offset,
                &ctx.accounts.mxe_account,
                &[CallbackAccount {
                    pubkey: ctx.accounts.hand.key(),
                    is_writable: true,
                }],
            )?],
            1,
            0,
            0,
        )?;
        Ok(())
    }

    #[arcium_callback(encrypted_ix = "showdown_reveal")]
    pub fn showdown_reveal_callback(
        ctx: Context<ShowdownRevealCallback>,
        output: SignedComputationOutputs<ShowdownRevealOutput>,
    ) -> Result<()> {
        let hole_cards = match output.verify_output(
            &ctx.accounts.cluster_account,
            &ctx.accounts.computation_account,
        ) {
            Ok(ShowdownRevealOutput { field_0 }) => field_0,
            Err(_) => return Err(ErrorCode::AbortedComputation.into()),
        };

        ctx.accounts.hand.settle(hole_cards)
    }

    pub fn init_deal_fast_comp_def(ctx: Context<InitDealFastCompDef>, circuit_url: Option<String>) -> Result<()> {
        init_computation_def(ctx.accounts, circuit_url.map(|url| off_chain(url, circuit_hash!("deal_fast"))))?;
        Ok(())
    }

    /// Like `new_hand`, but queues `deal_fast`: the only MPC call a hand needs when
    /// both players post their reveals. `next_street` and `showdown` remain as the
    /// MPC fallback when a player does not post.
    #[allow(clippy::too_many_arguments)]
    pub fn new_fast_hand(
        ctx: Context<NewFastHand>,
        computation_offset: u64,
        hand_id: u64,
        opponent: Pubkey,
        p0_enc_pubkey: [u8; 32],
        p0_nonce: u128,
        p1_enc_pubkey: [u8; 32],
        p1_nonce: u128,
    ) -> Result<()> {
        let payer = ctx.accounts.payer.key();
        ctx.accounts.hand.start(ctx.bumps.hand, hand_id, [payer, opponent], true);

        let args = ArgBuilder::new()
            .x25519_pubkey(p0_enc_pubkey)
            .plaintext_u128(p0_nonce)
            .x25519_pubkey(p1_enc_pubkey)
            .plaintext_u128(p1_nonce)
            .build();

        ctx.accounts.sign_pda_account.bump = ctx.bumps.sign_pda_account;

        queue_computation(
            ctx.accounts,
            computation_offset,
            args,
            vec![DealFastCallback::callback_ix(
                computation_offset,
                &ctx.accounts.mxe_account,
                &[CallbackAccount {
                    pubkey: ctx.accounts.hand.key(),
                    is_writable: true,
                }],
            )?],
            1,
            0,
            0,
        )?;
        Ok(())
    }

    /// Stores the encrypted deck, each seat's encrypted secrets, the masked board and
    /// the commitments that posted reveals are checked against.
    #[arcium_callback(encrypted_ix = "deal_fast")]
    pub fn deal_fast_callback(
        ctx: Context<DealFastCallback>,
        output: SignedComputationOutputs<DealFastOutput>,
    ) -> Result<()> {
        let o = match output.verify_output(
            &ctx.accounts.cluster_account,
            &ctx.accounts.computation_account,
        ) {
            Ok(DealFastOutput { field_0 }) => field_0,
            Err(_) => return Err(ErrorCode::AbortedComputation.into()),
        };

        let hand = &mut ctx.accounts.hand;
        hand.deck = o.field_0.ciphertexts;
        hand.deck_nonce = o.field_0.nonce;
        hand.seat_ciphertexts = [o.field_1.ciphertexts, o.field_2.ciphertexts];
        hand.seat_nonces = [o.field_1.nonce, o.field_2.nonce];
        hand.masked_board = o.field_3;
        hand.commitments = o.field_4;
        hand.stage = Stage::Preflop;
        hand.pending = false;

        emit!(HandDealtEvent {
            hand_id: hand.hand_id
        });
        Ok(())
    }

    /// A player posts what the next reveal needs from them: their board shares for
    /// the next street, or their hole cards at the river. The value must match the
    /// commitment from `deal_fast`. Once both seats have posted, the street is
    /// unmasked or the hand is settled, with no MPC call.
    pub fn post_reveal(
        ctx: Context<PostReveal>,
        _hand_id: u64,
        kind: u8,
        payload: [u8; 3],
        salt: [u8; 8],
    ) -> Result<()> {
        let hand = &mut ctx.accounts.hand;
        require!(hand.fast, ErrorCode::NotFastHand);
        require!(!hand.pending, ErrorCode::ComputationPending);
        require!(kind == next_reveal_kind(hand.stage)?, ErrorCode::InvalidStage);
        let seat = hand
            .players
            .iter()
            .position(|p| *p == ctx.accounts.player.key())
            .ok_or(ErrorCode::NotAuthorized)?;
        require!(hand.posted[seat] & (1 << kind) == 0, ErrorCode::AlreadyPosted);
        require!(
            commitment(seat as u8, kind, payload, salt) == hand.commitments[4 * seat + kind as usize],
            ErrorCode::CommitmentMismatch
        );

        hand.posted[seat] |= 1 << kind;
        match kind {
            HOLE_CARDS => hand.posted_holes[seat] = [payload[0], payload[1]],
            _ => {
                let (first, count, _) = street_slots(hand.stage)?;
                hand.board_shares[seat][first..first + count].copy_from_slice(&payload[..count]);
            }
        }
        if hand.posted[1 - seat] & (1 << kind) == 0 {
            return Ok(());
        }

        if kind == HOLE_CARDS {
            let [a, b] = hand.posted_holes;
            return hand.settle([a[0], a[1], b[0], b[1]]);
        }
        let (first, count, next) = street_slots(hand.stage)?;
        for slot in first..first + count {
            hand.board[slot] = hand.masked_board[slot] ^ hand.board_shares[0][slot] ^ hand.board_shares[1][slot];
        }
        hand.finish_street(next);
        Ok(())
    }
}

fn off_chain(source: String, hash: [u8; 32]) -> CircuitSource {
    CircuitSource::OffChain(OffChainCircuitSource { source, hash })
}

/// `post_reveal` kind for hole cards; 1, 2 and 3 are the flop, turn and river shares.
const HOLE_CARDS: u8 = 0;

/// Board slots the next street fills, and the stage after it.
fn street_slots(stage: Stage) -> Result<(usize, usize, Stage)> {
    match stage {
        Stage::Preflop => Ok((0, 3, Stage::Flop)),
        Stage::Flop => Ok((3, 1, Stage::Turn)),
        Stage::Turn => Ok((4, 1, Stage::River)),
        _ => Err(ErrorCode::InvalidStage.into()),
    }
}

/// The `post_reveal` kind a fast hand waits for at `stage`.
fn next_reveal_kind(stage: Stage) -> Result<u8> {
    match stage {
        Stage::Preflop => Ok(1),
        Stage::Flop => Ok(2),
        Stage::Turn => Ok(3),
        Stage::River => Ok(HOLE_CARDS),
        _ => Err(ErrorCode::InvalidStage.into()),
    }
}

/// Mirrors `commit` in the `deal_fast` circuit: SHA3-256 over
/// [seat, kind, payload x3, salt x8], truncated to 16 bytes.
fn commitment(seat: u8, kind: u8, payload: [u8; 3], salt: [u8; 8]) -> [u8; 16] {
    let mut preimage = [0u8; 13];
    preimage[0] = seat;
    preimage[1] = kind;
    preimage[2..5].copy_from_slice(&payload);
    preimage[5..].copy_from_slice(&salt);
    let digest = Sha3_256::digest(preimage);
    let mut truncated = [0u8; 16];
    truncated.copy_from_slice(&digest[..16]);
    truncated
}

impl Hand {
    fn start(&mut self, bump: u8, hand_id: u64, players: [Pubkey; 2], fast: bool) {
        self.bump = bump;
        self.hand_id = hand_id;
        self.players = players;
        self.fast = fast;
        self.stage = Stage::Dealing;
        self.pending = true;
        self.board = [NO_CARD; 5];
        self.hole_cards = [NO_CARD; 4];
        self.winner = NO_CARD;
    }

    fn finish_street(&mut self, next: Stage) {
        self.stage = next;
        self.pending = false;
        emit!(BoardRevealedEvent {
            hand_id: self.hand_id,
            board: self.board,
        });
    }

    /// Ranks both hands against the board and completes the hand.
    fn settle(&mut self, hole_cards: [u8; 4]) -> Result<()> {
        require!(self.stage == Stage::River, ErrorCode::InvalidStage);
        let b = self.board;
        let scores = [
            score_seven(&[hole_cards[0], hole_cards[1], b[0], b[1], b[2], b[3], b[4]]),
            score_seven(&[hole_cards[2], hole_cards[3], b[0], b[1], b[2], b[3], b[4]]),
        ];
        self.hole_cards = hole_cards;
        self.scores = scores;
        self.winner = match scores[0].cmp(&scores[1]) {
            std::cmp::Ordering::Greater => 0,
            std::cmp::Ordering::Less => 1,
            std::cmp::Ordering::Equal => 2,
        };
        self.stage = Stage::Complete;
        self.pending = false;

        emit!(ShowdownEvent {
            hand_id: self.hand_id,
            hole_cards,
            scores,
            winner: self.winner,
        });
        Ok(())
    }
}

/// Ranks the best five-card hand among seven cards; a higher score wins.
/// Score = category << 20 | up to five 4-bit tie-break ranks (deuce = 0 .. ace = 12).
/// Categories: 0 high card, 1 pair, 2 two pair, 3 trips, 4 straight, 5 flush,
/// 6 full house, 7 quads, 8 straight flush.
pub fn score_seven(cards: &[u8; 7]) -> u32 {
    let mut counts = [0u8; 13];
    let mut suit_masks = [0u16; 4];
    for &card in cards {
        let rank = (card % 13 + 12) % 13;
        counts[rank as usize] += 1;
        suit_masks[(card / 13) as usize] |= 1 << rank;
    }

    if let Some(&flush) = suit_masks.iter().find(|mask| mask.count_ones() >= 5) {
        return match straight_high(flush) {
            Some(high) => score(8, &[high]),
            None => score(5, &highest(flush, 5)),
        };
    }

    let present = suit_masks.iter().fold(0u16, |acc, mask| acc | mask);
    let with_count =
        |n: u8| -> Vec<u8> { (0..13u8).rev().filter(|&r| counts[r as usize] == n).collect() };
    let (quads, trips, pairs) = (with_count(4), with_count(3), with_count(2));

    if let Some(&q) = quads.first() {
        return score(7, &[q, highest(present & !(1 << q), 1)[0]]);
    }
    if let Some(&t) = trips.first() {
        // A second set of trips plays as the pair of a full house.
        if let Some(p) = trips.get(1).into_iter().chain(pairs.first()).copied().max() {
            return score(6, &[t, p]);
        }
    }
    if let Some(high) = straight_high(present) {
        return score(4, &[high]);
    }
    if let Some(&t) = trips.first() {
        let k = highest(present & !(1 << t), 2);
        return score(3, &[t, k[0], k[1]]);
    }
    if pairs.len() >= 2 {
        let (a, b) = (pairs[0], pairs[1]);
        return score(2, &[a, b, highest(present & !(1 << a) & !(1 << b), 1)[0]]);
    }
    if let Some(&p) = pairs.first() {
        let k = highest(present & !(1 << p), 3);
        return score(1, &[p, k[0], k[1], k[2]]);
    }
    score(0, &highest(present, 5))
}

/// Highest rank of a five-card straight in `mask`, counting the ace as low too.
fn straight_high(mask: u16) -> Option<u8> {
    // Bit 0 is the low ace; bit r + 1 is rank r.
    let extended = (mask << 1) | ((mask >> 12) & 1);
    (4..=13u8)
        .rev()
        .find(|&top| (extended >> (top - 4)) & 0b11111 == 0b11111)
        .map(|top| top - 1)
}

/// The `n` highest ranks set in `mask`, highest first.
fn highest(mask: u16, n: usize) -> Vec<u8> {
    (0..13u8).rev().filter(|&r| mask & (1 << r) != 0).take(n).collect()
}

fn score(category: u32, ranks: &[u8]) -> u32 {
    ranks
        .iter()
        .enumerate()
        .fold(category << 20, |acc, (i, &r)| acc | (r as u32) << (16 - 4 * i))
}

#[queue_computation_accounts("deal", payer)]
#[derive(Accounts)]
#[instruction(computation_offset: u64, hand_id: u64)]
pub struct NewHand<'info> {
    #[account(mut)]
    pub payer: Signer<'info>,
    #[account(
        init_if_needed,
        space = 9,
        payer = payer,
        seeds = [&SIGN_PDA_SEED],
        bump,
        address = derive_sign_pda!(),
    )]
    pub sign_pda_account: Account<'info, ArciumSignerAccount>,
    #[account(
        address = derive_mxe_pda!()
    )]
    pub mxe_account: Box<Account<'info, MXEAccount>>,
    #[account(
        mut,
        address = derive_mempool_pda!(mxe_account)
    )]
    /// CHECK: mempool_account, checked by the arcium program.
    pub mempool_account: UncheckedAccount<'info>,
    #[account(
        mut,
        address = derive_execpool_pda!(mxe_account)
    )]
    /// CHECK: executing_pool, checked by the arcium program.
    pub executing_pool: UncheckedAccount<'info>,
    #[account(
        mut,
        address = derive_comp_pda!(computation_offset, mxe_account)
    )]
    /// CHECK: computation_account, checked by the arcium program.
    pub computation_account: UncheckedAccount<'info>,
    #[account(
        address = derive_comp_def_pda!(COMP_DEF_OFFSET_DEAL)
    )]
    pub comp_def_account: Box<Account<'info, ComputationDefinitionAccount>>,
    #[account(
        mut,
        address = derive_cluster_pda!(mxe_account)
    )]
    pub cluster_account: Box<Account<'info, Cluster>>,
    #[account(
        mut,
        address = ARCIUM_FEE_POOL_ACCOUNT_ADDRESS,
    )]
    pub pool_account: Account<'info, FeePool>,
    #[account(
        mut,
        address = ARCIUM_CLOCK_ACCOUNT_ADDRESS,
    )]
    pub clock_account: Account<'info, ClockAccount>,
    pub system_program: Program<'info, System>,
    pub arcium_program: Program<'info, Arcium>,
    #[account(
        init,
        payer = payer,
        space = 8 + Hand::INIT_SPACE,
        seeds = [b"hand".as_ref(), hand_id.to_le_bytes().as_ref()],
        bump,
    )]
    pub hand: Account<'info, Hand>,
}

#[callback_accounts("deal")]
#[derive(Accounts)]
pub struct DealCallback<'info> {
    pub arcium_program: Program<'info, Arcium>,
    #[account(
        address = derive_comp_def_pda!(COMP_DEF_OFFSET_DEAL)
    )]
    pub comp_def_account: Box<Account<'info, ComputationDefinitionAccount>>,
    #[account(
        address = derive_mxe_pda!()
    )]
    pub mxe_account: Box<Account<'info, MXEAccount>>,
    /// CHECK: computation_account, checked by arcium program via constraints in the callback context.
    pub computation_account: UncheckedAccount<'info>,
    #[account(
        address = derive_cluster_pda!(mxe_account)
    )]
    pub cluster_account: Box<Account<'info, Cluster>>,
    #[account(address = ::arcium_anchor::solana_instructions_sysvar::ID)]
    /// CHECK: instructions_sysvar, checked by the account constraint
    pub instructions_sysvar: UncheckedAccount<'info>,
    #[account(mut)]
    pub hand: Account<'info, Hand>,
}

#[init_computation_definition_accounts("deal", payer)]
#[derive(Accounts)]
pub struct InitDealCompDef<'info> {
    #[account(mut)]
    pub payer: Signer<'info>,
    #[account(
        mut,
        address = derive_mxe_pda!()
    )]
    pub mxe_account: Box<Account<'info, MXEAccount>>,
    #[account(mut)]
    /// CHECK: comp_def_account, checked by arcium program.
    /// Can't check it here as it's not initialized yet.
    pub comp_def_account: UncheckedAccount<'info>,
    #[account(mut, address = derive_mxe_lut_pda!(mxe_account.lut_offset_slot))]
    /// CHECK: address_lookup_table, checked by arcium program.
    pub address_lookup_table: UncheckedAccount<'info>,
    #[account(address = LUT_PROGRAM_ID)]
    /// CHECK: lut_program is the Address Lookup Table program.
    pub lut_program: UncheckedAccount<'info>,
    pub arcium_program: Program<'info, Arcium>,
    pub system_program: Program<'info, System>,
}

#[queue_computation_accounts("reveal_board", payer)]
#[derive(Accounts)]
#[instruction(computation_offset: u64, _hand_id: u64)]
pub struct NextStreet<'info> {
    #[account(mut)]
    pub payer: Signer<'info>,
    #[account(
        init_if_needed,
        space = 9,
        payer = payer,
        seeds = [&SIGN_PDA_SEED],
        bump,
        address = derive_sign_pda!(),
    )]
    pub sign_pda_account: Account<'info, ArciumSignerAccount>,
    #[account(
        address = derive_mxe_pda!()
    )]
    pub mxe_account: Box<Account<'info, MXEAccount>>,
    #[account(
        mut,
        address = derive_mempool_pda!(mxe_account)
    )]
    /// CHECK: mempool_account, checked by the arcium program.
    pub mempool_account: UncheckedAccount<'info>,
    #[account(
        mut,
        address = derive_execpool_pda!(mxe_account)
    )]
    /// CHECK: executing_pool, checked by the arcium program.
    pub executing_pool: UncheckedAccount<'info>,
    #[account(
        mut,
        address = derive_comp_pda!(computation_offset, mxe_account)
    )]
    /// CHECK: computation_account, checked by the arcium program.
    pub computation_account: UncheckedAccount<'info>,
    #[account(
        address = derive_comp_def_pda!(COMP_DEF_OFFSET_REVEAL_BOARD)
    )]
    pub comp_def_account: Box<Account<'info, ComputationDefinitionAccount>>,
    #[account(
        mut,
        address = derive_cluster_pda!(mxe_account)
    )]
    pub cluster_account: Box<Account<'info, Cluster>>,
    #[account(
        mut,
        address = ARCIUM_FEE_POOL_ACCOUNT_ADDRESS,
    )]
    pub pool_account: Account<'info, FeePool>,
    #[account(
        mut,
        address = ARCIUM_CLOCK_ACCOUNT_ADDRESS,
    )]
    pub clock_account: Account<'info, ClockAccount>,
    pub system_program: Program<'info, System>,
    pub arcium_program: Program<'info, Arcium>,
    #[account(
        mut,
        seeds = [b"hand".as_ref(), _hand_id.to_le_bytes().as_ref()],
        bump = hand.bump,
        constraint = hand.players.contains(&payer.key()) @ ErrorCode::NotAuthorized,
    )]
    pub hand: Box<Account<'info, Hand>>,
}

#[callback_accounts("reveal_board")]
#[derive(Accounts)]
pub struct RevealBoardCallback<'info> {
    pub arcium_program: Program<'info, Arcium>,
    #[account(
        address = derive_comp_def_pda!(COMP_DEF_OFFSET_REVEAL_BOARD)
    )]
    pub comp_def_account: Box<Account<'info, ComputationDefinitionAccount>>,
    #[account(
        address = derive_mxe_pda!()
    )]
    pub mxe_account: Box<Account<'info, MXEAccount>>,
    /// CHECK: computation_account, checked by arcium program via constraints in the callback context.
    pub computation_account: UncheckedAccount<'info>,
    #[account(
        address = derive_cluster_pda!(mxe_account)
    )]
    pub cluster_account: Box<Account<'info, Cluster>>,
    #[account(address = ::arcium_anchor::solana_instructions_sysvar::ID)]
    /// CHECK: instructions_sysvar, checked by the account constraint
    pub instructions_sysvar: UncheckedAccount<'info>,
    #[account(mut)]
    pub hand: Account<'info, Hand>,
}

#[init_computation_definition_accounts("reveal_board", payer)]
#[derive(Accounts)]
pub struct InitRevealBoardCompDef<'info> {
    #[account(mut)]
    pub payer: Signer<'info>,
    #[account(
        mut,
        address = derive_mxe_pda!()
    )]
    pub mxe_account: Box<Account<'info, MXEAccount>>,
    #[account(mut)]
    /// CHECK: comp_def_account, checked by arcium program.
    /// Can't check it here as it's not initialized yet.
    pub comp_def_account: UncheckedAccount<'info>,
    #[account(mut, address = derive_mxe_lut_pda!(mxe_account.lut_offset_slot))]
    /// CHECK: address_lookup_table, checked by arcium program.
    pub address_lookup_table: UncheckedAccount<'info>,
    #[account(address = LUT_PROGRAM_ID)]
    /// CHECK: lut_program is the Address Lookup Table program.
    pub lut_program: UncheckedAccount<'info>,
    pub arcium_program: Program<'info, Arcium>,
    pub system_program: Program<'info, System>,
}

#[queue_computation_accounts("showdown_reveal", payer)]
#[derive(Accounts)]
#[instruction(computation_offset: u64, _hand_id: u64)]
pub struct Showdown<'info> {
    #[account(mut)]
    pub payer: Signer<'info>,
    #[account(
        init_if_needed,
        space = 9,
        payer = payer,
        seeds = [&SIGN_PDA_SEED],
        bump,
        address = derive_sign_pda!(),
    )]
    pub sign_pda_account: Account<'info, ArciumSignerAccount>,
    #[account(
        address = derive_mxe_pda!()
    )]
    pub mxe_account: Box<Account<'info, MXEAccount>>,
    #[account(
        mut,
        address = derive_mempool_pda!(mxe_account)
    )]
    /// CHECK: mempool_account, checked by the arcium program.
    pub mempool_account: UncheckedAccount<'info>,
    #[account(
        mut,
        address = derive_execpool_pda!(mxe_account)
    )]
    /// CHECK: executing_pool, checked by the arcium program.
    pub executing_pool: UncheckedAccount<'info>,
    #[account(
        mut,
        address = derive_comp_pda!(computation_offset, mxe_account)
    )]
    /// CHECK: computation_account, checked by the arcium program.
    pub computation_account: UncheckedAccount<'info>,
    #[account(
        address = derive_comp_def_pda!(COMP_DEF_OFFSET_SHOWDOWN_REVEAL)
    )]
    pub comp_def_account: Box<Account<'info, ComputationDefinitionAccount>>,
    #[account(
        mut,
        address = derive_cluster_pda!(mxe_account)
    )]
    pub cluster_account: Box<Account<'info, Cluster>>,
    #[account(
        mut,
        address = ARCIUM_FEE_POOL_ACCOUNT_ADDRESS,
    )]
    pub pool_account: Account<'info, FeePool>,
    #[account(
        mut,
        address = ARCIUM_CLOCK_ACCOUNT_ADDRESS,
    )]
    pub clock_account: Account<'info, ClockAccount>,
    pub system_program: Program<'info, System>,
    pub arcium_program: Program<'info, Arcium>,
    #[account(
        mut,
        seeds = [b"hand".as_ref(), _hand_id.to_le_bytes().as_ref()],
        bump = hand.bump,
        constraint = hand.players.contains(&payer.key()) @ ErrorCode::NotAuthorized,
    )]
    pub hand: Box<Account<'info, Hand>>,
}

#[callback_accounts("showdown_reveal")]
#[derive(Accounts)]
pub struct ShowdownRevealCallback<'info> {
    pub arcium_program: Program<'info, Arcium>,
    #[account(
        address = derive_comp_def_pda!(COMP_DEF_OFFSET_SHOWDOWN_REVEAL)
    )]
    pub comp_def_account: Box<Account<'info, ComputationDefinitionAccount>>,
    #[account(
        address = derive_mxe_pda!()
    )]
    pub mxe_account: Box<Account<'info, MXEAccount>>,
    /// CHECK: computation_account, checked by arcium program via constraints in the callback context.
    pub computation_account: UncheckedAccount<'info>,
    #[account(
        address = derive_cluster_pda!(mxe_account)
    )]
    pub cluster_account: Box<Account<'info, Cluster>>,
    #[account(address = ::arcium_anchor::solana_instructions_sysvar::ID)]
    /// CHECK: instructions_sysvar, checked by the account constraint
    pub instructions_sysvar: UncheckedAccount<'info>,
    #[account(mut)]
    pub hand: Account<'info, Hand>,
}

#[init_computation_definition_accounts("showdown_reveal", payer)]
#[derive(Accounts)]
pub struct InitShowdownRevealCompDef<'info> {
    #[account(mut)]
    pub payer: Signer<'info>,
    #[account(
        mut,
        address = derive_mxe_pda!()
    )]
    pub mxe_account: Box<Account<'info, MXEAccount>>,
    #[account(mut)]
    /// CHECK: comp_def_account, checked by arcium program.
    /// Can't check it here as it's not initialized yet.
    pub comp_def_account: UncheckedAccount<'info>,
    #[account(mut, address = derive_mxe_lut_pda!(mxe_account.lut_offset_slot))]
    /// CHECK: address_lookup_table, checked by arcium program.
    pub address_lookup_table: UncheckedAccount<'info>,
    #[account(address = LUT_PROGRAM_ID)]
    /// CHECK: lut_program is the Address Lookup Table program.
    pub lut_program: UncheckedAccount<'info>,
    pub arcium_program: Program<'info, Arcium>,
    pub system_program: Program<'info, System>,
}

#[queue_computation_accounts("deal_fast", payer)]
#[derive(Accounts)]
#[instruction(computation_offset: u64, hand_id: u64)]
pub struct NewFastHand<'info> {
    #[account(mut)]
    pub payer: Signer<'info>,
    #[account(
        init_if_needed,
        space = 9,
        payer = payer,
        seeds = [&SIGN_PDA_SEED],
        bump,
        address = derive_sign_pda!(),
    )]
    pub sign_pda_account: Account<'info, ArciumSignerAccount>,
    #[account(
        address = derive_mxe_pda!()
    )]
    pub mxe_account: Box<Account<'info, MXEAccount>>,
    #[account(
        mut,
        address = derive_mempool_pda!(mxe_account)
    )]
    /// CHECK: mempool_account, checked by the arcium program.
    pub mempool_account: UncheckedAccount<'info>,
    #[account(
        mut,
        address = derive_execpool_pda!(mxe_account)
    )]
    /// CHECK: executing_pool, checked by the arcium program.
    pub executing_pool: UncheckedAccount<'info>,
    #[account(
        mut,
        address = derive_comp_pda!(computation_offset, mxe_account)
    )]
    /// CHECK: computation_account, checked by the arcium program.
    pub computation_account: UncheckedAccount<'info>,
    #[account(
        address = derive_comp_def_pda!(COMP_DEF_OFFSET_DEAL_FAST)
    )]
    pub comp_def_account: Box<Account<'info, ComputationDefinitionAccount>>,
    #[account(
        mut,
        address = derive_cluster_pda!(mxe_account)
    )]
    pub cluster_account: Box<Account<'info, Cluster>>,
    #[account(
        mut,
        address = ARCIUM_FEE_POOL_ACCOUNT_ADDRESS,
    )]
    pub pool_account: Account<'info, FeePool>,
    #[account(
        mut,
        address = ARCIUM_CLOCK_ACCOUNT_ADDRESS,
    )]
    pub clock_account: Account<'info, ClockAccount>,
    pub system_program: Program<'info, System>,
    pub arcium_program: Program<'info, Arcium>,
    #[account(
        init,
        payer = payer,
        space = 8 + Hand::INIT_SPACE,
        seeds = [b"hand".as_ref(), hand_id.to_le_bytes().as_ref()],
        bump,
    )]
    pub hand: Account<'info, Hand>,
}

#[callback_accounts("deal_fast")]
#[derive(Accounts)]
pub struct DealFastCallback<'info> {
    pub arcium_program: Program<'info, Arcium>,
    #[account(
        address = derive_comp_def_pda!(COMP_DEF_OFFSET_DEAL_FAST)
    )]
    pub comp_def_account: Box<Account<'info, ComputationDefinitionAccount>>,
    #[account(
        address = derive_mxe_pda!()
    )]
    pub mxe_account: Box<Account<'info, MXEAccount>>,
    /// CHECK: computation_account, checked by arcium program via constraints in the callback context.
    pub computation_account: UncheckedAccount<'info>,
    #[account(
        address = derive_cluster_pda!(mxe_account)
    )]
    pub cluster_account: Box<Account<'info, Cluster>>,
    #[account(address = ::arcium_anchor::solana_instructions_sysvar::ID)]
    /// CHECK: instructions_sysvar, checked by the account constraint
    pub instructions_sysvar: UncheckedAccount<'info>,
    #[account(mut)]
    pub hand: Account<'info, Hand>,
}

#[init_computation_definition_accounts("deal_fast", payer)]
#[derive(Accounts)]
pub struct InitDealFastCompDef<'info> {
    #[account(mut)]
    pub payer: Signer<'info>,
    #[account(
        mut,
        address = derive_mxe_pda!()
    )]
    pub mxe_account: Box<Account<'info, MXEAccount>>,
    #[account(mut)]
    /// CHECK: comp_def_account, checked by arcium program.
    /// Can't check it here as it's not initialized yet.
    pub comp_def_account: UncheckedAccount<'info>,
    #[account(mut, address = derive_mxe_lut_pda!(mxe_account.lut_offset_slot))]
    /// CHECK: address_lookup_table, checked by arcium program.
    pub address_lookup_table: UncheckedAccount<'info>,
    #[account(address = LUT_PROGRAM_ID)]
    /// CHECK: lut_program is the Address Lookup Table program.
    pub lut_program: UncheckedAccount<'info>,
    pub arcium_program: Program<'info, Arcium>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
#[instruction(_hand_id: u64)]
pub struct PostReveal<'info> {
    pub player: Signer<'info>,
    #[account(
        mut,
        seeds = [b"hand".as_ref(), _hand_id.to_le_bytes().as_ref()],
        bump = hand.bump,
    )]
    pub hand: Box<Account<'info, Hand>>,
}

/// One heads-up hand. Ciphertext fields are fed back into circuits by byte
/// offset, so `deck` must stay the first field (see `DECK_OFFSET`).
#[account]
#[derive(InitSpace)]
pub struct Hand {
    /// Encrypted deck, 2 chunks (Pack<[u8; 52]> = 2 field elements); MXE-only.
    pub deck: [[u8; 32]; 2],
    pub deck_nonce: u128,
    /// Each player's encrypted hole cards (Pack<[u8; 2]>), readable only by that player.
    pub hole_ciphertexts: [[u8; 32]; 2],
    pub hole_nonces: [u128; 2],
    pub hand_id: u64,
    pub players: [Pubkey; 2],
    pub stage: Stage,
    /// True while a computation for this hand is queued; blocks overlapping queues.
    pub pending: bool,
    /// Flop, turn, river; `NO_CARD` until revealed.
    pub board: [u8; 5],
    /// [p0 a, p0 b, p1 a, p1 b], filled at showdown.
    pub hole_cards: [u8; 4],
    pub scores: [u32; 2],
    /// 0 or 1 for the winning seat, 2 for a split pot, `NO_CARD` before showdown.
    pub winner: u8,
    pub bump: u8,
    /// Dealt with `deal_fast`; the fields below are only used in that mode.
    pub fast: bool,
    /// Board cards XORed with both seats' shares; public from the deal.
    pub masked_board: [u8; 5],
    /// Truncated SHA3-256 commitments, indexed `4 * seat + kind`.
    pub commitments: [[u8; 16]; 8],
    /// Each seat's encrypted secrets (Pack<[u8; 39]>, 2 field elements).
    pub seat_ciphertexts: [[[u8; 32]; 2]; 2],
    pub seat_nonces: [u128; 2],
    /// Per seat, bit `kind` is set once that seat has posted that kind.
    pub posted: [u8; 2],
    /// Board shares posted so far, per seat and board slot.
    pub board_shares: [[u8; 5]; 2],
    /// Hole cards posted at showdown, per seat.
    pub posted_holes: [[u8; 2]; 2],
}

#[repr(u8)]
#[derive(InitSpace, AnchorSerialize, AnchorDeserialize, Clone, Copy, PartialEq, Eq, Debug)]
pub enum Stage {
    Dealing,
    Preflop,
    Flop,
    Turn,
    River,
    Complete,
}

#[event]
pub struct HandDealtEvent {
    pub hand_id: u64,
}

#[event]
pub struct BoardRevealedEvent {
    pub hand_id: u64,
    pub board: [u8; 5],
}

#[event]
pub struct ShowdownEvent {
    pub hand_id: u64,
    pub hole_cards: [u8; 4],
    pub scores: [u32; 2],
    pub winner: u8,
}

#[error_code]
pub enum ErrorCode {
    #[msg("The computation was aborted")]
    AbortedComputation,
    #[msg("Action not allowed at this stage of the hand")]
    InvalidStage,
    #[msg("A computation for this hand is still pending")]
    ComputationPending,
    #[msg("Cluster not set")]
    ClusterNotSet,
    #[msg("Not authorized to perform this action")]
    NotAuthorized,
    #[msg("This hand was not dealt with deal_fast")]
    NotFastHand,
    #[msg("This seat already posted this reveal")]
    AlreadyPosted,
    #[msg("Posted value does not match the dealt commitment")]
    CommitmentMismatch,
}

#[cfg(test)]
mod tests {
    use super::score_seven;

    /// Builds a card from a rank char (A, 2-9, T, J, Q, K) and a suit index 0-3.
    fn c(rank: char, suit: u8) -> u8 {
        let r = "A23456789TJQK".find(rank).unwrap() as u8;
        suit * 13 + r
    }

    fn category(cards: [u8; 7]) -> u32 {
        score_seven(&cards) >> 20
    }

    #[test]
    fn categories() {
        let s = |r, s| c(r, s);
        assert_eq!(category([s('A', 0), s('K', 0), s('Q', 0), s('J', 0), s('T', 0), s('2', 1), s('3', 2)]), 8);
        assert_eq!(category([s('9', 0), s('9', 1), s('9', 2), s('9', 3), s('2', 1), s('5', 2), s('K', 0)]), 7);
        assert_eq!(category([s('9', 0), s('9', 1), s('9', 2), s('4', 3), s('4', 1), s('5', 2), s('K', 0)]), 6);
        assert_eq!(category([s('2', 0), s('7', 0), s('9', 0), s('J', 0), s('K', 0), s('K', 1), s('K', 2)]), 5);
        assert_eq!(category([s('A', 0), s('2', 1), s('3', 2), s('4', 3), s('5', 0), s('9', 1), s('K', 2)]), 4);
        assert_eq!(category([s('8', 0), s('8', 1), s('8', 2), s('2', 3), s('5', 0), s('9', 1), s('K', 2)]), 3);
        assert_eq!(category([s('8', 0), s('8', 1), s('4', 2), s('4', 3), s('5', 0), s('9', 1), s('K', 2)]), 2);
        assert_eq!(category([s('8', 0), s('8', 1), s('3', 2), s('4', 3), s('6', 0), s('J', 1), s('K', 2)]), 1);
        assert_eq!(category([s('2', 0), s('4', 1), s('6', 2), s('8', 3), s('T', 0), s('Q', 1), s('K', 2)]), 0);
    }

    #[test]
    fn tie_breaks() {
        let s = |r, s| c(r, s);
        // Wheel (5-high) loses to a 6-high straight.
        let wheel = score_seven(&[s('A', 0), s('2', 1), s('3', 2), s('4', 3), s('5', 0), s('9', 1), s('K', 2)]);
        let six_high = score_seven(&[s('6', 0), s('2', 1), s('3', 2), s('4', 3), s('5', 0), s('9', 1), s('K', 2)]);
        assert!(six_high > wheel);
        // Two sets of trips make a full house using the lower set as the pair.
        let two_trips = score_seven(&[s('9', 0), s('9', 1), s('9', 2), s('4', 3), s('4', 1), s('4', 2), s('K', 0)]);
        let nines_full_of_fours = score_seven(&[s('9', 0), s('9', 1), s('9', 2), s('4', 3), s('4', 1), s('2', 2), s('K', 0)]);
        assert_eq!(two_trips, nines_full_of_fours);
        // With three pairs, the third pair's rank can be the kicker.
        let three_pairs = score_seven(&[s('Q', 0), s('Q', 1), s('8', 2), s('8', 3), s('J', 0), s('J', 1), s('2', 2)]);
        let qj_with_8 = score_seven(&[s('Q', 0), s('Q', 1), s('J', 2), s('J', 3), s('8', 0), s('3', 1), s('2', 2)]);
        assert_eq!(three_pairs, qj_with_8);
        // Pair of aces with K kicker beats pair of aces with Q kicker.
        let ak = score_seven(&[s('A', 0), s('A', 1), s('K', 2), s('7', 3), s('5', 0), s('3', 1), s('2', 2)]);
        let aq = score_seven(&[s('A', 0), s('A', 1), s('Q', 2), s('7', 3), s('5', 0), s('3', 1), s('2', 2)]);
        assert!(ak > aq);
        // Board plays: identical best five split the pot.
        let board = [s('A', 0), s('K', 1), s('Q', 2), s('J', 3), s('T', 0)];
        let p0 = score_seven(&[s('2', 1), s('3', 2), board[0], board[1], board[2], board[3], board[4]]);
        let p1 = score_seven(&[s('4', 1), s('5', 2), board[0], board[1], board[2], board[3], board[4]]);
        assert_eq!(p0, p1);
    }
}

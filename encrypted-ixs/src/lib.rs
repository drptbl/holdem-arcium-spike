//! Heads-up Hold'em circuits: shuffle and deal an encrypted 52-card deck, reveal
//! board cards street by street, and reveal both hands at showdown. The deck stays
//! encrypted to the MXE; each player can decrypt only their own hole cards until
//! showdown. Forked from the arcium-hq blackjack example. See README.md.
//!
//! Deck layout after the shuffle: [p0 a, p1 a, p0 b, p1 b, flop x3, turn, river, ...].

use arcis::*;

#[encrypted]
mod circuits {
    use arcis::*;

    /// Cards are 0-51: rank = card % 13 (0 = ace), suit = card / 13.
    const INITIAL_DECK: [u8; 52] = [
        0u8, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
        25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47,
        48, 49, 50, 51,
    ];

    type Deck = Pack<[u8; 52]>;
    type HoleCards = Pack<[u8; 2]>;

    /// Shuffles the deck and deals two hole cards to each player, each encrypted
    /// to that player's x25519 key. The deck itself is encrypted to the MXE only.
    #[instruction]
    pub fn deal(
        p0: Shared,
        p1: Shared,
    ) -> (Enc<Mxe, Deck>, Enc<Shared, HoleCards>, Enc<Shared, HoleCards>) {
        let mut deck = INITIAL_DECK;
        ArcisRNG::shuffle(&mut deck);

        (
            Mxe::get().from_arcis(Pack::new(deck)),
            p0.from_arcis(Pack::new([deck[0], deck[2]])),
            p1.from_arcis(Pack::new([deck[1], deck[3]])),
        )
    }

    /// Reveals `count` board cards (3 for the flop, 1 for turn and river) starting
    /// at deck index `start`. Unused slots are 255 so nothing beyond `count` leaks.
    #[instruction]
    pub fn reveal_board(deck_ctxt: Enc<Mxe, Deck>, start: u8, count: u8) -> [u8; 3] {
        let deck = deck_ctxt.to_arcis().unpack();

        let mut cards = [255u8; 3];
        for i in 0..3 {
            let card = deck[start as usize + i];
            cards[i] = if (i as u8) < count { card } else { 255 };
        }

        cards.reveal()
    }

    /// Reveals both players' hole cards as [p0 a, p0 b, p1 a, p1 b].
    #[instruction]
    pub fn showdown_reveal(deck_ctxt: Enc<Mxe, Deck>) -> [u8; 4] {
        let deck = deck_ctxt.to_arcis().unpack();
        [deck[0], deck[2], deck[1], deck[3]].reveal()
    }

    /// Per-seat secrets for the one-call deal, encrypted to that seat:
    /// [hole a, hole b, flop shares x3, turn share, river share, salts x4 (8 bytes each:
    /// hole, flop, turn, river)].
    type SeatSecrets = Pack<[u8; 39]>;

    /// Random board shares and salts for one seat: [shares x5, salts x32].
    type SeatRandom = [u8; 37];

    /// One-call deal: shuffles, deals hole cards, and publishes the board masked by
    /// both seats' random shares, so players reveal each street by posting their
    /// shares instead of waiting on MPC. Also publishes a commitment per seat and
    /// kind (0 hole cards, 1 flop, 2 turn, 3 river) that the program checks posted
    /// values against. The deck stays MXE-encrypted for the fallback reveals.
    #[instruction]
    pub fn deal_fast(
        p0: Shared,
        p1: Shared,
    ) -> (
        Enc<Mxe, Deck>,
        Enc<Shared, SeatSecrets>,
        Enc<Shared, SeatSecrets>,
        [u8; 5],
        [[u8; 16]; 8],
    ) {
        let mut deck = INITIAL_DECK;
        ArcisRNG::shuffle(&mut deck);

        let holes = [[deck[0], deck[2]], [deck[1], deck[3]]];
        let random = [
            ArcisRNG::gen_uniform::<SeatRandom>(),
            ArcisRNG::gen_uniform::<SeatRandom>(),
        ];

        let mut masked_board = [0u8; 5];
        for i in 0..5 {
            masked_board[i] = deck[4 + i] ^ random[0][i] ^ random[1][i];
        }

        let mut secrets = [[0u8; 39]; 2];
        let mut commitments = [[0u8; 16]; 8];
        for seat in 0..2 {
            let r = random[seat];
            secrets[seat][0] = holes[seat][0];
            secrets[seat][1] = holes[seat][1];
            for i in 0..37 {
                secrets[seat][2 + i] = r[i];
            }
            let salt = |from: usize| {
                let mut s = [0u8; 8];
                for i in 0..8 {
                    s[i] = r[from + i];
                }
                s
            };
            commitments[4 * seat] = commit(seat as u8, 0, [holes[seat][0], holes[seat][1], 0], salt(5));
            commitments[4 * seat + 1] = commit(seat as u8, 1, [r[0], r[1], r[2]], salt(13));
            commitments[4 * seat + 2] = commit(seat as u8, 2, [r[3], 0, 0], salt(21));
            commitments[4 * seat + 3] = commit(seat as u8, 3, [r[4], 0, 0], salt(29));
        }

        (
            Mxe::get().from_arcis(Pack::new(deck)),
            p0.from_arcis(Pack::new(secrets[0])),
            p1.from_arcis(Pack::new(secrets[1])),
            masked_board.reveal(),
            commitments.reveal(),
        )
    }

    /// First 16 bytes of SHA3-256 over [seat, kind, payload x3, salt x8]; the program
    /// recomputes this when a player posts the payload and salt.
    fn commit(seat: u8, kind: u8, payload: [u8; 3], salt: [u8; 8]) -> [u8; 16] {
        let mut preimage = [0u8; 13];
        preimage[0] = seat;
        preimage[1] = kind;
        for i in 0..3 {
            preimage[2 + i] = payload[i];
        }
        for i in 0..8 {
            preimage[5 + i] = salt[i];
        }
        let digest = SHA3_256::new().digest(&preimage);
        let mut truncated = [0u8; 16];
        for i in 0..16 {
            truncated[i] = digest[i];
        }
        truncated
    }
}

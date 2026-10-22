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
}

mod hasher;
mod height;

pub use hasher::LedgerHasher;
pub use height::Height;

pub type Jmt<'a, R> = jmt::JellyfishMerkleTree<'a, R, LedgerHasher>;

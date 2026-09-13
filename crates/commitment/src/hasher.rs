use jmt::SimpleHasher;

const JMT_DOMAIN: &str = "works.ferna.anchor.commitment.jmt.v0";

pub struct LedgerHasher {
    buffer: Vec<u8>,
}

impl SimpleHasher for LedgerHasher {
    fn new() -> Self {
        Self { buffer: Vec::new() }
    }

    fn update(&mut self, data: &[u8]) {
        self.buffer.extend_from_slice(data);
    }

    fn finalize(self) -> [u8; 32] {
        blake3::derive_key(JMT_DOMAIN, &self.buffer)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_depends_on_full_buffer_not_chunking() {
        let mut chunked = LedgerHasher::new();
        chunked.update(b"abc");
        chunked.update(b"xyz");

        let mut whole = LedgerHasher::new();
        whole.update(b"abcxyz");

        assert_eq!(chunked.finalize(), whole.finalize());
    }

    #[test]
    fn different_input_hashes_differently() {
        let mut a = LedgerHasher::new();
        a.update(b"abc");

        let mut b = LedgerHasher::new();
        b.update(b"xyz");

        assert_ne!(a.finalize(), b.finalize());
    }

    #[test]
    fn empty_input_is_hashable() {
        assert_eq!(
            LedgerHasher::new().finalize(),
            LedgerHasher::new().finalize()
        );
    }
}

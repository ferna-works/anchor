#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Height(u64);

impl Height {
    /// Wraps a raw block height.
    pub const fn from_u64(value: u64) -> Self {
        Self(value)
    }

    /// Returns the raw block height.
    pub const fn as_u64(self) -> u64 {
        self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_through_u64() {
        assert_eq!(Height::from_u64(42).as_u64(), 42);
    }

    #[test]
    fn orders_by_value() {
        assert!(Height::from_u64(1) < Height::from_u64(2));
    }
}

struct ParticipantIndex(pub u64);

impl ParticipantIndex {
    pub fn new(x: u64) -> Self {
        // TODO: use thiserror
        assert_ne!(x, 0, "ParticipantIndex must be nonzero");
        Self(x)
    }
}

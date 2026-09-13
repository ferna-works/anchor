use anchor_codec::TaggedBytes;

pub enum IdentityIdTag {}
pub type IdentityId = TaggedBytes<IdentityIdTag, 32>;

pub enum EventIdTag {}
pub type EventId = TaggedBytes<EventIdTag, 32>;

pub enum DeviceIdTag {}
pub type DeviceId = TaggedBytes<DeviceIdTag, 32>;

pub enum NextKeyCommitmentTag {}
pub type NextKeyCommitment = TaggedBytes<NextKeyCommitmentTag, 32>;

pub enum InceptionSignatureTargetTag {}
pub type InceptionSignatureTarget = TaggedBytes<InceptionSignatureTargetTag, 32>;

pub enum EventSignatureTargetTag {}
pub type EventSignatureTarget = TaggedBytes<EventSignatureTargetTag, 32>;

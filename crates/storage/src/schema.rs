use redb::TableDefinition;

pub(crate) const META_TABLE: TableDefinition<&str, u64> = TableDefinition::new("meta");
pub(crate) const IDENTITIES_TABLE: TableDefinition<&[u8], &[u8]> =
    TableDefinition::new("identities");
pub(crate) const IDENTITY_EVENTS_TABLE: TableDefinition<&[u8], &[u8]> =
    TableDefinition::new("identity_events");
pub(crate) const JMT_NODES_TABLE: TableDefinition<&[u8], &[u8]> = TableDefinition::new("jmt_nodes");
pub(crate) const JMT_HISTORY_TABLE: TableDefinition<&[u8], &[u8]> =
    TableDefinition::new("jmt_history");
pub(crate) const HEIGHT_KEY: &str = "height";

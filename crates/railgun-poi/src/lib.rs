//! Optional typed POI models and validation helpers.

mod error;
mod model;

pub use error::PoiError;
pub use model::{
    BlindedCommitment, DEFAULT_REQUIRED_POI_LIST_DESCRIPTION, DEFAULT_REQUIRED_POI_LIST_KEY,
    DEFAULT_REQUIRED_POI_LIST_NAME, PoiEventLengths, PoiEventType, PoiList, PoiListKey,
    PoiListStatus, PoiListType, PoiStatus, PreTransactionPoi, PreTransactionPoisPerTxidLeafPerList,
    TransactProofData, TxidLeafHash, TxidMerklerootIndex, default_required_poi_list,
    default_required_poi_list_key, is_required_poi_list_key, required_poi_lists,
};

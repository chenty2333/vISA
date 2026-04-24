use semantic_core::{StoreId, StoreRebindReport};

use super::store_manager::StoreManager;

const NETWORK_DRIVER_PACKAGE: &str = "driver_virtio_net";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum StoreAuthorityRebindRequest {
    NetworkDriver {
        store: StoreId,
        package: &'static str,
    },
}

pub(crate) fn plan_store_authority_rebind(
    manager: &StoreManager,
    report: StoreRebindReport,
) -> Option<StoreAuthorityRebindRequest> {
    let record = manager
        .records()
        .iter()
        .find(|record| record.store == report.store)?;
    if record.rebind_policy == "no-rebind" {
        return None;
    }
    if record.package == NETWORK_DRIVER_PACKAGE {
        Some(StoreAuthorityRebindRequest::NetworkDriver {
            store: record.store,
            package: record.package,
        })
    } else {
        None
    }
}

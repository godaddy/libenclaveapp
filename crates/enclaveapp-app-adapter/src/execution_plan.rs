#![cfg_attr(test, allow(clippy::unwrap_used))]

use crate::error::{AdapterError, Result};
use crate::types::IntegrationType;

/// Select the least-secret-exposing integration type from the app's supported list.
///
/// Priority order (most secure first):
/// 1. `HelperTool` — secrets never leave process
/// 2. `EnvInterpolation` — secrets in env vars only
/// 3. `TempMaterializedConfig` — secrets briefly on disk
pub fn choose_integration(supported: &[IntegrationType]) -> Result<IntegrationType> {
    if supported.contains(&IntegrationType::HelperTool) {
        return Ok(IntegrationType::HelperTool);
    }

    if supported.contains(&IntegrationType::EnvInterpolation) {
        return Ok(IntegrationType::EnvInterpolation);
    }

    if supported.contains(&IntegrationType::TempMaterializedConfig) {
        return Ok(IntegrationType::TempMaterializedConfig);
    }

    Err(AdapterError::NoSupportedIntegration)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chooses_least_secret_exposing_mode() {
        let supported = [
            IntegrationType::TempMaterializedConfig,
            IntegrationType::EnvInterpolation,
        ];

        assert_eq!(
            choose_integration(&supported).expect("integration"),
            IntegrationType::EnvInterpolation
        );
    }
}

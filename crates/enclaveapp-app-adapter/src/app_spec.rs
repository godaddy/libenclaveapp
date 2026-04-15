use crate::types::IntegrationType;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfigOverride {
    None,
    EnvironmentVariable { name: String },
    CommandLineFlag { flag: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppSpec {
    pub display_name: String,
    pub executable_name: String,
    /// Which integration types this application supports, in order of preference.
    /// The adapter will select the first type that matches an available payload.
    pub supported_integrations: Vec<IntegrationType>,
    pub config_override: ConfigOverride,
}

impl AppSpec {
    pub fn supports(&self, integration: IntegrationType) -> bool {
        self.supported_integrations.contains(&integration)
    }
}

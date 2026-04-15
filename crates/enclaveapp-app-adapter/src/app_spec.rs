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
    pub supported_integrations: Vec<IntegrationType>,
    pub config_override: ConfigOverride,
}

impl AppSpec {
    pub fn supports(&self, integration: IntegrationType) -> bool {
        self.supported_integrations.contains(&integration)
    }
}

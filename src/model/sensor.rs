use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SensorProvenance {
    HostAgent,
    NetworkProbe,
    NetworkIds,
    ProviderReadback,
}

impl SensorProvenance {
    pub(crate) const fn code(self) -> &'static str {
        match self {
            Self::HostAgent => "host-agent",
            Self::NetworkProbe => "network-probe",
            Self::NetworkIds => "network-ids",
            Self::ProviderReadback => "provider-readback",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SensorCapability {
    Readback,
    IntrusionDetection,
}

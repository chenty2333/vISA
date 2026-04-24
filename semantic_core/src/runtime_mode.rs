#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RuntimeMode {
    Research,
    Production,
    Replay,
}

impl RuntimeMode {
    pub const fn all() -> [Self; 3] {
        [Self::Research, Self::Production, Self::Replay]
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "research" => Some(Self::Research),
            "production" => Some(Self::Production),
            "replay" => Some(Self::Replay),
            _ => None,
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Research => "research",
            Self::Production => "production",
            Self::Replay => "replay",
        }
    }

    pub const fn event_log_policy(self) -> &'static str {
        match self {
            Self::Research => "full",
            Self::Production => "sampled",
            Self::Replay => "deterministic",
        }
    }

    pub const fn dmw_policy(self) -> &'static str {
        match self {
            Self::Research => "strict-quarantine",
            Self::Production => "aggressive-reuse",
            Self::Replay => "barrier-locked",
        }
    }

    pub const fn fast_path_enabled(self) -> bool {
        matches!(self, Self::Production)
    }

    pub const fn deterministic_boundary(self) -> bool {
        matches!(self, Self::Replay)
    }

    pub const fn capability_audit_policy(self) -> &'static str {
        match self {
            Self::Research => "full",
            Self::Production => "sampled",
            Self::Replay => "deterministic",
        }
    }

    pub const fn debug_metadata_policy(self) -> &'static str {
        match self {
            Self::Research => "full",
            Self::Production => "reduced",
            Self::Replay => "log-derived",
        }
    }

    pub const fn nondeterminism_policy(self) -> &'static str {
        match self {
            Self::Research => "record-at-boundary",
            Self::Production => "record-sampled-boundary",
            Self::Replay => "read-from-event-log",
        }
    }
}

impl Default for RuntimeMode {
    fn default() -> Self {
        Self::Research
    }
}

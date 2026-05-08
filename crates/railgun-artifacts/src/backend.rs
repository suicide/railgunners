//! Shared artifact backend selection metadata.

/// Requested proving backend artifact set.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ArtifactBackend {
    /// Load `wasm` only.
    Wasm,
    /// Load `dat` only.
    Native,
    /// Load both `wasm` and `dat`.
    Both,
}

impl ArtifactBackend {
    /// Returns whether this backend requires `wasm` artifacts.
    #[must_use]
    pub const fn includes_wasm(self) -> bool {
        matches!(self, Self::Wasm | Self::Both)
    }

    /// Returns whether this backend requires `dat` artifacts.
    #[must_use]
    pub const fn includes_dat(self) -> bool {
        matches!(self, Self::Native | Self::Both)
    }
}

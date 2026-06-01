//! Abstracts the SHA-256 byte sink so callers can swap in recording
//! wrappers for testing without touching the streaming call sites.
//!
//! `Sha256Sink` is a wrapper around [`sha2::Sha256`] rather than a
//! blanket trait impl: a direct impl collides with `sha2`'s own
//! `update` method (E0034 at every call site).

use sha2::{Digest, Sha256};

pub trait HashSink {
    fn update(&mut self, data: &[u8]);
}

pub struct Sha256Sink {
    inner: Sha256,
}

impl Sha256Sink {
    #[inline]
    pub fn new() -> Self {
        Self {
            inner: Sha256::new(),
        }
    }

    #[inline]
    pub fn finalize(self) -> [u8; 32] {
        sha2::Digest::finalize(self.inner).into()
    }
}

impl Default for Sha256Sink {
    fn default() -> Self {
        Self::new()
    }
}

impl HashSink for Sha256Sink {
    #[inline]
    fn update(&mut self, data: &[u8]) {
        sha2::digest::Update::update(&mut self.inner, data);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sink_digest_equals_raw_sha256() {
        let chunks: [&[u8]; 4] = [b"abc", b"", &[0u8; 64], b"trailing"];

        let mut raw = Sha256::new();
        for c in chunks {
            sha2::digest::Update::update(&mut raw, c);
        }
        let raw_digest: [u8; 32] = raw.finalize().into();

        let mut sink = Sha256Sink::new();
        for c in chunks {
            sink.update(c);
        }
        let sink_digest = sink.finalize();

        assert_eq!(raw_digest, sink_digest);
    }
}

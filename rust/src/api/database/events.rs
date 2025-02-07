// Copyright (c) 2022-2023 Yuki Kishimoto
// Copyright (c) 2023-2025 Rust Nostr Developers
// Distributed under the MIT software license

use std::ops::Deref;

use flutter_rust_bridge::frb;
use nostr_sdk::prelude::*;

use crate::api::protocol::event::_Event;

#[frb(name = "Events")]
pub struct _Events {
    inner: Events,
}

impl From<Events> for _Events {
    fn from(inner: Events) -> Self {
        Self { inner }
    }
}

impl Deref for _Events {
    type Target = Events;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

#[frb(sync)]
impl _Events {
    /// Returns the number of events in the collection.
    pub fn len(&self) -> u64 {
        self.inner.len() as u64
    }

    /// Returns the number of events in the collection.
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    /// Check if contains `Event`
    pub fn contains(&self, event: &_Event) -> bool {
        self.inner.contains(event.deref())
    }

    /// Merge events collections into a single one.
    ///
    /// Collection is converted to unbounded if one of the merge `Events` have a different hash.
    /// In other words, the filter limit is respected only if the `Events` are related to the same
    /// list of filters.
    ///
    /// **This method consumes the old `Events` collection and returns a new one!**
    pub fn merge(self, other: Self) -> Self {
        self.inner.merge(other.inner).into()
    }

    /// Get first `Event` (descending order)
    pub fn first(&self) -> Option<_Event> {
        self.inner.first().cloned().map(|e| e.into())
    }

    /// Clone and convert the collection to a vector of events.
    ///
    /// Use `toVec` method if you want to avoid the clone and consume the `Events` object.
    pub fn as_vec(&self) -> Vec<_Event> {
        self.inner.iter().cloned().map(|e| e.into()).collect()
    }

    /// Convert the collection to a vector of events.
    ///
    /// **This method consumes the `Events` collection!**
    pub fn to_vec(self) -> Vec<_Event> {
        self.inner.into_iter().map(|e| e.into()).collect()
    }
}

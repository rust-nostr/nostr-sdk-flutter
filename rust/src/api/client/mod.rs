// Copyright (c) 2022-2023 Yuki Kishimoto
// Copyright (c) 2023-2024 Rust Nostr Developers
// Distributed under the MIT software license

use anyhow::Result;
use chrono::Duration;
use flutter_rust_bridge::frb;
use nostr_sdk::prelude::*;

pub mod builder;
pub mod notification;
pub mod options;
pub mod output;

use self::builder::_ClientBuilder;
use self::notification::RelayPoolNotification;
use self::output::SendEventOutput;
use super::database::_NostrDatabase;
use super::database::events::_Events;
use super::protocol::event::_Event;
use super::protocol::event::builder::_EventBuilder;
use super::protocol::filter::_Filter;
use super::protocol::signer::_NostrSigner;
use crate::api::relay::options::_SubscribeAutoCloseOptions;
use crate::frb_generated::StreamSink;

#[frb(name = "Client")]
pub struct _Client {
    inner: Client,
}

impl From<Client> for _Client {
    fn from(inner: Client) -> Self {
        Self { inner }
    }
}

impl _Client {
    #[frb(sync)]
    pub fn new() -> Self {
        Self {
            inner: Client::default(),
        }
    }

    /// New client builder
    #[frb(sync)]
    pub fn builder() -> _ClientBuilder {
        _ClientBuilder::new()
    }

    /// Auto authenticate to relays (default: true)
    ///
    /// <https://github.com/nostr-protocol/nips/blob/master/42.md>
    #[frb(sync)]
    pub fn automatic_authentication(&self, enable: bool) {
        self.inner.automatic_authentication(enable);
    }

    /// Get database
    pub fn database(&self) -> _NostrDatabase {
        self.inner.database().clone().into()
    }

    /// Check if signer is configured
    pub async fn has_signer(&self) -> bool {
        self.inner.has_signer().await
    }

    /// Get current nostr signer
    ///
    /// Rise error if it not set.
    pub async fn signer(&self) -> Result<_NostrSigner> {
        Ok(self.inner.signer().await?.into())
    }

    /// Set nostr signer
    pub async fn set_signer(&self, signer: &_NostrSigner) {
        self.inner.set_signer(signer.inner.clone()).await;
    }

    /// Unset nostr signer
    pub async fn unset_signer(&self) {
        self.inner.unset_signer().await;
    }

    /// Reset client
    ///
    /// This method reset the client to simplify the switch to another account.
    pub async fn reset(&self) {
        self.inner.reset().await
    }

    /// Completely shutdown client
    #[inline]
    pub async fn shutdown(&self) {
        self.inner.shutdown().await
    }

    /// Add relay
    ///
    /// Relays added with this method will have both `READ` and `WRITE` flags enabled.
    ///
    /// If the relay already exists, the flags will be updated and `false` returned.
    ///
    /// If are set pool subscriptions, the new added relay will inherit them.
    ///
    /// Connection is **NOT** automatically started with relay, remember to call `connect` method!
    pub async fn add_relay(&self, url: &str) -> Result<bool> {
        Ok(self.inner.add_relay(url).await?)
    }

    /// Add discovery relay
    ///
    /// If relay already exists, this method automatically add the [`RelayServiceFlags::DISCOVERY`] flag to it and return `false`.
    ///
    /// <https://github.com/nostr-protocol/nips/blob/master/65.md>
    pub async fn add_discovery_relay(&self, url: &str) -> Result<bool> {
        Ok(self.inner.add_discovery_relay(url).await?)
    }

    /// Add read relay
    ///
    /// If relay already exists, this method add the [`RelayServiceFlags::READ`] flag to it and return `false`.
    ///
    /// If are set pool subscriptions, the new added relay will inherit them. Use `subscribe_to` method instead of `subscribe`,
    /// to avoid to set pool subscriptions.
    pub async fn add_read_relay(&self, url: &str) -> Result<bool> {
        Ok(self.inner.add_read_relay(url).await?)
    }

    /// Add write relay
    ///
    /// If relay already exists, this method add the [`RelayServiceFlags::WRITE`] flag to it and return `false`.
    pub async fn add_write_relay(&self, url: &str) -> Result<bool> {
        Ok(self.inner.add_write_relay(url).await?)
    }

    /// Remove and disconnect relay
    ///
    /// If the relay has [`RelayServiceFlags::GOSSIP`], it will not be removed from the pool and its
    /// flags will be updated (remove [`RelayServiceFlags::READ`],
    /// [`RelayServiceFlags::WRITE`] and [`RelayServiceFlags::DISCOVERY`] flags).
    ///
    /// To force remove the relay, use [`Client::force_remove_relay`].
    #[inline]
    pub async fn remove_relay(&self, url: &str) -> Result<()> {
        Ok(self.inner.remove_relay(url).await?)
    }

    /// Force remove and disconnect relay
    ///
    /// Note: this method will remove the relay, also if it's in use for the gossip model or other service!
    #[inline]
    pub async fn force_remove_relay(&self, url: &str) -> Result<()> {
        Ok(self.inner.force_remove_relay(url).await?)
    }

    /// Disconnect and remove all relays
    ///
    /// Some relays used by some services could not be disconnected with this method
    /// (like the ones used for gossip).
    /// Use [`Client::force_remove_all_relays`] to remove every relay.
    #[inline]
    pub async fn remove_all_relays(&self) {
        self.inner.remove_all_relays().await
    }

    /// Disconnect and force remove all relays
    #[inline]
    pub async fn force_remove_all_relays(&self) {
        self.inner.force_remove_all_relays().await
    }

    /// Connect to a previously added relay
    #[inline]
    pub async fn connect_relay(&self, url: &str) -> Result<()> {
        Ok(self.inner.connect_relay(url).await?)
    }

    /// Disconnect relay
    #[inline]
    pub async fn disconnect_relay(&self, url: &str) -> Result<()> {
        Ok(self.inner.disconnect_relay(url).await?)
    }

    /// Connect to all added relays
    pub async fn connect(&self) {
        self.inner.connect().await
    }

    /// Disconnect from all relays
    #[inline]
    pub async fn disconnect(&self) {
        self.inner.disconnect().await
    }

    /// Subscribe to filters
    ///
    /// This method creates a new subscription. None of the previous subscriptions will be edited/closed when you call this!
    /// So remember to unsubscribe when you no longer need it.
    ///
    /// If `gossip` is enabled (see [`Options::gossip`]) the events will be requested also to
    /// NIP65 relays (automatically discovered) of public keys included in filters (if any).
    ///
    /// # Auto-closing subscription
    ///
    /// It's possible to automatically close a subscription by configuring the [SubscribeAutoCloseOptions].
    ///
    /// Note: auto-closing subscriptions aren't saved in subscriptions map!
    pub async fn subscribe(
        &self,
        filter: &_Filter,
        opts: Option<_SubscribeAutoCloseOptions>,
    ) -> Result<String> {
        let opts = opts.map(|o| o.inner);
        let output = self.inner.subscribe(filter.inner.clone(), opts).await?;
        // TODO return output
        Ok(output.id().to_string())
    }

    /// Subscribe to filters with custom [SubscriptionId]
    ///
    /// If `gossip` is enabled (see [`Options::gossip`]) the events will be requested also to
    /// NIP65 relays (automatically discovered) of public keys included in filters (if any).
    ///
    /// # Auto-closing subscription
    ///
    /// It's possible to automatically close a subscription by configuring the [SubscribeAutoCloseOptions].
    ///
    /// Note: auto-closing subscriptions aren't saved in subscriptions map!
    pub async fn subscribe_with_id(
        &self,
        id: &str,
        filter: &_Filter,
        opts: Option<_SubscribeAutoCloseOptions>,
    ) -> Result<()> {
        let id = SubscriptionId::new(id);
        let opts = opts.map(|o| o.inner);
        self.inner
            .subscribe_with_id(id, filter.inner.clone(), opts)
            .await?;
        // TODO return output
        Ok(())
    }

    /// Subscribe to filters to specific relays
    ///
    /// This method creates a new subscription. None of the previous subscriptions will be edited/closed when you call this!
    /// So remember to unsubscribe when you no longer need it.
    ///
    /// ### Auto-closing subscription
    ///
    /// It's possible to automatically close a subscription by configuring the [SubscribeAutoCloseOptions].
    pub async fn subscribe_to(
        &self,
        urls: Vec<String>,
        filter: &_Filter,
        opts: Option<_SubscribeAutoCloseOptions>,
    ) -> Result<String> {
        let opts = opts.map(|o| o.inner);
        let output = self
            .inner
            .subscribe_to(urls, filter.inner.clone(), opts)
            .await?;
        // TODO return output
        Ok(output.id().to_string())
    }

    /// Subscribe to filters with custom [SubscriptionId] to specific relays
    ///
    /// ### Auto-closing subscription
    ///
    /// It's possible to automatically close a subscription by configuring the [SubscribeAutoCloseOptions].
    pub async fn subscribe_with_id_to(
        &self,
        urls: Vec<String>,
        id: &str,
        filter: &_Filter,
        opts: Option<_SubscribeAutoCloseOptions>,
    ) -> Result<()> {
        let id = SubscriptionId::new(id);
        let opts = opts.map(|o| o.inner);
        self.inner
            .subscribe_with_id_to(urls, id, filter.inner.clone(), opts)
            .await?;
        // TODO return output
        Ok(())
    }

    /// Fetch events from relays
    ///
    /// If `gossip` is enabled (see [`Options::gossip`]) the events will be requested also to
    /// NIP65 relays (automatically discovered) of public keys included in filters (if any).
    pub async fn fetch_events(&self, filter: &_Filter, timeout: Duration) -> Result<_Events> {
        let events = self
            .inner
            .fetch_events(filter.inner.clone(), timeout.to_std()?)
            .await?;
        Ok(events.into())
    }

    /// Fetch events from specific relays.
    pub async fn fetch_events_from(
        &self,
        urls: Vec<String>,
        filter: &_Filter,
        timeout: Duration,
    ) -> Result<_Events> {
        let events = self
            .inner
            .fetch_events_from(urls, filter.inner.clone(), timeout.to_std()?)
            .await?;
        Ok(events.into())
    }

    /// Send event
    ///
    /// Send `Event` to all relays with `WRITE` flag.
    /// If `gossip` option is enabled, the event will be sent also to NIP65 relays (automatically discovered).
    pub async fn send_event(&self, event: &_Event) -> Result<SendEventOutput> {
        let output = self.inner.send_event(&event.inner).await?;
        Ok(output.into())
    }

    /// Send event to specific relays.
    pub async fn send_event_to(
        &self,
        urls: Vec<String>,
        event: &_Event,
    ) -> Result<SendEventOutput> {
        let output = self.inner.send_event_to(urls, &event.inner).await?;
        Ok(output.into())
    }

    /// Send event
    ///
    /// Take an [`EventBuilder`], sign it by using the [`NostrSigner`] and broadcast to relays (check [`Client::send_event`] from more details).
    ///
    /// Return an error if the [`NostrSigner`] is not set.
    pub async fn send_event_builder(&self, builder: &_EventBuilder) -> Result<SendEventOutput> {
        let output = self.inner.send_event_builder(builder.inner.clone()).await?;
        Ok(output.into())
    }

    pub async fn handle_notifications(
        &self,
        stream: StreamSink<RelayPoolNotification>,
    ) -> Result<()> {
        self.inner
            .handle_notifications(|notification| async {
                let notification: RelayPoolNotification = notification.into();
                stream.add(notification).map_err(|e| anyhow::anyhow!(e))?;
                Ok(false)
            })
            .await?;
        Ok(())
    }
}

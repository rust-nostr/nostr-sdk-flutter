# Changelog

<!-- All notable changes to this project will be documented in this file. -->

<!-- The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), -->
<!-- and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html). -->

<!-- Template

## [Unreleased]

### Breaking changes

### Changed

### Added

### Fixed

### Removed

### Deprecated

-->

## [Unreleased]

### Breaking changes

### Changed

### Added

* Add `Events::as_vec` ([Yuki Kishimoto])
* Expose `EncryptedSecreKey` ([Yuki Kishimoto])

### Fixed

### Removed

### Deprecated

## [v0.39.0]

### Changed

* Bump `nostr-sdk` to 0.39 ([Yuki Kishimoto])

### Added

* Expose `EventId` ([Yuki Kishimoto])
* Expose `Alphabet`, `SingleLetterTag` and `Filter` ([Yuki Kishimoto])
* Expose `Client::fetch_events` ([Yuki Kishimoto])
* Expose `EventBuilder::seal` ([Yuki Kishimoto])
* Expose `EventBuilder::gift_wrap_from_seal` ([Yuki Kishimoto])
* Expose `EventBuilder::gift_wrap` ([Yuki Kishimoto])
* Expose `EventBuilder::private_msg` ([Yuki Kishimoto])
* Expose `UnwrappedGift` ([Yuki Kishimoto])
* Expose `Client::handle_notifications` ([Yuki Kishimoto])
* Expose subscribe `Client` methods ([Yuki Kishimoto])
* Expose `NostrDatabase` and `Events` structs ([Yuki Kishimoto])
* Expose `ClientBuilder::database` ([Yuki Kishimoto])
* Expose `Client::send_event_to` ([Yuki Kishimoto])
* Expose `Client::fetch_events_from` ([Yuki Kishimoto])
* Expose `Client::database` ([Yuki Kishimoto])

## [v0.38.0]

### Added

* Expose `ConnectionMode` ([Yuki Kishimoto])
* Expose `ClientOptions` ([Yuki Kishimoto])
* Expose `ClientBuilder` ([Yuki Kishimoto])
* Expose `NostrSigner` ([Yuki Kishimoto])
* Expose `UnsignedEvent` ([Yuki Kishimoto])
* Expose `EventBuilder` ([Yuki Kishimoto])
* Expose add relay method for `Client` ([Yuki Kishimoto])
* Expose remove relay methods for `Client` ([Yuki Kishimoto])
* Expose connect and disconnect methods for `Client` ([Yuki Kishimoto])
* Expose `Client::send_event_builder` ([Yuki Kishimoto])
* Expose `Client::automatic_authentication` ([Yuki Kishimoto])
* Expose `Client::reset` ([Yuki Kishimoto])
* Expose `Client::shutdown` ([Yuki Kishimoto])
* Expose signer methods for `Client` ([Yuki Kishimoto])
* Add `SendEventOutput` ([Yuki Kishimoto])

<!-- Contributors -->
[Yuki Kishimoto]: https://yukikishimoto.com
[J. Azad EMERY]: https://github.com/ethicnology

<!-- Tags -->
[Unreleased]: https://github.com/rust-nostr/nostr-sdk-flutter/compare/v0.39.0...HEAD
[v0.39.0]: https://github.com/rust-nostr/nostr-sdk-flutter/compare/5030349e7e13a96c00416f40d9aacd318a8dd978v0.38.0...v0.39.0
[v0.38.0]: https://github.com/rust-nostr/nostr-sdk-flutter/compare/5030349e7e13a96c00416f40d9aacd318a8dd978...v0.38.0

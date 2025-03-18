// This file is automatically generated, so please do not edit it.
// Generated by `flutter_rust_bridge`@ 2.0.0.

// ignore_for_file: invalid_use_of_internal_member, unused_import, unnecessary_import

import '../../frb_generated.dart';
import '../relay/options.dart';
import 'package:flutter_rust_bridge/flutter_rust_bridge_for_generated.dart';

// These function are ignored because they are on traits that is not defined in current crate (put an empty `#[frb]` on it to unignore): `deref`, `from`, `from`

// Rust type: RustOpaqueMoi<flutter_rust_bridge::for_generated::RustAutoOpaqueInner<_ClientOptions>>
abstract class ClientOptions implements RustOpaqueInterface {
  /// Automatically start connection with relays (default: false)
  ///
  /// When set to `true`, there isn't the need of calling the connect methods.
  ClientOptions autoconnect({required bool val});

  /// Auto authenticate to relays (default: true)
  ///
  /// <https://github.com/nostr-protocol/nips/blob/master/42.md>
  ClientOptions automaticAuthentication({required bool enabled});

  /// Connection
  ClientOptions connection({required Connection connection});

  /// Enable gossip model (default: false)
  ClientOptions gossip({required bool enabled});

  factory ClientOptions() =>
      NostrSdk.instance.api.crateApiClientOptionsClientOptionsNew();
}

// Rust type: RustOpaqueMoi<flutter_rust_bridge::for_generated::RustAutoOpaqueInner<_Connection>>
abstract class Connection implements RustOpaqueInterface {
  /// Set proxy (ex. `127.0.0.1:9050`)
  Connection addr({required String addr});

  /// Use embedded tor client
  ///
  /// This not work on `android` and/or `ios` targets.
  /// Use [`Connection::embedded_tor_with_path`] instead.
  Connection embeddedTor();

  /// Use embedded tor client
  ///
  /// Specify a path where to store data
  Connection embeddedTorWithPath({required String dataPath});

  /// Set connection mode (default: direct)
  Connection mode({required ConnectionMode mode});

  factory Connection() =>
      NostrSdk.instance.api.crateApiClientOptionsConnectionNew();

  /// Set connection target (default: all)
  Connection target({required ConnectionTarget target});
}

/// Connection target
enum ConnectionTarget {
  /// Use proxy for all relays
  all,

  /// Use proxy only for `.onion` relays
  onion,
  ;
}

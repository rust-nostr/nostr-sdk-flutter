// This file is automatically generated, so please do not edit it.
// Generated by `flutter_rust_bridge`@ 2.0.0.

// ignore_for_file: invalid_use_of_internal_member, unused_import, unnecessary_import

import '../../frb_generated.dart';
import 'package:flutter_rust_bridge/flutter_rust_bridge_for_generated.dart';
import 'package:freezed_annotation/freezed_annotation.dart' hide protected;
part 'options.freezed.dart';

// These function are ignored because they are on traits that is not defined in current crate (put an empty `#[frb]` on it to unignore): `deref`, `from`, `try_from`, `try_from`

// Rust type: RustOpaqueMoi<flutter_rust_bridge::for_generated::RustAutoOpaqueInner<_SubscribeAutoCloseOptions>>
abstract class SubscribeAutoCloseOptions implements RustOpaqueInterface {
  /// Close subscription when the policy is satisfied
  SubscribeAutoCloseOptions exitPolicy({required ReqExitPolicy policy});

  /// Automatically close subscription if no notifications/events are received within the duration.
  SubscribeAutoCloseOptions idleTimeout({Duration? timeout});

  factory SubscribeAutoCloseOptions() =>
      NostrSdk.instance.api.crateApiRelayOptionsSubscribeAutoCloseOptionsNew();

  /// Automatically close subscription after duration.
  SubscribeAutoCloseOptions timeout({Duration? timeout});
}

@freezed
sealed class ConnectionMode with _$ConnectionMode {
  const ConnectionMode._();

  /// Direct connection
  const factory ConnectionMode.direct() = ConnectionMode_Direct;

  /// Connect through proxy
  ///
  /// This doesn't work on web!
  const factory ConnectionMode.proxy({
    /// Socket addr (i.e. 127.0.0.1:9050)
    required String addr,
  }) = ConnectionMode_Proxy;

  /// Connect through tor network
  ///
  /// This doesn't work on web!
  const factory ConnectionMode.tor({
    /// Path where to store data
    ///
    /// This is required for `android` and `ios` targets!
    String? customPath,
  }) = ConnectionMode_Tor;
}

@freezed
sealed class ReqExitPolicy with _$ReqExitPolicy {
  const ReqExitPolicy._();

  /// Exit on EOSE
  const factory ReqExitPolicy.exitOnEose() = ReqExitPolicy_ExitOnEOSE;

  /// After EOSE is received, keep listening for N more events that match the filter.
  const factory ReqExitPolicy.waitForEventsAfterEose(
    int field0,
  ) = ReqExitPolicy_WaitForEventsAfterEOSE;

  /// After EOSE is received, keep listening for matching events for `Duration` more time.
  const factory ReqExitPolicy.waitDurationAfterEose(
    Duration field0,
  ) = ReqExitPolicy_WaitDurationAfterEOSE;
}

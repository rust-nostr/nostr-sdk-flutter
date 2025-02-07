// This file is automatically generated, so please do not edit it.
// Generated by `flutter_rust_bridge`@ 2.0.0.

// ignore_for_file: invalid_use_of_internal_member, unused_import, unnecessary_import

import '../../frb_generated.dart';
import '../protocol/event.dart';
import 'package:flutter_rust_bridge/flutter_rust_bridge_for_generated.dart';

// These function are ignored because they are on traits that is not defined in current crate (put an empty `#[frb]` on it to unignore): `deref`, `from`

// Rust type: RustOpaqueMoi<flutter_rust_bridge::for_generated::RustAutoOpaqueInner<_Events>>
abstract class Events implements RustOpaqueInterface {
  /// Clone and convert the collection to a vector of events.
  ///
  /// Use `toVec` method if you want to avoid the clone and consume the `Events` object.
  List<Event> asVec();

  /// Check if contains `Event`
  bool contains({required Event event});

  /// Get first `Event` (descending order)
  Event? first();

  /// Returns the number of events in the collection.
  bool isEmpty();

  /// Returns the number of events in the collection.
  BigInt len();

  /// Merge events collections into a single one.
  ///
  /// Collection is converted to unbounded if one of the merge `Events` have a different hash.
  /// In other words, the filter limit is respected only if the `Events` are related to the same
  /// list of filters.
  ///
  /// **This method consumes the old `Events` collection and returns a new one!**
  Events merge({required Events other});

  /// Convert the collection to a vector of events.
  ///
  /// **This method consumes the `Events` collection!**
  List<Event> toVec();
}

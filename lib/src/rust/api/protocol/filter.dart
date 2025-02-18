// This file is automatically generated, so please do not edit it.
// Generated by `flutter_rust_bridge`@ 2.0.0.

// ignore_for_file: invalid_use_of_internal_member, unused_import, unnecessary_import

import '../../frb_generated.dart';
import 'event.dart';
import 'event/id.dart';
import 'key/public_key.dart';
import 'package:flutter_rust_bridge/flutter_rust_bridge_for_generated.dart';

// These function are ignored because they are on traits that is not defined in current crate (put an empty `#[frb]` on it to unignore): `from`, `from`, `from`

// Rust type: RustOpaqueMoi<flutter_rust_bridge::for_generated::RustAutoOpaqueInner<_Filter>>
abstract class Filter implements RustOpaqueInterface {
  String asJson();

  /// Add event author Public Key
  Filter author({required PublicKey author});

  Filter authors({required List<PublicKey> authors});

  Filter customTag({required SingleLetterTag tag, required String content});

  Filter customTags(
      {required SingleLetterTag tag, required List<String> content});

  /// Add event ID (`e` tag)
  Filter event({required EventId id});

  /// Add event IDs (`e` tag)
  Filter events({required List<EventId> ids});

  static Filter fromJson({required String json}) =>
      NostrSdk.instance.api.crateApiProtocolFilterFilterFromJson(json: json);

  Filter hashtag({required String hashtag});

  Filter hashtags({required List<String> hashtags});

  Filter id({required EventId id});

  Filter identifier({required String identifier});

  Filter identifiers({required List<String> identifiers});

  Filter ids({required List<EventId> ids});

  bool isEmpty();

  Filter kind({required int kind});

  Filter kinds({required List<int> kinds});

  Filter limit({required BigInt limit});

  /// Determine if `Filter` match given `Event`.
  bool matchEvent({required Event event});

  factory Filter() => NostrSdk.instance.api.crateApiProtocolFilterFilterNew();

  /// Add Public Key (`p` tag)
  Filter pubkey({required PublicKey pubkey});

  /// Add Public Keys (`p` tag)
  Filter pubkeys({required List<PublicKey> pubkeys});

  Filter reference({required String reference});

  Filter references({required List<String> references});

  Filter removeAuthors({required List<PublicKey> authors});

  Filter removeCustomTags(
      {required SingleLetterTag tag, required List<String> content});

  Filter removeEvents({required List<EventId> ids});

  Filter removeHashtags({required List<String> hashtags});

  Filter removeIdentifiers({required List<String> identifiers});

  Filter removeIds({required List<EventId> ids});

  Filter removeKinds({required List<int> kinds});

  Filter removeLimit();

  Filter removePubkeys({required List<PublicKey> pubkeys});

  Filter removeReferences({required List<String> references});

  Filter removeSearch();

  Filter removeSince();

  Filter removeUntil();

  Filter search({required String text});

  Filter since({required BigInt timestamp});

  Filter until({required BigInt timestamp});
}

// Rust type: RustOpaqueMoi<flutter_rust_bridge::for_generated::RustAutoOpaqueInner<_SingleLetterTag>>
abstract class SingleLetterTag implements RustOpaqueInterface {
  /// Check if it's lowercase
  bool isLowercase();

  /// Check if it's uppercase
  bool isUppercase();

  /// New lowercase single-letter tag
  static SingleLetterTag lowercase({required Alphabet character}) =>
      NostrSdk.instance.api
          .crateApiProtocolFilterSingleLetterTagLowercase(character: character);

  /// New uppercase single-letter tag
  static SingleLetterTag uppercase({required Alphabet character}) =>
      NostrSdk.instance.api
          .crateApiProtocolFilterSingleLetterTagUppercase(character: character);
}

enum Alphabet {
  a,
  b,
  c,
  d,
  e,
  f,
  g,
  h,
  i,
  j,
  k,
  l,
  m,
  n,
  o,
  p,
  q,
  r,
  s,
  t,
  u,
  v,
  w,
  x,
  y,
  z,
  ;
}

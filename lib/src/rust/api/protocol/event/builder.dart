// This file is automatically generated, so please do not edit it.
// Generated by `flutter_rust_bridge`@ 2.0.0.

// ignore_for_file: invalid_use_of_internal_member, unused_import, unnecessary_import

import '../../../frb_generated.dart';
import '../event.dart';
import '../key.dart';
import '../key/public_key.dart';
import '../signer.dart';
import 'package:flutter_rust_bridge/flutter_rust_bridge_for_generated.dart';
import 'tag.dart';
import 'unsigned.dart';

// Rust type: RustOpaqueMoi<flutter_rust_bridge::for_generated::RustAutoOpaqueInner<_EventBuilder>>
abstract class EventBuilder implements RustOpaqueInterface {
  /// Build unsigned event
  UnsignedEvent build({required PublicKey publicKey});

  /// Set a custom `created_at` UNIX timestamp
  EventBuilder customCreatedAt({required BigInt createdAt});

  /// Gift Wrap
  ///
  /// <https://github.com/nostr-protocol/nips/blob/master/59.md>
  static Future<Event> giftWrap(
          {required NostrSigner signer,
          required PublicKey receiver,
          required UnsignedEvent rumor,
          required List<Tag> extraTags}) =>
      NostrSdk.instance.api.crateApiProtocolEventBuilderEventBuilderGiftWrap(
          signer: signer,
          receiver: receiver,
          rumor: rumor,
          extraTags: extraTags);

  /// Gift Wrap from seal
  ///
  /// <https://github.com/nostr-protocol/nips/blob/master/59.md>
  static Event giftWrapFromSeal(
          {required PublicKey receiver,
          required Event seal,
          required List<Tag> extraTags}) =>
      NostrSdk.instance.api
          .crateApiProtocolEventBuilderEventBuilderGiftWrapFromSeal(
              receiver: receiver, seal: seal, extraTags: extraTags);

  /// New event builder
  factory EventBuilder({required int kind, required String content}) =>
      NostrSdk.instance.api.crateApiProtocolEventBuilderEventBuilderNew(
          kind: kind, content: content);

  /// Set POW difficulty
  ///
  /// Only values `> 0` are accepted!
  EventBuilder pow({required int difficulty});

  /// Private Direct message
  ///
  /// <https://github.com/nostr-protocol/nips/blob/master/17.md>
  static Future<Event> privateMsg(
          {required NostrSigner signer,
          required PublicKey receiver,
          required String message,
          required List<Tag> rumorExtraTags}) =>
      NostrSdk.instance.api.crateApiProtocolEventBuilderEventBuilderPrivateMsg(
          signer: signer,
          receiver: receiver,
          message: message,
          rumorExtraTags: rumorExtraTags);

  /// Seal
  ///
  /// <https://github.com/nostr-protocol/nips/blob/master/59.md>
  static Future<EventBuilder> seal(
          {required NostrSigner signer,
          required PublicKey receiver,
          required UnsignedEvent rumor}) =>
      NostrSdk.instance.api.crateApiProtocolEventBuilderEventBuilderSeal(
          signer: signer, receiver: receiver, rumor: rumor);

  /// Build, sign and return event
  Future<Event> sign({required NostrSigner signer});

  /// Build, sign and return event using keys signer
  Event signWithKeys({required Keys keys});

  /// Add tag
  EventBuilder tag({required Tag tag});

  /// Add tags
  ///
  /// This method extends the current tags (if any).
  EventBuilder tags({required List<Tag> tags});

  /// Text note
  ///
  /// <https://github.com/nostr-protocol/nips/blob/master/01.md>
  static EventBuilder textNote({required String content}) =>
      NostrSdk.instance.api
          .crateApiProtocolEventBuilderEventBuilderTextNote(content: content);
}

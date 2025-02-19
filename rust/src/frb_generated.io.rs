// This file is automatically generated, so please do not edit it.
// Generated by `flutter_rust_bridge`@ 2.0.0.

// Section: imports

use super::*;
use crate::api::client::builder::*;
use crate::api::client::options::*;
use crate::api::client::*;
use crate::api::database::events::*;
use crate::api::database::*;
use crate::api::protocol::event::builder::*;
use crate::api::protocol::event::id::*;
use crate::api::protocol::event::tag::*;
use crate::api::protocol::event::unsigned::*;
use crate::api::protocol::event::*;
use crate::api::protocol::filter::*;
use crate::api::protocol::key::public_key::*;
use crate::api::protocol::key::secret_key::*;
use crate::api::protocol::key::*;
use crate::api::protocol::nips::nip49::*;
use crate::api::protocol::nips::nip59::*;
use crate::api::protocol::signer::*;
use crate::api::relay::options::*;
use flutter_rust_bridge::for_generated::byteorder::{NativeEndian, ReadBytesExt, WriteBytesExt};
use flutter_rust_bridge::for_generated::{transform_result_dco, Lifetimeable, Lockable};
use flutter_rust_bridge::{Handler, IntoIntoDart};

// Section: boilerplate

flutter_rust_bridge::frb_generated_boilerplate_io!();

#[no_mangle]
pub extern "C" fn frbgen_nostr_sdk_rust_arc_increment_strong_count_RustOpaque_flutter_rust_bridgefor_generatedRustAutoOpaqueInner_Client(
    ptr: *const std::ffi::c_void,
) {
    MoiArc::<flutter_rust_bridge::for_generated::RustAutoOpaqueInner<_Client>>::increment_strong_count(ptr as _);
}

#[no_mangle]
pub extern "C" fn frbgen_nostr_sdk_rust_arc_decrement_strong_count_RustOpaque_flutter_rust_bridgefor_generatedRustAutoOpaqueInner_Client(
    ptr: *const std::ffi::c_void,
) {
    MoiArc::<flutter_rust_bridge::for_generated::RustAutoOpaqueInner<_Client>>::decrement_strong_count(ptr as _);
}

#[no_mangle]
pub extern "C" fn frbgen_nostr_sdk_rust_arc_increment_strong_count_RustOpaque_flutter_rust_bridgefor_generatedRustAutoOpaqueInner_ClientBuilder(
    ptr: *const std::ffi::c_void,
) {
    MoiArc::<flutter_rust_bridge::for_generated::RustAutoOpaqueInner<_ClientBuilder>>::increment_strong_count(ptr as _);
}

#[no_mangle]
pub extern "C" fn frbgen_nostr_sdk_rust_arc_decrement_strong_count_RustOpaque_flutter_rust_bridgefor_generatedRustAutoOpaqueInner_ClientBuilder(
    ptr: *const std::ffi::c_void,
) {
    MoiArc::<flutter_rust_bridge::for_generated::RustAutoOpaqueInner<_ClientBuilder>>::decrement_strong_count(ptr as _);
}

#[no_mangle]
pub extern "C" fn frbgen_nostr_sdk_rust_arc_increment_strong_count_RustOpaque_flutter_rust_bridgefor_generatedRustAutoOpaqueInner_ClientOptions(
    ptr: *const std::ffi::c_void,
) {
    MoiArc::<flutter_rust_bridge::for_generated::RustAutoOpaqueInner<_ClientOptions>>::increment_strong_count(ptr as _);
}

#[no_mangle]
pub extern "C" fn frbgen_nostr_sdk_rust_arc_decrement_strong_count_RustOpaque_flutter_rust_bridgefor_generatedRustAutoOpaqueInner_ClientOptions(
    ptr: *const std::ffi::c_void,
) {
    MoiArc::<flutter_rust_bridge::for_generated::RustAutoOpaqueInner<_ClientOptions>>::decrement_strong_count(ptr as _);
}

#[no_mangle]
pub extern "C" fn frbgen_nostr_sdk_rust_arc_increment_strong_count_RustOpaque_flutter_rust_bridgefor_generatedRustAutoOpaqueInner_Connection(
    ptr: *const std::ffi::c_void,
) {
    MoiArc::<flutter_rust_bridge::for_generated::RustAutoOpaqueInner<_Connection>>::increment_strong_count(ptr as _);
}

#[no_mangle]
pub extern "C" fn frbgen_nostr_sdk_rust_arc_decrement_strong_count_RustOpaque_flutter_rust_bridgefor_generatedRustAutoOpaqueInner_Connection(
    ptr: *const std::ffi::c_void,
) {
    MoiArc::<flutter_rust_bridge::for_generated::RustAutoOpaqueInner<_Connection>>::decrement_strong_count(ptr as _);
}

#[no_mangle]
pub extern "C" fn frbgen_nostr_sdk_rust_arc_increment_strong_count_RustOpaque_flutter_rust_bridgefor_generatedRustAutoOpaqueInner_EncryptedSecretKey(
    ptr: *const std::ffi::c_void,
) {
    MoiArc::<flutter_rust_bridge::for_generated::RustAutoOpaqueInner<_EncryptedSecretKey>>::increment_strong_count(ptr as _);
}

#[no_mangle]
pub extern "C" fn frbgen_nostr_sdk_rust_arc_decrement_strong_count_RustOpaque_flutter_rust_bridgefor_generatedRustAutoOpaqueInner_EncryptedSecretKey(
    ptr: *const std::ffi::c_void,
) {
    MoiArc::<flutter_rust_bridge::for_generated::RustAutoOpaqueInner<_EncryptedSecretKey>>::decrement_strong_count(ptr as _);
}

#[no_mangle]
pub extern "C" fn frbgen_nostr_sdk_rust_arc_increment_strong_count_RustOpaque_flutter_rust_bridgefor_generatedRustAutoOpaqueInner_Event(
    ptr: *const std::ffi::c_void,
) {
    MoiArc::<flutter_rust_bridge::for_generated::RustAutoOpaqueInner<_Event>>::increment_strong_count(ptr as _);
}

#[no_mangle]
pub extern "C" fn frbgen_nostr_sdk_rust_arc_decrement_strong_count_RustOpaque_flutter_rust_bridgefor_generatedRustAutoOpaqueInner_Event(
    ptr: *const std::ffi::c_void,
) {
    MoiArc::<flutter_rust_bridge::for_generated::RustAutoOpaqueInner<_Event>>::decrement_strong_count(ptr as _);
}

#[no_mangle]
pub extern "C" fn frbgen_nostr_sdk_rust_arc_increment_strong_count_RustOpaque_flutter_rust_bridgefor_generatedRustAutoOpaqueInner_EventBuilder(
    ptr: *const std::ffi::c_void,
) {
    MoiArc::<flutter_rust_bridge::for_generated::RustAutoOpaqueInner<_EventBuilder>>::increment_strong_count(ptr as _);
}

#[no_mangle]
pub extern "C" fn frbgen_nostr_sdk_rust_arc_decrement_strong_count_RustOpaque_flutter_rust_bridgefor_generatedRustAutoOpaqueInner_EventBuilder(
    ptr: *const std::ffi::c_void,
) {
    MoiArc::<flutter_rust_bridge::for_generated::RustAutoOpaqueInner<_EventBuilder>>::decrement_strong_count(ptr as _);
}

#[no_mangle]
pub extern "C" fn frbgen_nostr_sdk_rust_arc_increment_strong_count_RustOpaque_flutter_rust_bridgefor_generatedRustAutoOpaqueInner_EventId(
    ptr: *const std::ffi::c_void,
) {
    MoiArc::<flutter_rust_bridge::for_generated::RustAutoOpaqueInner<_EventId>>::increment_strong_count(ptr as _);
}

#[no_mangle]
pub extern "C" fn frbgen_nostr_sdk_rust_arc_decrement_strong_count_RustOpaque_flutter_rust_bridgefor_generatedRustAutoOpaqueInner_EventId(
    ptr: *const std::ffi::c_void,
) {
    MoiArc::<flutter_rust_bridge::for_generated::RustAutoOpaqueInner<_EventId>>::decrement_strong_count(ptr as _);
}

#[no_mangle]
pub extern "C" fn frbgen_nostr_sdk_rust_arc_increment_strong_count_RustOpaque_flutter_rust_bridgefor_generatedRustAutoOpaqueInner_Events(
    ptr: *const std::ffi::c_void,
) {
    MoiArc::<flutter_rust_bridge::for_generated::RustAutoOpaqueInner<_Events>>::increment_strong_count(ptr as _);
}

#[no_mangle]
pub extern "C" fn frbgen_nostr_sdk_rust_arc_decrement_strong_count_RustOpaque_flutter_rust_bridgefor_generatedRustAutoOpaqueInner_Events(
    ptr: *const std::ffi::c_void,
) {
    MoiArc::<flutter_rust_bridge::for_generated::RustAutoOpaqueInner<_Events>>::decrement_strong_count(ptr as _);
}

#[no_mangle]
pub extern "C" fn frbgen_nostr_sdk_rust_arc_increment_strong_count_RustOpaque_flutter_rust_bridgefor_generatedRustAutoOpaqueInner_Filter(
    ptr: *const std::ffi::c_void,
) {
    MoiArc::<flutter_rust_bridge::for_generated::RustAutoOpaqueInner<_Filter>>::increment_strong_count(ptr as _);
}

#[no_mangle]
pub extern "C" fn frbgen_nostr_sdk_rust_arc_decrement_strong_count_RustOpaque_flutter_rust_bridgefor_generatedRustAutoOpaqueInner_Filter(
    ptr: *const std::ffi::c_void,
) {
    MoiArc::<flutter_rust_bridge::for_generated::RustAutoOpaqueInner<_Filter>>::decrement_strong_count(ptr as _);
}

#[no_mangle]
pub extern "C" fn frbgen_nostr_sdk_rust_arc_increment_strong_count_RustOpaque_flutter_rust_bridgefor_generatedRustAutoOpaqueInner_Keys(
    ptr: *const std::ffi::c_void,
) {
    MoiArc::<flutter_rust_bridge::for_generated::RustAutoOpaqueInner<_Keys>>::increment_strong_count(ptr as _);
}

#[no_mangle]
pub extern "C" fn frbgen_nostr_sdk_rust_arc_decrement_strong_count_RustOpaque_flutter_rust_bridgefor_generatedRustAutoOpaqueInner_Keys(
    ptr: *const std::ffi::c_void,
) {
    MoiArc::<flutter_rust_bridge::for_generated::RustAutoOpaqueInner<_Keys>>::decrement_strong_count(ptr as _);
}

#[no_mangle]
pub extern "C" fn frbgen_nostr_sdk_rust_arc_increment_strong_count_RustOpaque_flutter_rust_bridgefor_generatedRustAutoOpaqueInner_NostrDatabase(
    ptr: *const std::ffi::c_void,
) {
    MoiArc::<flutter_rust_bridge::for_generated::RustAutoOpaqueInner<_NostrDatabase>>::increment_strong_count(ptr as _);
}

#[no_mangle]
pub extern "C" fn frbgen_nostr_sdk_rust_arc_decrement_strong_count_RustOpaque_flutter_rust_bridgefor_generatedRustAutoOpaqueInner_NostrDatabase(
    ptr: *const std::ffi::c_void,
) {
    MoiArc::<flutter_rust_bridge::for_generated::RustAutoOpaqueInner<_NostrDatabase>>::decrement_strong_count(ptr as _);
}

#[no_mangle]
pub extern "C" fn frbgen_nostr_sdk_rust_arc_increment_strong_count_RustOpaque_flutter_rust_bridgefor_generatedRustAutoOpaqueInner_NostrSigner(
    ptr: *const std::ffi::c_void,
) {
    MoiArc::<flutter_rust_bridge::for_generated::RustAutoOpaqueInner<_NostrSigner>>::increment_strong_count(ptr as _);
}

#[no_mangle]
pub extern "C" fn frbgen_nostr_sdk_rust_arc_decrement_strong_count_RustOpaque_flutter_rust_bridgefor_generatedRustAutoOpaqueInner_NostrSigner(
    ptr: *const std::ffi::c_void,
) {
    MoiArc::<flutter_rust_bridge::for_generated::RustAutoOpaqueInner<_NostrSigner>>::decrement_strong_count(ptr as _);
}

#[no_mangle]
pub extern "C" fn frbgen_nostr_sdk_rust_arc_increment_strong_count_RustOpaque_flutter_rust_bridgefor_generatedRustAutoOpaqueInner_PublicKey(
    ptr: *const std::ffi::c_void,
) {
    MoiArc::<flutter_rust_bridge::for_generated::RustAutoOpaqueInner<_PublicKey>>::increment_strong_count(ptr as _);
}

#[no_mangle]
pub extern "C" fn frbgen_nostr_sdk_rust_arc_decrement_strong_count_RustOpaque_flutter_rust_bridgefor_generatedRustAutoOpaqueInner_PublicKey(
    ptr: *const std::ffi::c_void,
) {
    MoiArc::<flutter_rust_bridge::for_generated::RustAutoOpaqueInner<_PublicKey>>::decrement_strong_count(ptr as _);
}

#[no_mangle]
pub extern "C" fn frbgen_nostr_sdk_rust_arc_increment_strong_count_RustOpaque_flutter_rust_bridgefor_generatedRustAutoOpaqueInner_SecretKey(
    ptr: *const std::ffi::c_void,
) {
    MoiArc::<flutter_rust_bridge::for_generated::RustAutoOpaqueInner<_SecretKey>>::increment_strong_count(ptr as _);
}

#[no_mangle]
pub extern "C" fn frbgen_nostr_sdk_rust_arc_decrement_strong_count_RustOpaque_flutter_rust_bridgefor_generatedRustAutoOpaqueInner_SecretKey(
    ptr: *const std::ffi::c_void,
) {
    MoiArc::<flutter_rust_bridge::for_generated::RustAutoOpaqueInner<_SecretKey>>::decrement_strong_count(ptr as _);
}

#[no_mangle]
pub extern "C" fn frbgen_nostr_sdk_rust_arc_increment_strong_count_RustOpaque_flutter_rust_bridgefor_generatedRustAutoOpaqueInner_SingleLetterTag(
    ptr: *const std::ffi::c_void,
) {
    MoiArc::<flutter_rust_bridge::for_generated::RustAutoOpaqueInner<_SingleLetterTag>>::increment_strong_count(ptr as _);
}

#[no_mangle]
pub extern "C" fn frbgen_nostr_sdk_rust_arc_decrement_strong_count_RustOpaque_flutter_rust_bridgefor_generatedRustAutoOpaqueInner_SingleLetterTag(
    ptr: *const std::ffi::c_void,
) {
    MoiArc::<flutter_rust_bridge::for_generated::RustAutoOpaqueInner<_SingleLetterTag>>::decrement_strong_count(ptr as _);
}

#[no_mangle]
pub extern "C" fn frbgen_nostr_sdk_rust_arc_increment_strong_count_RustOpaque_flutter_rust_bridgefor_generatedRustAutoOpaqueInner_SubscribeAutoCloseOptions(
    ptr: *const std::ffi::c_void,
) {
    MoiArc::<flutter_rust_bridge::for_generated::RustAutoOpaqueInner<_SubscribeAutoCloseOptions>>::increment_strong_count(ptr as _);
}

#[no_mangle]
pub extern "C" fn frbgen_nostr_sdk_rust_arc_decrement_strong_count_RustOpaque_flutter_rust_bridgefor_generatedRustAutoOpaqueInner_SubscribeAutoCloseOptions(
    ptr: *const std::ffi::c_void,
) {
    MoiArc::<flutter_rust_bridge::for_generated::RustAutoOpaqueInner<_SubscribeAutoCloseOptions>>::decrement_strong_count(ptr as _);
}

#[no_mangle]
pub extern "C" fn frbgen_nostr_sdk_rust_arc_increment_strong_count_RustOpaque_flutter_rust_bridgefor_generatedRustAutoOpaqueInner_Tag(
    ptr: *const std::ffi::c_void,
) {
    MoiArc::<flutter_rust_bridge::for_generated::RustAutoOpaqueInner<_Tag>>::increment_strong_count(
        ptr as _,
    );
}

#[no_mangle]
pub extern "C" fn frbgen_nostr_sdk_rust_arc_decrement_strong_count_RustOpaque_flutter_rust_bridgefor_generatedRustAutoOpaqueInner_Tag(
    ptr: *const std::ffi::c_void,
) {
    MoiArc::<flutter_rust_bridge::for_generated::RustAutoOpaqueInner<_Tag>>::decrement_strong_count(
        ptr as _,
    );
}

#[no_mangle]
pub extern "C" fn frbgen_nostr_sdk_rust_arc_increment_strong_count_RustOpaque_flutter_rust_bridgefor_generatedRustAutoOpaqueInner_UnsignedEvent(
    ptr: *const std::ffi::c_void,
) {
    MoiArc::<flutter_rust_bridge::for_generated::RustAutoOpaqueInner<_UnsignedEvent>>::increment_strong_count(ptr as _);
}

#[no_mangle]
pub extern "C" fn frbgen_nostr_sdk_rust_arc_decrement_strong_count_RustOpaque_flutter_rust_bridgefor_generatedRustAutoOpaqueInner_UnsignedEvent(
    ptr: *const std::ffi::c_void,
) {
    MoiArc::<flutter_rust_bridge::for_generated::RustAutoOpaqueInner<_UnsignedEvent>>::decrement_strong_count(ptr as _);
}

#[no_mangle]
pub extern "C" fn frbgen_nostr_sdk_rust_arc_increment_strong_count_RustOpaque_flutter_rust_bridgefor_generatedRustAutoOpaqueInner_UnwrappedGift(
    ptr: *const std::ffi::c_void,
) {
    MoiArc::<flutter_rust_bridge::for_generated::RustAutoOpaqueInner<_UnwrappedGift>>::increment_strong_count(ptr as _);
}

#[no_mangle]
pub extern "C" fn frbgen_nostr_sdk_rust_arc_decrement_strong_count_RustOpaque_flutter_rust_bridgefor_generatedRustAutoOpaqueInner_UnwrappedGift(
    ptr: *const std::ffi::c_void,
) {
    MoiArc::<flutter_rust_bridge::for_generated::RustAutoOpaqueInner<_UnwrappedGift>>::decrement_strong_count(ptr as _);
}

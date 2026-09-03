//! SystemConfiguration dynamic store access: reads and writes the per-service
//! DNS dictionaries.
//!
//! osdns only ever touches the `State:` (runtime) copy of a service's DNS
//! settings - the `Setup:` (persisted) copy belongs to the user and to the
//! system. The whole DNS dictionary is captured into a serializable value
//! tree so that unrelated fields are preserved on apply and restored
//! losslessly on restore.

use std::ffi::c_void;

use crate::error::{Error, Result};
use system_configuration::core_foundation::array::CFArray;
use system_configuration::core_foundation::base::{CFType, TCFType};
use system_configuration::core_foundation::boolean::CFBoolean;
use system_configuration::core_foundation::dictionary::CFDictionary;
use system_configuration::core_foundation::number::CFNumber;
use system_configuration::core_foundation::string::{CFString, CFStringRef};
use system_configuration::dynamic_store::{SCDynamicStore, SCDynamicStoreBuilder};

const SERVICE_DNS_PREFIX: &str = "State:/Network/Service/";

type UntypedDictionary = CFDictionary<*const c_void, *const c_void>;
type UntypedArray = CFArray<*const c_void>;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub(crate) enum ScValue {
    Boolean(bool),
    Number(i64),
    String(String),
    Array(Vec<ScValue>),
    Dictionary(Vec<(String, ScValue)>),
}

use serde::{Deserialize, Serialize};

fn cf_to_sc(value: &CFType) -> Option<ScValue> {
    if let Some(text) = value.clone().downcast_into::<CFString>() {
        return Some(ScValue::String(text.to_string()));
    }
    if let Some(boolean) = value.clone().downcast_into::<CFBoolean>() {
        return Some(ScValue::Boolean(boolean == CFBoolean::true_value()));
    }
    if let Some(number) = value.clone().downcast_into::<CFNumber>() {
        return number.to_i64().map(ScValue::Number);
    }
    if let Some(array) = value.clone().downcast_into::<UntypedArray>() {
        let mut out = Vec::with_capacity(array.len() as usize);
        for item in array.iter() {
            // SAFETY: the item reference is owned by the array, which
            // outlives this conversion.
            let item = unsafe { CFType::wrap_under_get_rule(*item) };
            out.push(cf_to_sc(&item)?);
        }
        return Some(ScValue::Array(out));
    }
    if let Some(dictionary) = value.clone().downcast_into::<UntypedDictionary>() {
        return Some(untyped_dict_to_sc(&dictionary));
    }
    None
}

fn untyped_dict_to_sc(dictionary: &UntypedDictionary) -> ScValue {
    let count = dictionary.len();
    let mut keys: Vec<*const c_void> = Vec::with_capacity(count);
    let mut values: Vec<*const c_void> = Vec::with_capacity(count);
    // SAFETY: the dictionary reference is valid for the duration of the call
    // and the caller-provided vectors have exactly `count` slots, as
    // documented for CFDictionaryGetKeysAndValues.
    unsafe {
        core_foundation_sys::dictionary::CFDictionaryGetKeysAndValues(
            dictionary.as_CFTypeRef() as core_foundation_sys::dictionary::CFDictionaryRef,
            keys.as_mut_ptr(),
            values.as_mut_ptr(),
        );
        keys.set_len(count);
        values.set_len(count);
    }
    let mut entries = Vec::with_capacity(count);
    for (key, value) in keys.into_iter().zip(values) {
        // SAFETY: the key and value references are owned by the dictionary,
        // which outlives this conversion.
        let key = unsafe { CFString::wrap_under_get_rule(key as CFStringRef) };
        let value = unsafe { CFType::wrap_under_get_rule(value) };
        let value = cf_to_sc(&value).unwrap_or(ScValue::Boolean(false));
        entries.push((key.to_string(), value));
    }
    ScValue::Dictionary(entries)
}

fn sc_to_cf(value: ScValue) -> Option<CFType> {
    match value {
        ScValue::Boolean(value) => Some(CFBoolean::from(value).into_CFType()),
        ScValue::Number(value) => Some(CFNumber::from(value).into_CFType()),
        ScValue::String(value) => Some(CFString::new(&value).into_CFType()),
        ScValue::Array(items) => {
            let mut converted = Vec::with_capacity(items.len());
            for item in items {
                converted.push(sc_to_cf(item)?);
            }
            Some(CFArray::from_CFTypes(&converted).into_CFType())
        }
        ScValue::Dictionary(entries) => {
            let mut pairs = Vec::with_capacity(entries.len());
            for (key, value) in entries {
                pairs.push((CFString::new(&key), sc_to_cf(value)?));
            }
            Some(CFDictionary::from_CFType_pairs(&pairs).into_CFType())
        }
    }
}

fn dict_from_sc(entries: Vec<(String, ScValue)>) -> Result<CFDictionary<CFString, CFType>> {
    let mut pairs = Vec::with_capacity(entries.len());
    for (key, value) in entries {
        let value = match sc_to_cf(value) {
            Some(built) => built,
            None => {
                return Err(Error::platform(
                    crate::capability::BackendKind::MacosSystemConfiguration,
                    "captured DNS dictionary is malformed",
                ));
            }
        };
        pairs.push((CFString::new(&key), value));
    }
    Ok(CFDictionary::from_CFType_pairs(&pairs))
}

pub(crate) fn store() -> Result<SCDynamicStore> {
    SCDynamicStoreBuilder::new("osdns").build().ok_or_else(|| {
        Error::BackendUnavailable("cannot open the SystemConfiguration dynamic store".to_string())
    })
}

pub(crate) fn primary_service_id(store: &SCDynamicStore) -> Result<String> {
    let plist = store.get(CFString::new("State:/Network/Global/IPv4"));
    let Some(dict) = plist.and_then(|p| p.downcast_into::<UntypedDictionary>()) else {
        return Err(Error::invalid_config(
            "no primary network service is currently available",
        ));
    };
    let key = CFString::new("PrimaryService");
    let Some(found) = dict.find(key.as_CFTypeRef()) else {
        return Err(Error::invalid_config(
            "global IPv4 state carries no primary service",
        ));
    };
    // SAFETY: the found reference is owned by the dictionary, which outlives
    // this conversion.
    let text = unsafe { CFString::wrap_under_get_rule(*found as CFStringRef) };
    Ok(text.to_string())
}

pub(crate) fn service_ids(store: &SCDynamicStore) -> Result<Vec<String>> {
    let keys = store
        .get_keys("^Setup:/Network/Service/[^/]+$")
        .ok_or_else(|| Error::BackendUnavailable("cannot list network services".to_string()))?;
    Ok(keys
        .into_iter()
        .map(|key| {
            key.to_string()
                .strip_prefix("Setup:/Network/Service/")
                .unwrap_or_default()
                .to_string()
        })
        .filter(|id| !id.is_empty())
        .collect())
}

pub(crate) fn service_interface_name(store: &SCDynamicStore, id: &str) -> Option<String> {
    let plist = store.get(CFString::new(&format!("State:/Network/Service/{id}/IPv4")))?;
    let value = plist.downcast_into::<UntypedDictionary>()?;
    let key = CFString::new("InterfaceName");
    let found = value.find(key.as_CFTypeRef())?;
    // SAFETY: the found reference is owned by the dictionary.
    let name = unsafe { CFString::wrap_under_get_rule(*found as CFStringRef) };
    Some(name.to_string())
}

pub(crate) fn service_for_interface_name(store: &SCDynamicStore, name: &str) -> Result<String> {
    for id in service_ids(store)? {
        if service_interface_name(store, &id).as_deref() == Some(name) {
            return Ok(id);
        }
    }
    Err(Error::invalid_config(format_args!(
        "no network service found for interface {name:?}"
    )))
}

/// The full `State:/Network/Service/<id>/DNS` dictionary, when present.
pub(crate) fn read_service_dns(store: &SCDynamicStore, id: &str) -> Result<Option<ScValue>> {
    Ok(store
        .get(CFString::new(&format!("{SERVICE_DNS_PREFIX}{id}/DNS")))
        .and_then(|plist| plist.downcast_into::<UntypedDictionary>())
        .map(|dict| untyped_dict_to_sc(&dict)))
}

fn dns_key(id: &str) -> CFString {
    CFString::new(&format!("{SERVICE_DNS_PREFIX}{id}/DNS"))
}

pub(crate) fn write_service_dns(
    store: &SCDynamicStore,
    id: &str,
    servers: &[String],
    search: &[String],
) -> Result<()> {
    let mut entries: Vec<(String, ScValue)> = match read_service_dns(store, id)? {
        Some(ScValue::Dictionary(entries)) => entries
            .into_iter()
            .filter(|(key, _)| key != "ServerAddresses" && key != "SearchDomains")
            .collect(),
        _ => Vec::new(),
    };
    set_dict_field(&mut entries, "ServerAddresses", string_array(servers));
    set_dict_field(&mut entries, "SearchDomains", string_array(search));
    let dict = dict_from_sc(entries)?;
    if !store.set(dns_key(id), dict.to_untyped()) {
        return Err(Error::RequiresPrivilege(
            "writing the service DNS settings requires administrator privileges".to_string(),
        ));
    }
    Ok(())
}

pub(crate) fn rewrite_service_dns(store: &SCDynamicStore, id: &str, dict: ScValue) -> Result<()> {
    let entries = match dict {
        ScValue::Dictionary(entries) => entries,
        _ => {
            return Err(Error::platform(
                crate::capability::BackendKind::MacosSystemConfiguration,
                "captured DNS dictionary is malformed",
            ));
        }
    };
    let dict = dict_from_sc(entries)?;
    if !store.set(dns_key(id), dict.to_untyped()) {
        return Err(Error::RequiresPrivilege(
            "writing the service DNS settings requires administrator privileges".to_string(),
        ));
    }
    Ok(())
}

pub(crate) fn remove_service_dns(store: &SCDynamicStore, id: &str) -> Result<()> {
    if !store.remove(dns_key(id)) {
        return Err(Error::RequiresPrivilege(
            "removing the service DNS settings requires administrator privileges".to_string(),
        ));
    }
    Ok(())
}

fn set_dict_field(entries: &mut Vec<(String, ScValue)>, key: &str, value: ScValue) {
    for (existing, current) in entries.iter_mut() {
        if existing == key {
            *current = value;
            return;
        }
    }
    entries.push((key.to_string(), value));
}

fn string_array(values: &[String]) -> ScValue {
    ScValue::Array(values.iter().cloned().map(ScValue::String).collect())
}

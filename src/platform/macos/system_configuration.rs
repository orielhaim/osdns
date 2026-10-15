//! Runtime SystemConfiguration DNS dictionaries stored as native binary property lists.

use crate::error::{Error, Result};
use core_foundation::{
    array::CFArray,
    base::{CFType, TCFType},
    data::CFData,
    dictionary::CFDictionary,
    propertylist::{
        self, CFPropertyList, kCFPropertyListBinaryFormat_v1_0, kCFPropertyListImmutable,
    },
    string::{CFString, CFStringRef},
};
use std::ffi::c_void;
use system_configuration::dynamic_store::{SCDynamicStore, SCDynamicStoreBuilder};

const SERVICE_DNS_PREFIX: &str = "State:/Network/Service/";
type UntypedDictionary = CFDictionary<*const c_void, *const c_void>;
type UntypedArray = CFArray<*const c_void>;

fn plist_error(error: impl std::fmt::Display) -> Error {
    Error::platform(crate::BackendKind::MacosSystemConfiguration, error)
}

fn pairs(dictionary: &UntypedDictionary) -> Result<Vec<(CFString, CFType)>> {
    let (keys, values) = dictionary.get_keys_and_values();
    keys.into_iter()
        .zip(values)
        .map(|(key, value)| {
            // SAFETY: the dictionary retains these objects during the type check and wrapping.
            unsafe {
                if core_foundation_sys::base::CFGetTypeID(key)
                    != core_foundation_sys::string::CFStringGetTypeID()
                {
                    return Err(plist_error("DNS dictionary key is not a string"));
                }
                Ok((
                    CFString::wrap_under_get_rule(key as CFStringRef),
                    CFType::wrap_under_get_rule(value),
                ))
            }
        })
        .collect()
}

fn validate_managed(dictionary: &UntypedDictionary) -> Result<()> {
    for (key, value) in pairs(dictionary)? {
        let name = key.to_string();
        if !["ServerAddresses", "SearchDomains"].contains(&name.as_str()) {
            continue;
        }
        let array = value
            .downcast_into::<UntypedArray>()
            .ok_or_else(|| plist_error("managed DNS field is not an array"))?;
        for value in array.iter() {
            // SAFETY: the array retains the value during checked downcasting.
            let value = unsafe { CFType::wrap_under_get_rule(*value) }
                .downcast_into::<CFString>()
                .ok_or_else(|| plist_error("managed DNS array contains a non-string"))?
                .to_string();
            if name == "ServerAddresses" {
                value.parse::<std::net::IpAddr>().map_err(plist_error)?;
            } else {
                crate::DnsSuffix::parse(&value)?;
            }
        }
    }
    Ok(())
}

pub(crate) fn decode(bytes: &[u8]) -> Result<UntypedDictionary> {
    let (raw, _) =
        propertylist::create_with_data(CFData::from_buffer(bytes), kCFPropertyListImmutable)
            .map_err(plist_error)?;
    // SAFETY: create_with_data transfers a +1 property-list reference.
    let plist = unsafe { CFPropertyList::wrap_under_create_rule(raw) };
    let dictionary = plist
        .downcast_into::<UntypedDictionary>()
        .ok_or_else(|| plist_error("DNS property list is not a dictionary"))?;
    validate_managed(&dictionary)?;
    Ok(dictionary)
}

fn encode(dictionary: &UntypedDictionary) -> Result<Vec<u8>> {
    validate_managed(dictionary)?;
    let data =
        propertylist::create_data(dictionary.as_CFTypeRef(), kCFPropertyListBinaryFormat_v1_0)
            .map_err(plist_error)?;
    Ok(data.bytes().to_vec())
}

pub(crate) fn equivalent(left: Option<&[u8]>, right: Option<&[u8]>) -> bool {
    let decode_optional = |bytes: Option<&[u8]>| bytes.map(decode).transpose();
    let (Ok(left), Ok(right)) = (decode_optional(left), decode_optional(right)) else {
        return false;
    };
    ["ServerAddresses", "SearchDomains"]
        .into_iter()
        .all(|name| {
            let value = |dictionary: &Option<UntypedDictionary>| {
                dictionary.as_ref().and_then(|dictionary| {
                    dictionary
                        .find(CFString::new(name).as_CFTypeRef())
                        .map(|value| {
                            // SAFETY: the dictionary retains the found value during wrapping.
                            unsafe { CFType::wrap_under_get_rule(*value) }
                        })
                })
            };
            value(&left) == value(&right)
        })
}

pub(crate) fn string_list(bytes: &[u8], name: &str) -> Option<Vec<String>> {
    let dictionary = decode(bytes).ok()?;
    let found = dictionary.find(CFString::new(name).as_CFTypeRef())?;
    // SAFETY: dictionary retains the found object during checked downcasting.
    let value = unsafe { CFType::wrap_under_get_rule(*found) };
    let array = value.downcast_into::<UntypedArray>()?;
    array
        .iter()
        .map(|value| {
            // SAFETY: array retains each object during checked downcasting.
            unsafe { CFType::wrap_under_get_rule(*value) }
                .downcast_into::<CFString>()
                .map(|value| value.to_string())
        })
        .collect()
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
    // SAFETY: the dictionary retains the CF object during the type check.
    if unsafe { core_foundation_sys::base::CFGetTypeID(*found) }
        != unsafe { core_foundation_sys::string::CFStringGetTypeID() }
    {
        return Err(Error::platform(
            crate::BackendKind::MacosSystemConfiguration,
            "PrimaryService is not a string",
        ));
    }
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
    // SAFETY: the dictionary retains the found value during checked downcasting.
    unsafe { CFType::wrap_under_get_rule(*found) }
        .downcast_into::<CFString>()
        .map(|name| name.to_string())
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
pub(crate) fn read_service_dns(store: &SCDynamicStore, id: &str) -> Result<Option<Vec<u8>>> {
    let Some(plist) = store.get(CFString::new(&format!("{SERVICE_DNS_PREFIX}{id}/DNS"))) else {
        return Ok(None);
    };
    let Some(dictionary) = plist.downcast_into::<UntypedDictionary>() else {
        return Err(Error::platform(
            crate::capability::BackendKind::MacosSystemConfiguration,
            "service DNS state is not a dictionary",
        ));
    };
    encode(&dictionary).map(Some)
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
    let mut entries = match read_service_dns(store, id)? {
        Some(bytes) => pairs(&decode(&bytes)?)?,
        None => Vec::new(),
    };
    entries.retain(|(key, _)| *key != "ServerAddresses" && *key != "SearchDomains");
    for (name, values) in [("ServerAddresses", servers), ("SearchDomains", search)] {
        let values: Vec<_> = values.iter().map(|value| CFString::new(value)).collect();
        entries.push((
            CFString::new(name),
            CFArray::from_CFTypes(&values).into_CFType(),
        ));
    }
    let dictionary = CFDictionary::from_CFType_pairs(&entries);
    set_dictionary(store, id, &dictionary.to_untyped())
}

pub(crate) fn restore_service_dns(
    store: &SCDynamicStore,
    id: &str,
    before: Option<&[u8]>,
) -> Result<()> {
    let current = read_service_dns(store, id)?;
    match restored_dictionary(current.as_deref(), before)? {
        Some(dictionary) => set_dictionary(store, id, &dictionary),
        None => remove_service_dns(store, id),
    }
}

fn restored_dictionary(
    current: Option<&[u8]>,
    before: Option<&[u8]>,
) -> Result<Option<UntypedDictionary>> {
    let mut entries = current
        .map(decode)
        .transpose()?
        .as_ref()
        .map(pairs)
        .transpose()?
        .unwrap_or_default();
    entries.retain(|(key, _)| {
        !["ServerAddresses", "SearchDomains"].contains(&key.to_string().as_str())
    });
    if let Some(before) = before {
        entries.extend(pairs(&decode(before)?)?.into_iter().filter(|(key, _)| {
            ["ServerAddresses", "SearchDomains"].contains(&key.to_string().as_str())
        }));
    }
    Ok(if entries.is_empty() && before.is_none() {
        None
    } else {
        Some(CFDictionary::from_CFType_pairs(&entries).to_untyped())
    })
}

fn set_dictionary(store: &SCDynamicStore, id: &str, dictionary: &UntypedDictionary) -> Result<()> {
    if !store.set(dns_key(id), dictionary.clone()) {
        return Err(Error::RequiresPrivilege(
            "writing service DNS requires administrator privileges".to_string(),
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

#[cfg(test)]
mod tests {
    use super::*;
    use core_foundation::{boolean::CFBoolean, date::CFDate, number::CFNumber};
    use rstest::rstest;

    #[rstest]
    #[case(0)]
    #[case(1)]
    #[case(2)]
    #[case(3)]
    fn native_property_list_values_roundtrip(#[case] kind: usize) {
        let values = [
            CFNumber::from(1.5_f64).into_CFType(),
            CFData::from_buffer(b"data").into_CFType(),
            CFDate::new(123.5).into_CFType(),
            CFBoolean::true_value().into_CFType(),
        ];
        let dictionary =
            CFDictionary::from_CFType_pairs(&[(CFString::new("unmanaged"), values[kind].clone())])
                .to_untyped();
        let bytes = encode(&dictionary).unwrap();
        assert_eq!(decode(&bytes).unwrap().as_CFType(), dictionary.as_CFType());
    }

    #[test]
    fn dictionary_keys_are_checked_before_string_operations() {
        let dictionary =
            CFDictionary::from_CFType_pairs(&[(CFNumber::from(1_i32), CFString::new("value"))]);
        assert!(pairs(&dictionary.to_untyped()).is_err());
    }
    #[rstest]
    #[case(false)]
    #[case(true)]
    fn restore_preserves_current_unmanaged_values(#[case] before_exists: bool) {
        let current = CFDictionary::from_CFType_pairs(&[
            (
                CFString::new("ServerAddresses"),
                CFArray::from_CFTypes(&[CFString::new("8.8.8.8")]).into_CFType(),
            ),
            (
                CFString::new("unmanaged"),
                CFNumber::from(1.5_f64).into_CFType(),
            ),
        ])
        .to_untyped();
        let before = CFDictionary::from_CFType_pairs(&[
            (
                CFString::new("ServerAddresses"),
                CFArray::from_CFTypes(&[CFString::new("1.1.1.1")]).into_CFType(),
            ),
            (
                CFString::new("unmanaged"),
                CFNumber::from(2.5_f64).into_CFType(),
            ),
        ])
        .to_untyped();
        let current = encode(&current).unwrap();
        let before = before_exists.then(|| encode(&before).unwrap());
        let restored = restored_dictionary(Some(&current), before.as_deref())
            .unwrap()
            .unwrap();
        let fields = pairs(&restored).unwrap();
        assert_eq!(
            fields
                .iter()
                .find(|(key, _)| *key == "unmanaged")
                .unwrap()
                .1,
            CFNumber::from(1.5_f64).into_CFType()
        );
        let restored = encode(&restored).unwrap();
        assert_eq!(
            string_list(&restored, "ServerAddresses"),
            before_exists.then(|| vec!["1.1.1.1".to_string()])
        );
    }

    #[rstest]
    #[case(false)]
    #[case(true)]
    fn malformed_managed_values_are_rejected(#[case] nested: bool) {
        let invalid = CFNumber::from(1_i32).into_CFType();
        let value = if nested {
            CFArray::from_CFTypes(&[invalid]).into_CFType()
        } else {
            invalid
        };
        let dictionary =
            CFDictionary::from_CFType_pairs(&[(CFString::new("ServerAddresses"), value)])
                .to_untyped();
        assert!(encode(&dictionary).is_err());
    }
}

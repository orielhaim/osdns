use std::ffi::c_void;
use std::io;
use std::mem;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::ptr;

use crate::error::{Error, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Family {
    V4,
    V6,
}

pub(crate) fn default_interface() -> Result<u32> {
    let ipv4 = default_route(Family::V4)?;
    let ipv6 = default_route(Family::V6)?;
    match (ipv4, ipv6) {
        (Some(left), Some(right)) if left != right => Err(Error::platform(
            crate::capability::BackendKind::Resolvconf,
            format_args!(
                "IPv4 and IPv6 default routes use different interfaces ({left} and {right})"
            ),
        )),
        (Some(index), _) | (_, Some(index)) => Ok(index),
        (None, None) => Err(Error::platform(
            crate::capability::BackendKind::Resolvconf,
            "no IPv4 or IPv6 default route is available",
        )),
    }
}

fn default_route(family: Family) -> Result<Option<u32>> {
    let fd = socket()?;
    let request = route_request(family)?;
    match write_request(&fd, &request) {
        Ok(()) => {}
        Err(Error::Io(error))
            if matches!(
                error.raw_os_error(),
                Some(libc::ESRCH) | Some(libc::ENETUNREACH) | Some(libc::EHOSTUNREACH)
            ) || (matches!(family, Family::V6)
                && error.raw_os_error() == Some(libc::EINVAL)) =>
        {
            return Ok(None);
        }
        Err(error) => {
            return Err(Error::platform(
                crate::capability::BackendKind::Resolvconf,
                format_args!("cannot write the BSD routing request: {error}"),
            ));
        }
    }
    let mut response = [0u8; 4096];
    let read = read_response(&fd, &mut response).map_err(|error| {
        Error::platform(
            crate::capability::BackendKind::Resolvconf,
            format_args!("cannot read the BSD routing response: {error}"),
        )
    })?;
    parse_route(&response[..read])
}

fn socket() -> Result<OwnedFd> {
    let raw = unsafe { libc::socket(libc::PF_ROUTE, libc::SOCK_RAW, 0) };
    if raw < 0 {
        return Err(io::Error::last_os_error().into());
    }
    Ok(unsafe { OwnedFd::from_raw_fd(raw) })
}

fn write_request(fd: &OwnedFd, request: &[u8]) -> Result<()> {
    let written = unsafe {
        libc::write(
            fd.as_raw_fd(),
            request.as_ptr().cast::<c_void>(),
            request.len(),
        )
    };
    if written == request.len() as isize {
        Ok(())
    } else if written < 0 {
        Err(io::Error::last_os_error().into())
    } else {
        Err(Error::platform(
            crate::capability::BackendKind::Resolvconf,
            "short write to the BSD routing socket",
        ))
    }
}

fn read_response(fd: &OwnedFd, response: &mut [u8]) -> Result<usize> {
    let read = unsafe {
        libc::read(
            fd.as_raw_fd(),
            response.as_mut_ptr().cast::<c_void>(),
            response.len(),
        )
    };
    if read < 0 {
        Err(io::Error::last_os_error().into())
    } else {
        Ok(read as usize)
    }
}

fn route_request(family: Family) -> Result<Vec<u8>> {
    let (destination, netmask) = sockaddr_pair(family)?;
    let interface = interface_sockaddr();
    let header_len = if cfg!(target_os = "freebsd") {
        152
    } else {
        120
    };
    let mut request = vec![0u8; header_len];
    put_u16(
        &mut request,
        0,
        (header_len + destination.len() + netmask.len() + interface.len()) as u16,
    );
    request[2] = libc::RTM_VERSION as u8;
    request[3] = libc::RTM_GET as u8;
    put_i32(&mut request, 8, libc::RTF_UP);
    put_i32(
        &mut request,
        12,
        libc::RTA_DST | libc::RTA_NETMASK | libc::RTA_IFP,
    );
    put_i32(&mut request, 16, 0);
    put_i32(&mut request, 20, 1);
    put_i32(&mut request, 24, 0);
    put_i32(&mut request, 28, 0);
    request.extend(destination);
    request.extend(netmask);
    request.extend(interface);
    Ok(request)
}

fn sockaddr_pair(family: Family) -> Result<(Vec<u8>, Vec<u8>)> {
    match family {
        Family::V4 => {
            let mut destination = unsafe { mem::zeroed::<libc::sockaddr_in>() };
            destination.sin_len = mem::size_of::<libc::sockaddr_in>() as u8;
            destination.sin_family = libc::AF_INET as libc::sa_family_t;
            let mut netmask = unsafe { mem::zeroed::<libc::sockaddr_in>() };
            netmask.sin_len = mem::size_of::<libc::sockaddr_in>() as u8;
            netmask.sin_family = libc::AF_INET as libc::sa_family_t;
            Ok((struct_bytes(&destination), struct_bytes(&netmask)))
        }
        Family::V6 => {
            let mut destination = unsafe { mem::zeroed::<libc::sockaddr_in6>() };
            destination.sin6_len = mem::size_of::<libc::sockaddr_in6>() as u8;
            destination.sin6_family = libc::AF_INET6 as libc::sa_family_t;
            let mut netmask = unsafe { mem::zeroed::<libc::sockaddr_in6>() };
            netmask.sin6_len = mem::size_of::<libc::sockaddr_in6>() as u8;
            netmask.sin6_family = libc::AF_INET6 as libc::sa_family_t;
            Ok((struct_bytes(&destination), struct_bytes(&netmask)))
        }
    }
}

fn interface_sockaddr() -> Vec<u8> {
    let mut interface = unsafe { mem::zeroed::<libc::sockaddr_dl>() };
    interface.sdl_len = mem::size_of::<libc::sockaddr_dl>() as u8;
    interface.sdl_family = libc::AF_LINK as libc::sa_family_t;
    let mut bytes = struct_bytes(&interface);
    bytes.resize(round_up(bytes.len()), 0);
    bytes
}

fn struct_bytes<T>(value: &T) -> Vec<u8> {
    let bytes = unsafe {
        std::slice::from_raw_parts(ptr::from_ref(value).cast::<u8>(), mem::size_of::<T>())
    };
    bytes.to_vec()
}

fn put_u16(bytes: &mut [u8], offset: usize, value: u16) {
    bytes[offset..offset + 2].copy_from_slice(&value.to_ne_bytes());
}

fn put_i32(bytes: &mut [u8], offset: usize, value: i32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_ne_bytes());
}

fn parse_route(response: &[u8]) -> Result<Option<u32>> {
    if response.len() < 32 {
        return Err(Error::platform(
            crate::capability::BackendKind::Resolvconf,
            "short response from the BSD routing socket",
        ));
    }
    if response[2] != libc::RTM_VERSION as u8 {
        return Err(Error::platform(
            crate::capability::BackendKind::Resolvconf,
            "unexpected routing socket protocol version",
        ));
    }
    let message_len = get_u16(response, 0) as usize;
    if message_len > response.len() {
        return Err(Error::platform(
            crate::capability::BackendKind::Resolvconf,
            "truncated response from the BSD routing socket",
        ));
    }
    let route_error = get_i32(response, 24);
    if route_error != 0 {
        if route_error == libc::EHOSTUNREACH || route_error == libc::ENETUNREACH {
            return Ok(None);
        }
        return Err(Error::platform(
            crate::capability::BackendKind::Resolvconf,
            format_args!("BSD default-route query failed with errno {route_error}"),
        ));
    }
    let index = get_u16(response, 4);
    if index != 0 {
        return Ok(Some(index as u32));
    }
    let header_len = if cfg!(target_os = "freebsd") {
        152
    } else {
        120
    };
    if message_len <= header_len {
        return Ok(None);
    }
    let mut offset = header_len;
    while offset + mem::size_of::<libc::sockaddr>() <= message_len {
        let length = response[offset] as usize;
        if length == 0 || offset + length > message_len {
            break;
        }
        if response[offset + 1] as i32 == libc::AF_LINK && length >= 4 {
            return Ok(Some(
                u16::from_ne_bytes([response[offset + 2], response[offset + 3]]) as u32,
            ));
        }
        offset += round_up(length);
    }
    Ok(None)
}

fn get_u16(bytes: &[u8], offset: usize) -> u16 {
    u16::from_ne_bytes([bytes[offset], bytes[offset + 1]])
}

fn get_i32(bytes: &[u8], offset: usize) -> i32 {
    i32::from_ne_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
    ])
}

fn round_up(length: usize) -> usize {
    (length + mem::size_of::<usize>() - 1) & !(mem::size_of::<usize>() - 1)
}

pub(crate) fn route_command_interface() -> Result<String> {
    let output = std::process::Command::new("route")
        .args(["-n", "get", "default"])
        .output()?;
    if !output.status.success() {
        return Err(Error::platform(
            crate::capability::BackendKind::Resolvconf,
            format_args!(
                "route command failed: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            ),
        ));
    }
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .find_map(|line| line.trim_start().strip_prefix("interface: "))
        .map(str::to_string)
        .ok_or_else(|| {
            Error::platform(
                crate::capability::BackendKind::Resolvconf,
                "route command did not report an interface",
            )
        })
}

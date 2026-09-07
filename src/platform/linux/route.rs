use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use netlink_packet_core::{NLM_F_REQUEST, NetlinkMessage, NetlinkPayload};
use netlink_packet_route::{
    AddressFamily, RouteNetlinkMessage,
    route::{RouteAttribute, RouteMessage},
};
use netlink_sys::{Socket, SocketAddr, protocols::NETLINK_ROUTE};

use crate::error::{Error, Result};

const SEQUENCE: u32 = 1;

pub(super) fn default_interface() -> Result<u32> {
    let ipv4 = lookup(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)));
    let ipv6 = lookup(IpAddr::V6(Ipv6Addr::new(
        0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1111,
    )));
    let (ipv4, ipv6) = match (ipv4, ipv6) {
        (Ok(ipv4), Ok(ipv6)) => (ipv4, ipv6),
        (Ok(Some(ipv4)), Err(_)) => (Some(ipv4), None),
        (Err(_), Ok(Some(ipv6))) => (None, Some(ipv6)),
        (Err(error), Err(_)) | (Err(error), Ok(None)) => return Err(error),
        (Ok(None), Err(error)) => return Err(error),
    };
    match (ipv4, ipv6) {
        (Some(v4), Some(v6)) if v4 != v6 => Err(Error::invalid_config(
            "IPv4 and IPv6 route lookups select different default interfaces",
        )),
        (Some(index), _) | (_, Some(index)) => Ok(index),
        (None, None) => Err(Error::invalid_config("no default route is available")),
    }
}

fn lookup(destination: IpAddr) -> Result<Option<u32>> {
    let mut socket = Socket::new(NETLINK_ROUTE).map_err(netlink_error)?;
    let local = socket.bind_auto().map_err(netlink_error)?;
    socket
        .connect(&SocketAddr::new(0, 0))
        .map_err(netlink_error)?;

    let mut route = RouteMessage::default();
    route.header.address_family = match destination {
        IpAddr::V4(_) => AddressFamily::Inet,
        IpAddr::V6(_) => AddressFamily::Inet6,
    };
    route.header.destination_prefix_length = if destination.is_ipv4() { 32 } else { 128 };
    route
        .attributes
        .push(RouteAttribute::Destination(destination.into()));

    let mut request = NetlinkMessage::from(RouteNetlinkMessage::GetRoute(route));
    request.header.flags = NLM_F_REQUEST;
    request.header.sequence_number = SEQUENCE;
    request.header.port_number = local.port_number();
    request.finalize();
    let mut bytes = vec![0; request.buffer_len()];
    request.serialize(&mut bytes);
    socket.send(&bytes, 0).map_err(netlink_error)?;

    let (response, sender) = socket.recv_from_full().map_err(netlink_error)?;
    if sender.port_number() != 0 {
        return Err(netlink_error("route response did not come from the kernel"));
    }
    let message =
        NetlinkMessage::<RouteNetlinkMessage>::deserialize(&response).map_err(netlink_error)?;
    if message.header.sequence_number != SEQUENCE {
        return Err(netlink_error(
            "route response sequence did not match the request",
        ));
    }
    match message.payload {
        NetlinkPayload::InnerMessage(RouteNetlinkMessage::NewRoute(route)) => Ok(route
            .attributes
            .into_iter()
            .find_map(|attribute| match attribute {
                RouteAttribute::Oif(index) => Some(index),
                _ => None,
            })),
        NetlinkPayload::Error(error) => Err(netlink_error(error)),
        payload => Err(netlink_error(format!(
            "unexpected route response: {payload:?}"
        ))),
    }
}

fn netlink_error(error: impl std::fmt::Display) -> Error {
    Error::BackendUnavailable(format!("Linux route lookup failed: {error}"))
}

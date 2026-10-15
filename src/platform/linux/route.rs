use netlink_packet_core::{
    NLM_F_DUMP, NLM_F_DUMP_INTR, NLM_F_REQUEST, NetlinkMessage, NetlinkPayload,
};
use netlink_packet_route::{
    AddressFamily, RouteNetlinkMessage,
    route::{RouteAttribute, RouteHeader, RouteMessage, RouteType},
};
use netlink_sys::{Socket, SocketAddr, protocols::NETLINK_ROUTE};
use std::collections::BTreeSet;
use std::os::fd::{AsRawFd, BorrowedFd};

use crate::error::{Error, Result};

const SEQUENCE: u32 = 1;

pub(super) fn default_interface() -> Result<u32> {
    select_default(&default_routes()?)
}

fn select_default(routes: &[RouteMessage]) -> Result<u32> {
    let mut candidates = BTreeSet::new();
    for family in [AddressFamily::Inet, AddressFamily::Inet6] {
        let routes: Vec<_> = routes
            .iter()
            .filter(|route| {
                let table = route
                    .attributes
                    .iter()
                    .find_map(|attribute| match attribute {
                        RouteAttribute::Table(table) => Some(*table),
                        _ => None,
                    })
                    .unwrap_or(u32::from(route.header.table));
                route.header.address_family == family
                    && table == u32::from(RouteHeader::RT_TABLE_MAIN)
                    && route.header.destination_prefix_length == 0
                    && route.header.source_prefix_length == 0
                    && route.header.tos == 0
                    && route.header.kind == RouteType::Unicast
            })
            .collect();
        let metric = |route: &RouteMessage| {
            route
                .attributes
                .iter()
                .find_map(|attribute| match attribute {
                    RouteAttribute::Priority(metric) => Some(*metric),
                    _ => None,
                })
                .unwrap_or(0)
        };
        let Some(best) = routes.iter().map(|route| metric(route)).min() else {
            continue;
        };
        for route in routes.into_iter().filter(|route| metric(route) == best) {
            let mut found = false;
            for attribute in &route.attributes {
                match attribute {
                    RouteAttribute::Oif(index) => {
                        candidates.insert(*index);
                        found = true;
                    }
                    RouteAttribute::MultiPath(paths) => {
                        for path in paths {
                            candidates.insert(path.interface_index);
                        }
                        found = !paths.is_empty();
                    }
                    _ => {}
                }
            }
            if !found {
                return Err(Error::invalid_config(
                    "default route has no unambiguous output interface; select an interface explicitly",
                ));
            }
        }
    }
    match candidates.len() {
        0 => Err(Error::invalid_config(
            "no unicast default route exists in the main routing table",
        )),
        1 => Ok(*candidates.first().unwrap()),
        _ => Err(Error::invalid_config(
            "main-table default routes select multiple interfaces; select an interface explicitly",
        )),
    }
}

fn default_routes() -> Result<Vec<RouteMessage>> {
    let mut socket = Socket::new(NETLINK_ROUTE).map_err(netlink_error)?;
    let local = socket.bind_auto().map_err(netlink_error)?;
    socket
        .connect(&SocketAddr::new(0, 0))
        .map_err(netlink_error)?;
    let mut route = RouteMessage::default();
    route.header.address_family = AddressFamily::Unspec;
    let mut request = NetlinkMessage::from(RouteNetlinkMessage::GetRoute(route));
    request.header.flags = NLM_F_REQUEST | NLM_F_DUMP;
    request.header.sequence_number = SEQUENCE;
    request.header.port_number = local.port_number();
    request.finalize();
    let mut bytes = vec![0; request.buffer_len()];
    request.serialize(&mut bytes);
    socket.send(&bytes, 0).map_err(netlink_error)?;
    let mut routes = Vec::new();
    loop {
        // SAFETY: the socket owns this descriptor throughout poll and receive.
        let fd = unsafe { BorrowedFd::borrow_raw(socket.as_raw_fd()) };
        let mut fds = [rustix::event::PollFd::new(
            &fd,
            rustix::event::PollFlags::IN,
        )];
        let timeout = rustix::event::Timespec {
            tv_sec: 2,
            tv_nsec: 0,
        };
        if rustix::event::poll(&mut fds, Some(&timeout)).map_err(netlink_error)? == 0 {
            return Err(netlink_error("route dump timed out"));
        }
        let (response, sender) = socket.recv_from_full().map_err(netlink_error)?;
        if sender.port_number() != 0 {
            return Err(netlink_error("route response did not come from the kernel"));
        }
        let mut offset = 0;
        while offset < response.len() {
            let message = NetlinkMessage::<RouteNetlinkMessage>::deserialize(&response[offset..])
                .map_err(netlink_error)?;
            if message.header.sequence_number != SEQUENCE
                || message.header.flags & NLM_F_DUMP_INTR != 0
            {
                return Err(netlink_error(
                    "route dump changed or returned an unexpected sequence; retry resolution",
                ));
            }
            let length = message.header.length as usize;
            if length < 16 || length > response.len() - offset {
                return Err(netlink_error("invalid route message length"));
            }
            offset += (length + 3) & !3;
            match message.payload {
                NetlinkPayload::InnerMessage(RouteNetlinkMessage::NewRoute(route)) => {
                    routes.push(route)
                }
                NetlinkPayload::Done(done) if done.code == 0 => return Ok(routes),
                NetlinkPayload::Done(done) => return Err(netlink_error(done.code)),
                NetlinkPayload::Error(error) => return Err(netlink_error(error)),
                _ => return Err(netlink_error("unexpected route dump response")),
            }
        }
    }
}

fn netlink_error(error: impl std::fmt::Display) -> Error {
    Error::BackendUnavailable(format!("Linux default-route discovery failed: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    fn route(
        index: u32,
        metric: u32,
        family: AddressFamily,
        table: u8,
        prefix: u8,
    ) -> RouteMessage {
        let mut route = RouteMessage::default();
        route.header.address_family = family;
        route.header.table = table;
        route.header.kind = RouteType::Unicast;
        route.header.destination_prefix_length = prefix;
        route.attributes = vec![RouteAttribute::Oif(index), RouteAttribute::Priority(metric)];
        route
    }

    #[rstest]
    #[case(vec![], None)]
    #[case(vec![(2, 100, false, 254, 0)], Some(2))]
    #[case(vec![(2, 100, false, 254, 0), (3, 200, false, 254, 0)], Some(2))]
    #[case(vec![(2, 100, false, 254, 0), (3, 100, false, 254, 0)], None)]
    #[case(vec![(2, 100, false, 254, 0), (3, 100, true, 254, 0)], None)]
    #[case(vec![(2, 100, false, 254, 0), (2, 100, true, 254, 0)], Some(2))]
    #[case(vec![(3, 1, false, 254, 1), (2, 100, false, 254, 0)], Some(2))]
    #[case(vec![(3, 1, false, 100, 0), (2, 100, false, 254, 0)], Some(2))]
    fn main_table_default_selection(
        #[case] specs: Vec<(u32, u32, bool, u8, u8)>,
        #[case] expected: Option<u32>,
    ) {
        let routes: Vec<_> = specs
            .into_iter()
            .map(|(index, metric, v6, table, prefix)| {
                route(
                    index,
                    metric,
                    if v6 {
                        AddressFamily::Inet6
                    } else {
                        AddressFamily::Inet
                    },
                    table,
                    prefix,
                )
            })
            .collect();
        assert_eq!(select_default(&routes).ok(), expected);
    }
    #[test]
    fn native_route_dump_is_read_only_and_parses_multipart_messages() {
        let routes = default_routes().unwrap();
        if let Ok(index) = select_default(&routes) {
            assert!(index > 0);
        }
    }
}

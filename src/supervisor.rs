use crate::{
    chap::ChapClient,
    pap::PapClient,
    pppoe::PppoeClient,
    proto::{NegotiationProtocol, ProtocolConfig},
};

use std::net::Ipv4Addr;

use ppproperly::{IpCompressionProtocol, IpcpOpt, Ipv6cpOpt, LcpOpt, QualityProtocol};
// use socket2::Socket;

/// A client control instance for full dual stack PPPoE sessions.
#[derive(Debug)]
pub struct Client {
    link: String,
    username: String,
    password: String,

    magic: u32,

    pppoe: PppoeClient,
    lcp: NegotiationProtocol<LcpOpt>,
    pap: PapClient,
    chap: ChapClient,
    ipcp: NegotiationProtocol<IpcpOpt>,
    ipv6cp: NegotiationProtocol<Ipv6cpOpt>,
}

impl Client {
    /// Creates a new `Client` with the specified credential pair.
    ///
    /// # Arguments
    ///
    /// * `link` - The Ethernet interface to open the session on.
    /// * `username` - The PAP/CHAP username to use for authentication.
    /// * `password` - The PAP/CHAP password to use for authentication.
    pub fn new(link: String, username: String, password: String) -> Self {
        let magic = rand::random();
        let peer_magic = rand::random();

        let ifid = rand::random();

        Self {
            link,
            username,
            password,

            magic,

            pppoe: PppoeClient::new(None, None),
            lcp: NegotiationProtocol::new(ProtocolConfig {
                require: vec![LcpOpt::Mru(1492), LcpOpt::MagicNumber(peer_magic)],
                deny: vec![
                    LcpOpt::QualityProtocol(QualityProtocol::default()),
                    LcpOpt::ProtocolFieldCompression,
                    LcpOpt::AddrCtlFieldCompression,
                ],
                deny_exact: vec![(LcpOpt::MagicNumber(0), LcpOpt::MagicNumber(peer_magic))],

                request: vec![LcpOpt::Mru(1492), LcpOpt::MagicNumber(magic)],
                refuse: vec![LcpOpt::Mru(1492), LcpOpt::MagicNumber(magic)],
                refuse_exact: vec![],

                need_protocol_reject: true,

                restart_interval: None,
                max_terminate: None,
                max_configure: None,
                max_failure: None,
            }),
            pap: PapClient::new(None, None),
            chap: ChapClient::new(None),
            ipcp: NegotiationProtocol::new(ProtocolConfig {
                require: vec![IpcpOpt::IpAddr(Ipv4Addr::UNSPECIFIED.into())],
                deny: vec![IpcpOpt::IpCompressionProtocol(
                    IpCompressionProtocol::default(),
                )],
                deny_exact: vec![(
                    IpcpOpt::IpAddr(Ipv4Addr::UNSPECIFIED.into()),
                    IpcpOpt::IpAddr(Ipv4Addr::from(rand::random::<u32>()).into()),
                )],

                request: vec![
                    IpcpOpt::IpAddr(Ipv4Addr::UNSPECIFIED.into()),
                    IpcpOpt::PrimaryDns(Ipv4Addr::UNSPECIFIED.into()),
                    IpcpOpt::SecondaryDns(Ipv4Addr::UNSPECIFIED.into()),
                ],
                refuse: vec![IpcpOpt::IpCompressionProtocol(
                    IpCompressionProtocol::default(),
                )],
                refuse_exact: vec![
                    IpcpOpt::IpAddr(Ipv4Addr::UNSPECIFIED.into()),
                    IpcpOpt::PrimaryDns(Ipv4Addr::UNSPECIFIED.into()),
                    IpcpOpt::SecondaryDns(Ipv4Addr::UNSPECIFIED.into()),
                ],

                need_protocol_reject: false,

                restart_interval: None,
                max_terminate: None,
                max_configure: None,
                max_failure: None,
            }),
            ipv6cp: NegotiationProtocol::new(ProtocolConfig {
                require: vec![Ipv6cpOpt::InterfaceId(rand::random())],
                deny: vec![],
                deny_exact: vec![(
                    Ipv6cpOpt::InterfaceId(ifid),
                    Ipv6cpOpt::InterfaceId(rand::random()),
                )],

                request: vec![Ipv6cpOpt::InterfaceId(ifid)],
                refuse: vec![Ipv6cpOpt::InterfaceId(ifid)],
                refuse_exact: vec![],

                need_protocol_reject: false,

                restart_interval: None,
                max_terminate: None,
                max_configure: None,
                max_failure: None,
            }),
        }
    }

    /// Runs the connection. Blocks the caller forever unless a panic occurs.
    pub fn run(&self) {
        // let sock_disc = self.new_discovery_socket();
    }
}

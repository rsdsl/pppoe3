use crate::Result;
use crate::{
    chap::ChapClient,
    pap::PapClient,
    pppoe::PppoeClient,
    proto::{NegotiationProtocol, ProtocolConfig},
};

use std::ffi::CString;
use std::fs::File;
use std::net::Ipv4Addr;
use std::{io, mem};

use ppproperly::{IpCompressionProtocol, IpcpOpt, Ipv6cpOpt, LcpOpt, QualityProtocol};
use socket2::{SockAddr, Socket};

macro_rules! os_err {
    () => {
        return Err(io::Error::last_os_error().into());
    };
}

/// A set of file descriptors describing a PPP session
/// and its virtual network interface.
#[derive(Debug)]
struct SessionFds(Socket, File, File);

impl SessionFds {
    /// Returns an immutable reference to the network interface control socket.
    pub fn interface(&self) -> &Socket {
        &self.0
    }

    /// Returns a mutable reference to the network interface control socket.
    pub fn interface_mut(&mut self) -> &mut Socket {
        &mut self.0
    }

    /// Returns an immutable reference to the file descriptor
    /// that handles LCP, authentication and other link related traffic.
    pub fn link(&self) -> &File {
        &self.1
    }

    /// Returns a mutable reference to the file descriptor
    /// that handles LCP, authentication and other link related traffic.
    pub fn link_mut(&mut self) -> &mut File {
        &mut self.1
    }

    /// Returns an immutable reference to the file descriptor
    /// that handles NCP traffic.
    pub fn network(&self) -> &File {
        &self.2
    }

    /// Returns a mutable reference to the file descriptor
    /// that handles NCP traffic.
    pub fn network_mut(&mut self) -> &mut File {
        &mut self.2
    }
}

/// A client control instance for full dual stack PPPoE sessions.
#[derive(Debug)]
pub struct Client {
    link: String,
    username: String,
    password: String,

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

        let ifid = rand::random(); // TODO: persistence (accept fn params)

        Self {
            link,
            username,
            password,

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
                refuse: vec![LcpOpt::Mru(1492)],
                refuse_exact: vec![LcpOpt::MagicNumber(0)],

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
        let sock_disc = self.new_discovery_socket();
    }

    /// Creates a new socket for PPPoE Discovery traffic.
    /// Used by the PPPoE implementation.
    fn new_discovery_socket(&self) -> Result<Socket> {
        use libc::{
            sockaddr_ll, sockaddr_storage, socklen_t, AF_PACKET, ETH_P_PPP_DISC, PF_PACKET,
            SOCK_RAW,
        };

        let sock = Socket::new(
            PF_PACKET.into(),
            SOCK_RAW.into(),
            Some(ETH_P_PPP_DISC.into()),
        )?;

        sock.set_broadcast(true)?;

        let c_link = CString::new(&*self.link)?;

        let ifi = unsafe { libc::if_nametoindex(c_link.as_ptr()) };
        if ifi == 0 {
            os_err!();
        }

        let sa = sockaddr_ll {
            sll_family: AF_PACKET as u16,
            sll_protocol: (ETH_P_PPP_DISC as u16).to_be(),
            sll_ifindex: ifi as i32,
            sll_hatype: 0,
            sll_pkttype: 0,
            sll_halen: 0,
            sll_addr: [0; 8],
        };

        sock.bind(&unsafe {
            SockAddr::new(
                *mem::transmute::<*const sockaddr_ll, *const sockaddr_storage>(&sa),
                mem::size_of_val(&sa) as socklen_t,
            )
        })?;

        Ok(sock)
    }

    /// Creates a control socket for the `ppp0` virtual network interface
    /// as well as file descriptors for link/auth and network traffic each.
    ///
    /// It is desirable to drop the structure before creating a new one
    /// to ensure the deletion if the old interface.
    fn new_session_fds(&self) -> Result<SessionFds> {
        todo!()
    }
}

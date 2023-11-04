use crate::Result;
use crate::{
    chap::ChapClient,
    pap::PapClient,
    pppoe::PppoeClient,
    proto::{NegotiationProtocol, ProtocolConfig},
};

use std::ffi::CString;
use std::fs::{File, OpenOptions};
use std::net::Ipv4Addr;
use std::os::fd::AsRawFd;
use std::{io, mem};

use ppproperly::{IpCompressionProtocol, IpcpOpt, Ipv6cpOpt, LcpOpt, MacAddr, QualityProtocol};
use socket2::{SockAddr, Socket, Type};

macro_rules! os_err {
    () => {
        return Err(io::Error::last_os_error().into());
    };
}

/// A port of the `pppoe_addr` C data structure.
#[repr(C)]
#[derive(Debug)]
struct pppoe_addr {
    pub sid: u16,
    pub remote: MacAddr,
    pub dev: String,
}

/// A port of the `sockaddr_pppox` C data structure.
#[repr(C)]
#[derive(Debug)]
struct sockaddr_pppox {
    pub sa_family: libc::sa_family_t,
    pub sa_protocol: u32,
    pub pppoe: pppoe_addr,
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

/// A client control instance for dual stack PPPoE sessions and all involved protocols.
#[derive(Debug)]
pub struct Client {
    link: String,
    username: String,
    password: String,

    session_id: u16,
    remote: MacAddr,

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
    /// * `ipv4_addr` - The IPv4 address to request initially.
    /// * `ipv6_ifid` - The IPv6 interface identifier to request.
    pub fn new(
        link: String,
        username: String,
        password: String,
        ipv4_addr: Option<Ipv4Addr>,
        ipv6_ifid: Option<u64>,
    ) -> Self {
        let magic = rand::random();
        let peer_magic = rand::random();

        let ifid = ipv6_ifid.unwrap_or(rand::random());

        Self {
            link,
            username,
            password,

            session_id: 0,
            remote: MacAddr::BROADCAST,

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
                    IpcpOpt::IpAddr(ipv4_addr.unwrap_or(Ipv4Addr::UNSPECIFIED).into()),
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

    /// Tries to keep a session open at all costs.
    /// Blocks the caller forever unless a panic occurs.
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
        use libc::{sockaddr_storage, socklen_t, AF_PPPOX};

        const PX_PROTO_OE: i32 = 0;

        let sp = sockaddr_pppox {
            sa_family: AF_PPPOX as u16,
            sa_protocol: PX_PROTO_OE as u32,
            pppoe: pppoe_addr {
                sid: self.session_id,
                remote: self.remote,
                dev: self.link.clone(),
            },
        };

        let sock = Socket::new(AF_PPPOX.into(), Type::STREAM, Some(PX_PROTO_OE.into()))?;

        sock.connect(&unsafe {
            SockAddr::new(
                *mem::transmute::<*const sockaddr_pppox, *const sockaddr_storage>(&sp),
                mem::size_of_val(&sp) as socklen_t,
            )
        })?;

        let mut chindex = 0;
        if unsafe { ioctls::pppiocgchan(sock.as_raw_fd(), &mut chindex) } < 0 {
            os_err!();
        }

        let ctl = OpenOptions::new()
            .read(true)
            .write(true)
            .create(false)
            .truncate(false)
            .open("/dev/ppp")?;

        let ppp_dev = OpenOptions::new()
            .read(true)
            .write(true)
            .create(false)
            .truncate(false)
            .open("/dev/ppp")?;

        let mut ifunit = -1;
        if unsafe { ioctls::pppiocnewunit(ppp_dev.as_raw_fd(), &mut ifunit) } < 0 {
            os_err!();
        }

        if unsafe { ioctls::pppiocconnect(ctl.as_raw_fd(), &ifunit) } < 0 {
            os_err!();
        }

        Ok(SessionFds(sock, ctl, ppp_dev))
    }
}

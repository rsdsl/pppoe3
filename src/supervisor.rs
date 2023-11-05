use crate::{Result, *};

use std::ffi::CString;
use std::fs::{File, OpenOptions};
use std::io::Read;
use std::net::Ipv4Addr;
use std::os::fd::AsRawFd;
use std::time::Duration;
use std::{io, mem};

use async_io::Async;
use ppproperly::*;
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

    authenticated: bool,

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

            authenticated: false,

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
    pub async fn run(&mut self) -> Result<()> {
        let sock_disc = self.new_discovery_socket()?;
        let mut session_fds: Option<SessionFds> = None;

        let mut pppoe_buf = [0; 1522];
        let mut link_buf = [0; 1494];
        let mut net_buf = [0; 1494];

        let mut ncp_check = tokio::time::interval(Duration::from_secs(20));

        let mut pppoe_rx = self.pppoe.active();
        let mut lcp_rx = self.lcp.opened();
        let mut pap_rx = self.pap.opened();
        let mut chap_rx = self.chap.opened();
        let mut ipcp_rx = self.ipcp.opened();
        let mut ipv6cp_rx = self.ipv6cp.opened();

        let mut lcp_lower_rx = self.lcp.active();
        let mut ipcp_lower_rx = self.ipcp.active();
        let mut ipv6cp_lower_rx = self.ipv6cp.active();

        self.pppoe.open();
        self.lcp.open();
        // Authentication protocols are opened as needed, see select! below.
        self.ipcp.open();
        self.ipv6cp.open();

        loop {
            tokio::select! {
                result = pppoe_rx.changed() => {
                    result?;

                    let is_active = *pppoe_rx.borrow_and_update();
                    if is_active {
                        session_fds = Some(self.new_session_fds()?);
                        self.lcp.up();
                    } else {
                        session_fds = None;

                        self.session_id = 0;
                        self.remote = MacAddr::BROADCAST;

                        self.lcp.down();
                    }
                }
                result = lcp_rx.changed() => {
                    result?;

                    let is_opened = *lcp_rx.borrow_and_update();
                    if is_opened {
                        let our_auth = self.lcp.peer_options().iter().find_map(|option| {
                            if let LcpOpt::AuthenticationProtocol(auth_protocol) = option {
                                Some(&auth_protocol.protocol)
                            } else {
                                None
                            }
                        });

                        self.pap.up();
                        self.chap.up();

                        match our_auth {
                            Some(AuthProto::Pap) => self.pap.open(),
                            Some(AuthProto::Chap(ChapAlgorithm::Md5)) => self.chap.open(),
                            None => {
                                self.authenticated = true;
                                ncp_check.reset();

                                self.ipcp.up();
                                self.ipv6cp.up();
                            }
                        }
                    } else {
                        self.authenticated = false;

                        self.pap.down();
                        self.chap.down();
                        self.ipcp.down();
                        self.ipv6cp.down();

                        self.pap.close();
                        self.chap.close();
                    }
                }
                result = pap_rx.changed() => {
                    result?;

                    let is_opened = *pap_rx.borrow_and_update();
                    if is_opened {
                        self.authenticated = true;
                        ncp_check.reset();

                        self.ipcp.up();
                        self.ipv6cp.up();
                    } // PAP cannot go down once it has opened successfully.
                }
                result = chap_rx.changed() => {
                    result?;

                    let is_opened = *chap_rx.borrow_and_update();
                    if is_opened {
                        self.authenticated = true;
                        ncp_check.reset();

                        self.ipcp.up();
                        self.ipv6cp.up();
                    } else {
                        self.authenticated = false;
                        self.lcp.close();
                    }
                }
                result = ipcp_rx.changed() => {
                    result?;

                    let is_opened = *ipcp_rx.borrow_and_update();
                    if is_opened {
                        todo!("write v4 success to ds config and inform netlinkd")
                    } else {
                        todo!("write v4 invalidation to ds config and inform netlinkd")
                    }
                }
                result = ipv6cp_rx.changed() => {
                    result?;

                    let is_opened = *ipv6cp_rx.borrow_and_update();
                    if is_opened {
                        todo!("write v6 success to ds config and inform netlinkd and dhcp6")
                    } else {
                        todo!("write v6 invalidation to ds config and inform netlinkd and dhcp6")
                    }
                }

                result = lcp_lower_rx.changed() => {
                    result?;

                    let is_active = *lcp_lower_rx.borrow_and_update();
                    if !is_active { // LCP has gone down, a new PPPoE session is needed.
                        self.lcp.down();

                        self.pppoe.close();
                        self.pppoe.open();

                        self.lcp.open();
                    }
                }
                result = ipcp_lower_rx.changed() => {
                    result?;
                    ncp_check.reset();
                }
                result = ipv6cp_lower_rx.changed() => {
                    result?;
                    ncp_check.reset();
                }

                _ = ncp_check.tick() => {
                    if *lcp_rx.borrow() && self.authenticated && !*ipcp_rx.borrow() && !*ipv6cp_rx.borrow() {
                        // No NCPs are up after 20 seconds, terminate the link.
                        self.lcp.close();
                    }
                }

                result = sock_disc.read_with(|mut io| io.read(&mut pppoe_buf)) => {
                    let n = result?;
                    let mut pppoe_buf = &pppoe_buf[..n];

                    let mut pkt = PppoePkt::default();
                    pkt.deserialize(&mut pppoe_buf)?;

                    self.handle_pppoe(pkt);
                }
                Some(result) = option_read_with(session_fds.as_ref().map(|fds| fds.link()), &mut link_buf) => {
                    let n = result?;
                    let mut link_buf = &link_buf[..n];

                    let mut pkt = PppPkt::default();
                    pkt.deserialize(&mut link_buf)?;

                    self.handle_ppp(pkt);
                }
                Some(result) = option_read_with(session_fds.as_ref().map(|fds| fds.network()), &mut net_buf) => {
                    let n = result?;
                    let mut net_buf = &net_buf[..n];

                    let mut pkt = PppPkt::default();
                    pkt.deserialize(&mut net_buf)?;

                    self.handle_ppp(pkt);
                }
            }
        }
    }

    /// Transforms a [`PppoePkt`] into a [`PppoePacket`] and feeds it
    /// into the PPPoE state machine.
    fn handle_pppoe(&mut self, pkt: PppoePkt) {
        if pkt.session_id != self.session_id {
            return;
        }

        if pkt.src_mac != self.remote && self.remote != MacAddr::BROADCAST {
            return;
        }

        let packet = match pkt.data {
            PppoeData::Ignore => None,
            PppoeData::Ppp(_) => None, // illegal
            PppoeData::Padi(_) => Some(PppoePacket {
                ty: PppoeType::Padi,
                ac_cookie: None,
            }),
            PppoeData::Pado(pado) => {
                self.remote = pkt.src_mac;

                Some(PppoePacket {
                    ty: PppoeType::Pado,
                    ac_cookie: pado.tags.into_iter().find_map(|tag| {
                        if let PppoeVal::AcCookie(ac_cookie) = tag.data {
                            Some(ac_cookie)
                        } else {
                            None
                        }
                    }),
                })
            }
            PppoeData::Padr(padr) => Some(PppoePacket {
                ty: PppoeType::Padr,
                ac_cookie: padr.tags.into_iter().find_map(|tag| {
                    if let PppoeVal::AcCookie(ac_cookie) = tag.data {
                        Some(ac_cookie)
                    } else {
                        None
                    }
                }),
            }),
            PppoeData::Pads(_) => {
                self.session_id = pkt.session_id;

                Some(PppoePacket {
                    ty: PppoeType::Pads,
                    ac_cookie: None,
                })
            }
            PppoeData::Padt(_) => Some(PppoePacket {
                ty: PppoeType::Padt,
                ac_cookie: None,
            }),
        };

        if let Some(packet) = packet {
            self.pppoe.from_recv(packet);
        }
    }

    /// Transforms a [`PppPkt`] into the correct sub-protocol packet type
    /// and feeds it into the right sub-PPP state machine.
    fn handle_ppp(&mut self, pkt: PppPkt) {
        match pkt.data {
            PppData::Lcp(lcp) => self.handle_lcp(lcp),
            PppData::Pap(pap) => self.handle_pap(pap),
            PppData::Chap(chap) => self.handle_chap(chap),
            PppData::Ipcp(ipcp) => self.handle_ipcp(ipcp),
            PppData::Ipv6cp(ipv6cp) => self.handle_ipv6cp(ipv6cp),
        }
    }

    /// Transforms an [`LcpPkt`] into an [`LcpPacket`] and feeds it
    /// into the LCP state machine.
    fn handle_lcp(&mut self, pkt: LcpPkt) {
        let packet = match pkt.data {
            LcpData::ConfigureRequest(cfg_req) => Some(Packet {
                ty: PacketType::ConfigureRequest,
                options: cfg_req.options.into_iter().map(|opt| opt.value).collect(),
                rejected_code: PacketType::Unknown,
                rejected_protocol: 0,
            }),
            LcpData::ConfigureAck(cfg_ack) => Some(Packet {
                ty: PacketType::ConfigureAck,
                options: cfg_ack.options.into_iter().map(|opt| opt.value).collect(),
                rejected_code: PacketType::Unknown,
                rejected_protocol: 0,
            }),
            LcpData::ConfigureNak(cfg_nak) => Some(Packet {
                ty: PacketType::ConfigureNak,
                options: cfg_nak.options.into_iter().map(|opt| opt.value).collect(),
                rejected_code: PacketType::Unknown,
                rejected_protocol: 0,
            }),
            LcpData::ConfigureReject(cfg_reject) => Some(Packet {
                ty: PacketType::ConfigureReject,
                options: cfg_reject
                    .options
                    .into_iter()
                    .map(|opt| opt.value)
                    .collect(),
                rejected_code: PacketType::Unknown,
                rejected_protocol: 0,
            }),
            LcpData::TerminateRequest(_) => Some(Packet {
                ty: PacketType::TerminateRequest,
                options: Vec::default(),
                rejected_code: PacketType::Unknown,
                rejected_protocol: 0,
            }),
            LcpData::TerminateAck(_) => Some(Packet {
                ty: PacketType::TerminateAck,
                options: Vec::default(),
                rejected_code: PacketType::Unknown,
                rejected_protocol: 0,
            }),
            LcpData::CodeReject(code_reject) => Some(Packet {
                ty: PacketType::CodeReject,
                options: Vec::default(),
                rejected_code: code_reject.pkt[1].into(),
                rejected_protocol: 0,
            }),
            LcpData::ProtocolReject(protocol_reject) => match protocol_reject.protocol {
                // LCP, PAP, CHAP or anything else.
                _ => Some(Packet {
                    ty: PacketType::ProtocolReject,
                    options: Vec::default(),
                    rejected_code: PacketType::Unknown,
                    rejected_protocol: protocol_reject.protocol,
                }),
                IPCP => {
                    self.ipcp.from_recv(Packet {
                        ty: PacketType::ProtocolReject,
                        options: Vec::default(),
                        rejected_code: PacketType::Unknown,
                        rejected_protocol: protocol_reject.protocol,
                    });

                    None
                }
                IPV6CP => {
                    self.ipv6cp.from_recv(Packet {
                        ty: PacketType::ProtocolReject,
                        options: Vec::default(),
                        rejected_code: PacketType::Unknown,
                        rejected_protocol: protocol_reject.protocol,
                    });

                    None
                }
            },
            LcpData::EchoRequest(_) => Some(Packet {
                ty: PacketType::EchoRequest,
                options: Vec::default(),
                rejected_code: PacketType::Unknown,
                rejected_protocol: 0,
            }),
            LcpData::EchoReply(_) => Some(Packet {
                ty: PacketType::EchoReply,
                options: Vec::default(),
                rejected_code: PacketType::Unknown,
                rejected_protocol: 0,
            }),
            LcpData::DiscardRequest(_) => Some(Packet {
                ty: PacketType::DiscardRequest,
                options: Vec::default(),
                rejected_code: PacketType::Unknown,
                rejected_protocol: 0,
            }),
        };

        if let Some(packet) = packet {
            self.lcp.from_recv(packet);
        }
    }

    /// Transforms a [`PapPkt`] into a [`PapPacket`] and feeds it
    /// into the PAP state machine.
    fn handle_pap(&mut self, pkt: PapPkt) {
        self.pap.from_recv(match pkt.data {
            PapData::AuthenticateRequest(_) => PapPacket::AuthenticateRequest,
            PapData::AuthenticateAck(_) => PapPacket::AuthenticateAck,
            PapData::AuthenticateNak(_) => PapPacket::AuthenticateNak,
        });
    }

    /// Transforms a [`ChapPkt`] into a [`ChapPacket`] and feeds it
    /// into the CHAP state machine.
    fn handle_chap(&mut self, pkt: ChapPkt) {
        self.chap.from_recv(match pkt.data {
            ChapData::Challenge(challenge) => ChapPacket {
                ty: ChapType::Challenge,
                id: pkt.identifier,
                data: challenge.value,
            },
            ChapData::Response(response) => ChapPacket {
                ty: ChapType::Response,
                id: pkt.identifier,
                data: response.value,
            },
            ChapData::Success(_) => ChapPacket {
                ty: ChapType::Success,
                id: pkt.identifier,
                data: Vec::default(),
            },
            ChapData::Failure(_) => ChapPacket {
                ty: ChapType::Failure,
                id: pkt.identifier,
                data: Vec::default(),
            },
        });
    }

    /// Transforms an [`IpcpPkt`] into an [`IpcpPacket`] and feeds it
    /// into the IPCP state machine.
    fn handle_ipcp(&mut self, pkt: IpcpPkt) {}

    /// Transforms an [`Ipv6cpPkt`] into an [`Ipv6cpPacket`] and feeds it
    /// into the IPv6CP state machine.
    fn handle_ipv6cp(&mut self, pkt: Ipv6cpPkt) {}

    /// Creates a new socket for PPPoE Discovery traffic.
    /// Used by the PPPoE implementation.
    fn new_discovery_socket(&self) -> Result<Async<Socket>> {
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

        Ok(Async::new(sock)?)
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

async fn option_read_with(file: Option<&File>, buf: &mut [u8]) -> Option<io::Result<usize>> {
    file.map(|mut file| file.read(buf))
}

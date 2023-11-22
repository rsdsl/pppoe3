use crate::{Error, Result, *};

use std::ffi::CString;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::os::fd::AsRawFd;
use std::time::Duration;
use std::{io, mem};

use tokio::io::unix::AsyncFd;
use tokio::signal::unix::{signal, SignalKind};
use tokio::sync::mpsc;

use async_io::Async;
use ppproperly::*;
use rsdsl_ip_config::{Ipv4Config, Ipv6Config};
use socket2::{SockAddr, Socket, Type};

macro_rules! os_err {
    () => {
        return Err(io::Error::last_os_error().into());
    };
}

/// A port of the `pppoe_addr` C data structure.
#[repr(C, packed)]
struct pppoe_addr {
    pub sid: u16,
    pub remote: MacAddr,
    pub dev: [u8; libc::IFNAMSIZ],
}

/// A port of the `sockaddr_pppox` C data structure.
#[repr(C, packed)]
struct sockaddr_pppox {
    pub sa_family: libc::sa_family_t,
    pub sa_protocol: u32,
    pub pppoe: pppoe_addr,
}

/// A set of file descriptors describing a PPP session
/// and its virtual network interface.
#[derive(Debug)]
struct SessionFds(Socket, AsyncFd<File>, AsyncFd<File>);

impl SessionFds {
    /// Returns an immutable reference to the file descriptor
    /// that handles LCP, authentication and other link related traffic.
    pub fn link(&self) -> &AsyncFd<File> {
        &self.1
    }

    /// Returns an immutable reference to the file descriptor
    /// that handles NCP traffic.
    pub fn network(&self) -> &AsyncFd<File> {
        &self.2
    }

    /// Returns immutable references to both traffic related file descriptors.
    pub fn both(&self) -> (&AsyncFd<File>, &AsyncFd<File>) {
        (&self.1, &self.2)
    }
}

/// A client control instance for dual stack PPPoE sessions and all involved protocols.
#[derive(Debug)]
pub struct Client {
    link: String,
    username: String,
    password: String,

    session_id: u16,
    local: MacAddr,
    remote: MacAddr,

    shutdown: bool,
    authenticated: bool,

    last_id_remote: u8,

    lcp_id_cfg: u8,
    lcp_id_term: u8,
    lcp_id_echo: u8,
    lcp_id_remote: u8,

    pap_id: u8,

    chap_id_remote: u8,

    ipcp_id_cfg: u8,
    ipcp_id_term: u8,
    ipcp_id_remote: u8,

    ipv6cp_id_cfg: u8,
    ipv6cp_id_term: u8,
    ipv6cp_id_remote: u8,

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
    ) -> Result<Self> {
        let magic = rand::random();
        let peer_magic = rand::random();

        let ifid = ipv6_ifid.unwrap_or(rand::random());

        Ok(Self {
            link: link.clone(),
            username,
            password,

            session_id: 0,
            local: mac_address::mac_address_by_name(&link)?
                .ok_or(Error::NoMacAddress(link))?
                .bytes()
                .into(),
            remote: MacAddr::BROADCAST,

            shutdown: false,
            authenticated: false,

            last_id_remote: 0,

            lcp_id_cfg: 0,
            lcp_id_term: 0,
            lcp_id_echo: 0,
            lcp_id_remote: 0,

            pap_id: 0,

            chap_id_remote: 0,

            ipcp_id_cfg: 0,
            ipcp_id_term: 0,
            ipcp_id_remote: 0,

            ipv6cp_id_cfg: 0,
            ipv6cp_id_term: 0,
            ipv6cp_id_remote: 0,

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
        })
    }

    /// Returns the currently negotiated local magic number.
    pub fn magic(&self) -> Result<u32> {
        Ok(*self
            .lcp
            .our_options()
            .iter()
            .find_map(|option| {
                if let LcpOpt::MagicNumber(magic) = option {
                    Some(magic)
                } else {
                    None
                }
            })
            .ok_or(Error::NoMagicNumber)?)
    }

    /// Tries to keep a session open at all costs.
    /// Blocks the caller forever unless a panic occurs or SIGTERM is received.
    ///
    /// # Arguments
    ///
    /// * `v4_tx` - Channel sender for IPv4 configuration updates.
    /// * `v6_tx` - Channel sender for IPv6 configuration updates.
    pub async fn run(
        mut self,
        v4_tx: mpsc::UnboundedSender<Option<Ipv4Config>>,
        v6_tx: mpsc::UnboundedSender<Option<Ipv6Config>>,
    ) -> Result<()> {
        let sock_disc = self.new_discovery_socket()?;
        let mut session_fds: Option<SessionFds> = None;

        let mut pppoe_buf = [0; 1522];
        let mut link_buf = [0; 1494];
        let mut net_buf = [0; 1494];

        let mut sighup = signal(SignalKind::hangup())?;
        let mut sigterm = signal(SignalKind::terminate())?;

        let mut echo_timeout = tokio::time::interval(Duration::from_secs(12));
        let mut ncp_check = tokio::time::interval(Duration::from_secs(20));

        let mut echo_reqs = 0;

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
            let (ctl, ppp_dev) = session_fds.as_mut().map(|fds| fds.both()).unzip();

            tokio::select! {
                biased;

                _ = sighup.recv() => {
                    self.lcp.close();
                    println!("[info] <> reconnect: sighup");
                }
                _ = sigterm.recv() => {
                    self.shutdown = true;
                    self.lcp.close();

                    println!("[info] <> disconnect: sigterm");
                }

                packet = self.pppoe.to_send() => self.send_pppoe(&sock_disc, packet).await?,
                packet = self.lcp.to_send() => self.send_lcp(
                    session_fds.as_mut().map(|fds| fds.link()),
                    packet
                ).await?,
                packet = self.pap.to_send() => self.send_pap(
                    session_fds.as_mut().map(|fds| fds.link()),
                    packet
                ).await?,
                packet = self.chap.to_send() => self.send_chap(
                    session_fds.as_mut().map(|fds| fds.link()),
                    packet
                ).await?,
                packet = self.ipcp.to_send() => self.send_ipcp(
                    session_fds.as_mut().map(|fds| fds.network()),
                    packet
                ).await?,
                packet = self.ipv6cp.to_send() => self.send_ipv6cp(
                    session_fds.as_mut().map(|fds| fds.network()),
                    packet
                ).await?,

                result = pppoe_rx.changed() => {
                    result?;

                    let is_active = *pppoe_rx.borrow_and_update();
                    if is_active {
                        session_fds = Some(self.new_session_fds().await?);
                        self.lcp.up();

                        println!("[info] <- ({}) confirm pppoe session", self.session_id);
                    } else {
                        session_fds = None;

                        self.session_id = 0;
                        self.remote = MacAddr::BROADCAST;

                        self.lcp.down();

                        println!("[info] <> terminate pppoe session");

                        if self.shutdown {
                            return Ok(());
                        }
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
                            Some(AuthProto::Pap) => {
                                self.pap.open();
                                println!("[info] -> authenticate pap");
                            }
                            Some(AuthProto::Chap(ChapAlgorithm::Md5)) => {
                                self.chap.open();
                                println!("[info] -> authenticate chap-md5");
                            }
                            None => {
                                self.authenticated = true;
                                ncp_check.reset();

                                self.ipcp.up();
                                self.ipv6cp.up();

                                println!("[info] <- no authentication required");
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

                        println!("[info] <> terminate lcp");
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

                        println!("[info] <- pap success");
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

                        println!("[info] <- chap success");
                    } else {
                        self.authenticated = false;
                        self.lcp.close();

                        println!("[info] <- chap reauthentication failure");
                    }
                }
                result = ipcp_rx.changed() => {
                    result?;

                    let is_opened = *ipcp_rx.borrow_and_update();
                    if is_opened {
                        let addr = self.ipcp.our_options().iter().find_map(|option| {
                            if let IpcpOpt::IpAddr(addr) = option {
                                Some(addr)
                            } else {
                                None
                            }
                        }).ok_or(Error::NoIpv4Addr)?.0;

                        let dns1 = self.ipcp.our_options().iter().find_map(|option| {
                            if let IpcpOpt::PrimaryDns(addr) = option {
                                Some(addr)
                            } else {
                                None
                            }
                        }).ok_or(Error::NoIpv4Dns1)?.0;

                        let dns2 = self.ipcp.our_options().iter().find_map(|option| {
                            if let IpcpOpt::SecondaryDns(addr) = option {
                                Some(addr)
                            } else {
                                None
                            }
                        }).ok_or(Error::NoIpv4Dns2)?.0;

                        v4_tx.send(Some(Ipv4Config {
                            addr,
                            dns1,
                            dns2,
                        }))?;

                        println!("[info] <> open ipcp");
                    } else {
                        if !self.shutdown {
                            v4_tx.send(None)?;
                        }

                        println!("[info] <> terminate ipcp");
                    }
                }
                result = ipv6cp_rx.changed() => {
                    result?;

                    let is_opened = *ipv6cp_rx.borrow_and_update();
                    if is_opened {
                        let lifid = self.ipv6cp.our_options().iter().map(|option| {
                            let Ipv6cpOpt::InterfaceId(ifid) = option;
                            ifid
                        }).next().ok_or(Error::NoIpv6Local)?;

                        let rifid = self.ipv6cp.peer_options().iter().map(|option| {
                            let Ipv6cpOpt::InterfaceId(ifid) = option;
                            ifid
                        }).next().ok_or(Error::NoIpv6Remote)?;

                        v6_tx.send(Some(Ipv6Config{
                            laddr: ll(*lifid),
                            raddr: ll(*rifid),
                        }))?;

                        println!("[info] <> open ipv6cp");
                    } else {
                        if !self.shutdown {
                            v6_tx.send(None)?;
                        }

                        println!("[info] <> terminate ipv6cp");
                    }
                }

                result = lcp_lower_rx.changed() => {
                    result?;

                    let is_active = *lcp_lower_rx.borrow_and_update();
                    if !is_active { // LCP has gone down, a new PPPoE session is needed.
                        self.lcp.down();
                        self.pppoe.close();

                        if !self.shutdown {
                            self.pppoe.open();
                            self.lcp.open();
                        }
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

                _ = echo_timeout.tick() => {
                    if *lcp_rx.borrow() {
                        if let Some(ppp_dev) = ppp_dev {
                            // Send an LCP Echo-Request every 12 seconds
                            // if no data traffic has been received for 30 seconds.

                            let mut idle = ioctls::ppp_idle64 {
                                xmit_idle: 0,
                                recv_idle: 0,
                            };

                            if unsafe { ioctls::pppiocgidle64(ppp_dev.as_raw_fd(), &mut idle) } < 0 {
                                os_err!();
                            }

                            if idle.recv_idle >= 30 {
                                if echo_reqs >= 5 {
                                    self.lcp.close();
                                    println!("[info] -> timeout");
                                } else {
                                    self.send_lcp(
                                        session_fds.as_mut().map(|fds| fds.link()),
                                        Packet {
                                            ty: PacketType::EchoRequest,
                                            options: Vec::default(),
                                            rejected_code: PacketType::Unknown(0),
                                            rejected_protocol: 0,
                                        }
                                    ).await?;
                                    echo_reqs += 1;
                                }
                            } else {
                                echo_reqs = 0;
                            }
                        }
                    }
                }
                _ = ncp_check.tick() => {
                    if *lcp_rx.borrow() && self.authenticated && !*ipcp_rx.borrow() && !*ipv6cp_rx.borrow() {
                        // No NCPs are up after 20 seconds, terminate the link.
                        self.lcp.close();

                        println!("[info] -> no ncps after 20s");
                    }
                }

                result = sock_disc.read_with(|mut io| io.read(&mut pppoe_buf)) => {
                    let n = result?;
                    let mut pppoe_buf = &pppoe_buf[..n];

                    let mut pkt = PppoePkt::default();
                    pkt.deserialize(&mut pppoe_buf)?;

                    self.handle_pppoe(pkt);
                }
                Some(result) = option_read(ctl, &mut link_buf) => {
                    let n = result?;
                    if n != 0 { // Real message, session not closed.
                        let mut link_buf = &link_buf[..n];

                        let mut pkt = PppPkt::default();
                        pkt.deserialize(&mut link_buf)?;

                        self.handle_ppp(pkt)?;
                    } else { // Session closed.
                        session_fds = None;
                    }
                }
                Some(result) = option_read(ppp_dev, &mut net_buf) => {
                    let n = result?;
                    if n != 0 { // Real message, session not closed.
                        let mut net_buf = &net_buf[..n];

                        let mut pkt = PppPkt::default();
                        pkt.deserialize(&mut net_buf)?;

                        self.handle_ppp(pkt)?;
                    } else { // Session closed.
                        session_fds = None;
                    }
                }
            }
        }
    }

    /// Transforms a [`PppoePacket`] into a [`PppoePkt`] and sends it
    /// over the network interface.
    async fn send_pppoe(&self, sock_disc: &Async<Socket>, packet: PppoePacket) -> Result<()> {
        let pkt = match packet.ty {
            PppoeType::Padi => Some(PppoePkt::new_padi(
                self.local,
                vec![PppoeVal::ServiceName(String::new()).into()],
            )),
            PppoeType::Pado | PppoeType::Pads => None, // illegal
            PppoeType::Padr => Some(PppoePkt::new_padr(
                self.remote,
                self.local,
                if let Some(ac_cookie) = packet.ac_cookie {
                    vec![
                        PppoeVal::ServiceName(String::new()).into(),
                        PppoeVal::AcCookie(ac_cookie).into(),
                    ]
                } else {
                    vec![PppoeVal::ServiceName(String::new()).into()]
                },
            )),
            PppoeType::Padt => Some(PppoePkt::new_padt(
                self.remote,
                self.local,
                self.session_id,
                vec![],
            )),
        };

        if let Some(pkt) = pkt {
            let mut buf = Vec::new();
            pkt.serialize(&mut buf)?;

            sock_disc.write_with(|mut io| io.write(&buf)).await?;
        }

        Ok(())
    }

    /// Transforms a [`Packet`] into an [`LcpPkt`] and sends it
    /// over the PPP session if available.
    async fn send_lcp(
        &mut self,
        file: Option<&AsyncFd<File>>,
        packet: Packet<LcpOpt>,
    ) -> Result<()> {
        let pkt = PppPkt::new_lcp(match packet.ty {
            PacketType::ConfigureRequest => {
                self.lcp_id_cfg = rand::random();
                LcpPkt::new_configure_request(
                    self.lcp_id_cfg,
                    packet.options.into_iter().map(|opt| opt.into()).collect(),
                )
            }
            PacketType::ConfigureAck => LcpPkt::new_configure_ack(
                self.lcp_id_remote,
                packet.options.into_iter().map(|opt| opt.into()).collect(),
            ),
            PacketType::ConfigureNak => LcpPkt::new_configure_nak(
                self.lcp_id_remote,
                packet.options.into_iter().map(|opt| opt.into()).collect(),
            ),
            PacketType::ConfigureReject => LcpPkt::new_configure_reject(
                self.lcp_id_remote,
                packet.options.into_iter().map(|opt| opt.into()).collect(),
            ),
            PacketType::TerminateRequest => {
                self.lcp_id_term = rand::random();
                LcpPkt::new_terminate_request(self.lcp_id_term, Vec::default())
            }
            PacketType::TerminateAck => {
                LcpPkt::new_terminate_ack(self.lcp_id_remote, Vec::default())
            }
            PacketType::CodeReject => LcpPkt::new_code_reject(
                self.lcp_id_remote,
                vec![self.lcp_id_remote, packet.rejected_code.into()],
            ),
            PacketType::ProtocolReject => LcpPkt::new_protocol_reject(
                self.last_id_remote,
                packet.rejected_protocol,
                Vec::default(),
            ),
            PacketType::EchoRequest => {
                self.lcp_id_echo = rand::random();
                LcpPkt::new_echo_request(self.lcp_id_echo, self.magic()?, Vec::default())
            }
            PacketType::EchoReply => {
                LcpPkt::new_echo_reply(self.lcp_id_remote, self.magic()?, Vec::default())
            }
            PacketType::DiscardRequest => {
                LcpPkt::new_discard_request(rand::random(), self.magic()?, Vec::default())
            }
            PacketType::Unknown(_) => return Ok(()), // illegal
        });

        if let Some(file) = file {
            let mut buf = Vec::new();
            pkt.serialize(&mut buf)?;

            async_write_all(file, &buf).await?;
        }

        Ok(())
    }

    /// Transforms a [`PapPacket`] into a [`PapPkt`] and sends it
    /// over the PPP session if available.
    async fn send_pap(&mut self, file: Option<&AsyncFd<File>>, packet: PapPacket) -> Result<()> {
        let pkt = PppPkt::new_pap(match packet {
            PapPacket::AuthenticateRequest => {
                self.pap_id = rand::random();
                PapPkt::new_authenticate_request(
                    self.pap_id,
                    self.username.clone(),
                    self.password.clone(),
                )
            }
            PapPacket::AuthenticateAck | PapPacket::AuthenticateNak => return Ok(()), // illegal
            PapPacket::TerminateLower => {
                self.lcp.close();
                return Ok(());
            }
        });

        if let Some(file) = file {
            let mut buf = Vec::new();
            pkt.serialize(&mut buf)?;

            async_write_all(file, &buf).await?;
        }

        Ok(())
    }

    /// Transforms a [`ChapPacket`] into a [`ChapPkt`] and sends it
    /// over the PPP session if available.
    async fn send_chap(&mut self, file: Option<&AsyncFd<File>>, packet: ChapPacket) -> Result<()> {
        let pkt = PppPkt::new_chap(match packet.ty {
            ChapType::Challenge | ChapType::Success | ChapType::Failure => return Ok(()), // illegal
            ChapType::Response => {
                let mut hash_input = Vec::new();

                hash_input.push(self.chap_id_remote);
                hash_input.extend_from_slice(self.password.as_bytes());
                hash_input.extend_from_slice(&packet.data);

                let hash = md5::compute(hash_input).to_vec();

                ChapPkt::new_response(self.chap_id_remote, hash, self.username.clone())
            }
            ChapType::TerminateLower => {
                self.lcp.close();
                return Ok(());
            }
        });

        if let Some(file) = file {
            let mut buf = Vec::new();
            pkt.serialize(&mut buf)?;

            async_write_all(file, &buf).await?;
        }

        Ok(())
    }

    /// Transforms a [`Packet`] into an [`IpcpPkt`] and sends it
    /// over the PPP session if available.
    async fn send_ipcp(
        &mut self,
        file: Option<&AsyncFd<File>>,
        packet: Packet<IpcpOpt>,
    ) -> Result<()> {
        let pkt = PppPkt::new_ipcp(match packet.ty {
            PacketType::ConfigureRequest => {
                self.ipcp_id_cfg = rand::random();
                IpcpPkt::new_configure_request(
                    self.ipcp_id_cfg,
                    packet.options.into_iter().map(|opt| opt.into()).collect(),
                )
            }
            PacketType::ConfigureAck => IpcpPkt::new_configure_ack(
                self.ipcp_id_remote,
                packet.options.into_iter().map(|opt| opt.into()).collect(),
            ),
            PacketType::ConfigureNak => IpcpPkt::new_configure_nak(
                self.ipcp_id_remote,
                packet.options.into_iter().map(|opt| opt.into()).collect(),
            ),
            PacketType::ConfigureReject => IpcpPkt::new_configure_reject(
                self.ipcp_id_remote,
                packet.options.into_iter().map(|opt| opt.into()).collect(),
            ),
            PacketType::TerminateRequest => {
                self.ipcp_id_term = rand::random();
                IpcpPkt::new_terminate_request(self.ipcp_id_term, Vec::default())
            }
            PacketType::TerminateAck => {
                IpcpPkt::new_terminate_ack(self.ipcp_id_remote, Vec::default())
            }
            PacketType::CodeReject => IpcpPkt::new_code_reject(
                self.ipcp_id_remote,
                vec![self.ipcp_id_remote, packet.rejected_code.into()],
            ),
            _ => return Ok(()), // illegal
        });

        if let Some(file) = file {
            let mut buf = Vec::new();
            pkt.serialize(&mut buf)?;

            async_write_all(file, &buf).await?;
        }

        Ok(())
    }

    /// Transforms a [`Packet`] into an [`Ipv6cpPkt`] and sends it
    /// over the PPP session if available.
    async fn send_ipv6cp(
        &mut self,
        file: Option<&AsyncFd<File>>,
        packet: Packet<Ipv6cpOpt>,
    ) -> Result<()> {
        let pkt = PppPkt::new_ipv6cp(match packet.ty {
            PacketType::ConfigureRequest => {
                self.ipv6cp_id_cfg = rand::random();
                Ipv6cpPkt::new_configure_request(
                    self.ipv6cp_id_cfg,
                    packet.options.into_iter().map(|opt| opt.into()).collect(),
                )
            }
            PacketType::ConfigureAck => Ipv6cpPkt::new_configure_ack(
                self.ipv6cp_id_remote,
                packet.options.into_iter().map(|opt| opt.into()).collect(),
            ),
            PacketType::ConfigureNak => Ipv6cpPkt::new_configure_nak(
                self.ipv6cp_id_remote,
                packet.options.into_iter().map(|opt| opt.into()).collect(),
            ),
            PacketType::ConfigureReject => Ipv6cpPkt::new_configure_reject(
                self.ipv6cp_id_remote,
                packet.options.into_iter().map(|opt| opt.into()).collect(),
            ),
            PacketType::TerminateRequest => {
                self.ipv6cp_id_term = rand::random();
                Ipv6cpPkt::new_terminate_request(self.ipv6cp_id_term, Vec::default())
            }
            PacketType::TerminateAck => {
                Ipv6cpPkt::new_terminate_ack(self.ipv6cp_id_remote, Vec::default())
            }
            PacketType::CodeReject => Ipv6cpPkt::new_code_reject(
                self.ipv6cp_id_remote,
                vec![self.ipv6cp_id_remote, packet.rejected_code.into()],
            ),
            _ => return Ok(()), // illegal
        });

        if let Some(file) = file {
            let mut buf = Vec::new();
            pkt.serialize(&mut buf)?;

            async_write_all(file, &buf).await?;
        }

        Ok(())
    }

    /// Transforms a [`PppoePkt`] into a [`PppoePacket`] and feeds it
    /// into the PPPoE state machine.
    fn handle_pppoe(&mut self, pkt: PppoePkt) {
        if pkt.session_id != self.session_id && self.session_id != 0 {
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
    fn handle_ppp(&mut self, pkt: PppPkt) -> Result<()> {
        match pkt.data {
            PppData::Lcp(lcp) => self.handle_lcp(lcp)?,
            PppData::Pap(pap) => self.handle_pap(pap),
            PppData::Chap(chap) => self.handle_chap(chap),
            PppData::Ipcp(ipcp) => self.handle_ipcp(ipcp),
            PppData::Ipv6cp(ipv6cp) => self.handle_ipv6cp(ipv6cp),
        }

        Ok(())
    }

    /// Transforms an [`LcpPkt`] into an [`LcpPacket`] and feeds it
    /// into the LCP state machine.
    fn handle_lcp(&mut self, pkt: LcpPkt) -> Result<()> {
        self.last_id_remote = pkt.identifier;
        self.lcp_id_remote = pkt.identifier;

        let packet = match pkt.data {
            LcpData::ConfigureRequest(cfg_req) => Some(Packet {
                ty: PacketType::ConfigureRequest,
                options: cfg_req.options.into_iter().map(|opt| opt.value).collect(),
                rejected_code: PacketType::Unknown(0),
                rejected_protocol: 0,
            }),
            LcpData::ConfigureAck(cfg_ack) => {
                if pkt.identifier == self.lcp_id_cfg {
                    Some(Packet {
                        ty: PacketType::ConfigureAck,
                        options: cfg_ack.options.into_iter().map(|opt| opt.value).collect(),
                        rejected_code: PacketType::Unknown(0),
                        rejected_protocol: 0,
                    })
                } else {
                    None
                }
            }
            LcpData::ConfigureNak(cfg_nak) => {
                if pkt.identifier == self.lcp_id_cfg {
                    Some(Packet {
                        ty: PacketType::ConfigureNak,
                        options: cfg_nak.options.into_iter().map(|opt| opt.value).collect(),
                        rejected_code: PacketType::Unknown(0),
                        rejected_protocol: 0,
                    })
                } else {
                    None
                }
            }
            LcpData::ConfigureReject(cfg_reject) => {
                if pkt.identifier == self.lcp_id_cfg {
                    Some(Packet {
                        ty: PacketType::ConfigureReject,
                        options: cfg_reject
                            .options
                            .into_iter()
                            .map(|opt| opt.value)
                            .collect(),
                        rejected_code: PacketType::Unknown(0),
                        rejected_protocol: 0,
                    })
                } else {
                    None
                }
            }
            LcpData::TerminateRequest(_) => Some(Packet {
                ty: PacketType::TerminateRequest,
                options: Vec::default(),
                rejected_code: PacketType::Unknown(0),
                rejected_protocol: 0,
            }),
            LcpData::TerminateAck(_) => {
                if pkt.identifier == self.lcp_id_term {
                    Some(Packet {
                        ty: PacketType::TerminateAck,
                        options: Vec::default(),
                        rejected_code: PacketType::Unknown(0),
                        rejected_protocol: 0,
                    })
                } else {
                    None
                }
            }
            LcpData::CodeReject(code_reject) => Some(Packet {
                ty: PacketType::CodeReject,
                options: Vec::default(),
                rejected_code: code_reject.pkt[1].into(),
                rejected_protocol: 0,
            }),
            LcpData::ProtocolReject(protocol_reject) => match protocol_reject.protocol {
                IPCP => {
                    self.ipcp.from_recv(Packet {
                        ty: PacketType::ProtocolReject,
                        options: Vec::default(),
                        rejected_code: PacketType::Unknown(0),
                        rejected_protocol: protocol_reject.protocol,
                    });

                    None
                }
                IPV6CP => {
                    self.ipv6cp.from_recv(Packet {
                        ty: PacketType::ProtocolReject,
                        options: Vec::default(),
                        rejected_code: PacketType::Unknown(0),
                        rejected_protocol: protocol_reject.protocol,
                    });

                    None
                }
                // LCP, PAP, CHAP or anything else.
                _ => Some(Packet {
                    ty: PacketType::ProtocolReject,
                    options: Vec::default(),
                    rejected_code: PacketType::Unknown(0),
                    rejected_protocol: protocol_reject.protocol,
                }),
            },
            LcpData::EchoRequest(echo_request) => {
                if echo_request.magic != self.magic()? {
                    Some(Packet {
                        ty: PacketType::EchoRequest,
                        options: Vec::default(),
                        rejected_code: PacketType::Unknown(0),
                        rejected_protocol: 0,
                    })
                } else {
                    println!("[warn] <- own echo-req");
                    None
                }
            }
            LcpData::EchoReply(echo_reply) => {
                if pkt.identifier == self.lcp_id_echo {
                    if echo_reply.magic != self.magic()? {
                        Some(Packet {
                            ty: PacketType::EchoReply,
                            options: Vec::default(),
                            rejected_code: PacketType::Unknown(0),
                            rejected_protocol: 0,
                        })
                    } else {
                        println!("[warn] <- own echo-reply");
                        None
                    }
                } else {
                    None
                }
            }
            LcpData::DiscardRequest(discard_request) => {
                if discard_request.magic != self.magic()? {
                    Some(Packet {
                        ty: PacketType::DiscardRequest,
                        options: Vec::default(),
                        rejected_code: PacketType::Unknown(0),
                        rejected_protocol: 0,
                    })
                } else {
                    println!("[warn] <- own discard-req");
                    None
                }
            }
        };

        if let Some(packet) = packet {
            self.lcp.from_recv(packet);
        }

        Ok(())
    }

    /// Transforms a [`PapPkt`] into a [`PapPacket`] and feeds it
    /// into the PAP state machine.
    fn handle_pap(&mut self, pkt: PapPkt) {
        self.last_id_remote = pkt.identifier;

        self.pap.from_recv(match pkt.data {
            PapData::AuthenticateRequest(_) => PapPacket::AuthenticateRequest,
            PapData::AuthenticateAck(_) => {
                if pkt.identifier == self.pap_id {
                    PapPacket::AuthenticateAck
                } else {
                    return;
                }
            }
            PapData::AuthenticateNak(_) => {
                if pkt.identifier == self.pap_id {
                    PapPacket::AuthenticateNak
                } else {
                    return;
                }
            }
        });
    }

    /// Transforms a [`ChapPkt`] into a [`ChapPacket`] and feeds it
    /// into the CHAP state machine.
    fn handle_chap(&mut self, pkt: ChapPkt) {
        self.last_id_remote = pkt.identifier;
        self.chap_id_remote = pkt.identifier;

        self.chap.from_recv(match pkt.data {
            ChapData::Challenge(challenge) => ChapPacket {
                ty: ChapType::Challenge,
                data: challenge.value,
            },
            ChapData::Response(response) => ChapPacket {
                ty: ChapType::Response,
                data: response.value,
            },
            ChapData::Success(_) => ChapPacket {
                ty: ChapType::Success,
                data: Vec::default(),
            },
            ChapData::Failure(_) => ChapPacket {
                ty: ChapType::Failure,
                data: Vec::default(),
            },
        });
    }

    /// Transforms an [`IpcpPkt`] into an [`IpcpPacket`] and feeds it
    /// into the IPCP state machine.
    fn handle_ipcp(&mut self, pkt: IpcpPkt) {
        self.last_id_remote = pkt.identifier;
        self.ipcp_id_remote = pkt.identifier;

        self.ipcp.from_recv(match pkt.data {
            IpcpData::ConfigureRequest(cfg_req) => Packet {
                ty: PacketType::ConfigureRequest,
                options: cfg_req.options.into_iter().map(|opt| opt.value).collect(),
                rejected_code: PacketType::Unknown(0),
                rejected_protocol: 0,
            },
            IpcpData::ConfigureAck(cfg_ack) => {
                if pkt.identifier == self.ipcp_id_cfg {
                    Packet {
                        ty: PacketType::ConfigureAck,
                        options: cfg_ack.options.into_iter().map(|opt| opt.value).collect(),
                        rejected_code: PacketType::Unknown(0),
                        rejected_protocol: 0,
                    }
                } else {
                    return;
                }
            }
            IpcpData::ConfigureNak(cfg_nak) => {
                if pkt.identifier == self.ipcp_id_cfg {
                    Packet {
                        ty: PacketType::ConfigureNak,
                        options: cfg_nak.options.into_iter().map(|opt| opt.value).collect(),
                        rejected_code: PacketType::Unknown(0),
                        rejected_protocol: 0,
                    }
                } else {
                    return;
                }
            }
            IpcpData::ConfigureReject(cfg_reject) => {
                if pkt.identifier == self.ipcp_id_cfg {
                    Packet {
                        ty: PacketType::ConfigureReject,
                        options: cfg_reject
                            .options
                            .into_iter()
                            .map(|opt| opt.value)
                            .collect(),
                        rejected_code: PacketType::Unknown(0),
                        rejected_protocol: 0,
                    }
                } else {
                    return;
                }
            }
            IpcpData::TerminateRequest(_) => Packet {
                ty: PacketType::TerminateRequest,
                options: Vec::default(),
                rejected_code: PacketType::Unknown(0),
                rejected_protocol: 0,
            },
            IpcpData::TerminateAck(_) => {
                if pkt.identifier == self.ipcp_id_term {
                    Packet {
                        ty: PacketType::TerminateAck,
                        options: Vec::default(),
                        rejected_code: PacketType::Unknown(0),
                        rejected_protocol: 0,
                    }
                } else {
                    return;
                }
            }
            IpcpData::CodeReject(code_reject) => Packet {
                ty: PacketType::CodeReject,
                options: Vec::default(),
                rejected_code: code_reject.pkt[1].into(),
                rejected_protocol: 0,
            },
        });
    }

    /// Transforms an [`Ipv6cpPkt`] into an [`Ipv6cpPacket`] and feeds it
    /// into the IPv6CP state machine.
    fn handle_ipv6cp(&mut self, pkt: Ipv6cpPkt) {
        self.last_id_remote = pkt.identifier;
        self.ipv6cp_id_remote = pkt.identifier;

        self.ipv6cp.from_recv(match pkt.data {
            Ipv6cpData::ConfigureRequest(cfg_req) => Packet {
                ty: PacketType::ConfigureRequest,
                options: cfg_req.options.into_iter().map(|opt| opt.value).collect(),
                rejected_code: PacketType::Unknown(0),
                rejected_protocol: 0,
            },
            Ipv6cpData::ConfigureAck(cfg_ack) => {
                if pkt.identifier == self.ipv6cp_id_cfg {
                    Packet {
                        ty: PacketType::ConfigureAck,
                        options: cfg_ack.options.into_iter().map(|opt| opt.value).collect(),
                        rejected_code: PacketType::Unknown(0),
                        rejected_protocol: 0,
                    }
                } else {
                    return;
                }
            }
            Ipv6cpData::ConfigureNak(cfg_nak) => {
                if pkt.identifier == self.ipv6cp_id_cfg {
                    Packet {
                        ty: PacketType::ConfigureNak,
                        options: cfg_nak.options.into_iter().map(|opt| opt.value).collect(),
                        rejected_code: PacketType::Unknown(0),
                        rejected_protocol: 0,
                    }
                } else {
                    return;
                }
            }
            Ipv6cpData::ConfigureReject(cfg_reject) => {
                if pkt.identifier == self.ipv6cp_id_cfg {
                    Packet {
                        ty: PacketType::ConfigureReject,
                        options: cfg_reject
                            .options
                            .into_iter()
                            .map(|opt| opt.value)
                            .collect(),
                        rejected_code: PacketType::Unknown(0),
                        rejected_protocol: 0,
                    }
                } else {
                    return;
                }
            }
            Ipv6cpData::TerminateRequest(_) => Packet {
                ty: PacketType::TerminateRequest,
                options: Vec::default(),
                rejected_code: PacketType::Unknown(0),
                rejected_protocol: 0,
            },
            Ipv6cpData::TerminateAck(_) => {
                if pkt.identifier == self.ipv6cp_id_term {
                    Packet {
                        ty: PacketType::TerminateAck,
                        options: Vec::default(),
                        rejected_code: PacketType::Unknown(0),
                        rejected_protocol: 0,
                    }
                } else {
                    return;
                }
            }
            Ipv6cpData::CodeReject(code_reject) => Packet {
                ty: PacketType::CodeReject,
                options: Vec::default(),
                rejected_code: code_reject.pkt[1].into(),
                rejected_protocol: 0,
            },
        });
    }

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
    async fn new_session_fds(&self) -> Result<SessionFds> {
        use libc::{
            fcntl, sockaddr_storage, socklen_t, AF_PPPOX, F_GETFL, F_SETFL, IFNAMSIZ, O_NONBLOCK,
        };

        const PX_PROTO_OE: i32 = 0;

        let c_link = CString::new(&*self.link)?;

        let mut dev = [0; IFNAMSIZ];
        for (i, ch) in c_link.as_bytes_with_nul().iter().enumerate() {
            dev[i] = *ch;
        }

        let sp = sockaddr_pppox {
            sa_family: AF_PPPOX as u16,
            sa_protocol: PX_PROTO_OE as u32,
            pppoe: pppoe_addr {
                sid: self.session_id.to_be(),
                remote: self.remote,
                dev,
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

        if unsafe { ioctls::pppiocattchan(ctl.as_raw_fd(), &chindex) } < 0 {
            os_err!();
        }

        let flags = unsafe { fcntl(ctl.as_raw_fd(), F_GETFL) };
        if flags < 0 || unsafe { fcntl(ctl.as_raw_fd(), F_SETFL, flags | O_NONBLOCK) } < 0 {
            os_err!();
        }

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

        let flags = unsafe { fcntl(ppp_dev.as_raw_fd(), F_GETFL) };
        if flags < 0 || unsafe { fcntl(ppp_dev.as_raw_fd(), F_SETFL, flags | O_NONBLOCK) } < 0 {
            os_err!();
        }

        Ok(SessionFds(sock, AsyncFd::new(ctl)?, AsyncFd::new(ppp_dev)?))
    }
}

async fn option_read(file: Option<&AsyncFd<File>>, buf: &mut [u8]) -> Option<io::Result<usize>> {
    match file {
        Some(file) => Some(option_read_inner(file, buf).await),
        None => None,
    }
}

async fn option_read_inner(file: &AsyncFd<File>, buf: &mut [u8]) -> io::Result<usize> {
    loop {
        let mut guard = file.readable().await?;

        match guard.try_io(|inner| inner.get_ref().read(buf)) {
            Ok(result) => return result,
            Err(_would_block) => continue,
        }
    }
}

async fn async_write_all(file: &AsyncFd<File>, buf: &[u8]) -> io::Result<()> {
    loop {
        let mut guard = file.writable().await?;

        match guard.try_io(|inner| inner.get_ref().write_all(buf)) {
            Ok(result) => return result,
            Err(_would_block) => continue,
        }
    }
}

/// Creates a link-local IPv6 address from a 64-bit interface identifier.
fn ll(ifid: u64) -> Ipv6Addr {
    ((0xfe80 << 112) | ifid as u128).into()
}

use ioctl_sys::ioctl;

#[repr(C, packed)]
pub struct ppp_idle64 {
    pub xmit_idle: i64,
    pub recv_idle: i64,
}

ioctl!(write pppiocattchan with b't', 56; ::std::os::raw::c_int);
ioctl!(write pppiocconnect with b't', 58; ::std::os::raw::c_int);
ioctl!(read pppiocgchan with b't', 55; ::std::os::raw::c_int);
ioctl!(readwrite pppiocnewunit with b't', 62; ::std::os::raw::c_int);
ioctl!(read pppiocgidle64 with b't', 63; ppp_idle64);

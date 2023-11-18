use ioctl_sys::ioctl;

ioctl!(write pppiocattchan with b't', 56; ::std::os::raw::c_int);
ioctl!(write pppiocconnect with b't', 58; ::std::os::raw::c_int);
ioctl!(read pppiocgchan with b't', 55; ::std::os::raw::c_int);
ioctl!(readwrite pppiocnewunit with b't', 62; ::std::os::raw::c_int);

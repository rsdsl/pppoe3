use crate::ProtocolOption;

use ppproperly::LcpOpt;

impl ProtocolOption for LcpOpt {
    const PROTOCOL: u16 = ppproperly::LCP;
}

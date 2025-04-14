use crate::ProtocolOption;

use ppproperly::Ipv6cpOpt;

impl ProtocolOption for Ipv6cpOpt {
    const PROTOCOL: u16 = ppproperly::IPV6CP;

    fn is_unknown(&self) -> bool {
        matches!(self, Ipv6cpOpt::Unhandled(..))
    }
}

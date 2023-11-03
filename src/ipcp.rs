use crate::ProtocolOption;

use ppproperly::IpcpOpt;

impl ProtocolOption for IpcpOpt {
    const PROTOCOL: u16 = ppproperly::IPCP;
}

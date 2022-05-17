#![no_std]
#![no_main]

use core::fmt::Error;
use cty::*;
use redbpf_probes::xdp::prelude::*;

program!(0xFFFFFFFE, "GPL");

const TCP_XDP_DROP: XdpAction = XdpAction::Drop;
const UDP_XDP_DROP: XdpAction = XdpAction::Drop;
const XDP_PASS: XdpAction = XdpAction::Pass;

// XDP/eBPF based IP-layer firewall to drop all UDP packets.
// And, also drop all TCP packets destined to port 80.
#[xdp]
pub fn xdp_ip_firewall(ctx: XdpContext) -> XdpResult {
    if let Ok(ip_protocol) = get_ip_protocol(&ctx) {
        match ip_protocol as u32 {
            IPPROTO_UDP => return Ok(UDP_XDP_DROP), // drop it on the floor
            IPPROTO_TCP => {
                if let Ok(transport) = ctx.transport() {
                    if transport.dest() == 80 {
                        return Ok(TCP_XDP_DROP);  // drop it on the floor
                    }
                }
            }
            _ => return Ok(XDP_PASS), // pass it up the protocol stack
        }
    }
    return Ok(XDP_PASS); // pass it up the protocol stack
}

fn get_ip_protocol(ctx: &XdpContext) -> Result<u32, Error> {
    if let Ok(ip) = ctx.ip() {
        // We need to make raw pointer into a u32 so `unsafe` is required.
        unsafe {
            return Ok((*ip).protocol as u32);
        }
    }
    // Anything above `255` is reserved.
    return Ok(0x10000);
}

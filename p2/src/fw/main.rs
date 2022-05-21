#![no_std]
#![no_main]

use core::fmt::Error;
use core::str;
use core::str::*;
use cty::*;
use redbpf_probes::xdp::prelude::*;
use redbpf_probes::bindings::*;

program!(0xFFFFFFFE, "GPL");

const TCP_XDP_DROP: XdpAction = XdpAction::Drop;
const UDP_XDP_DROP: XdpAction = XdpAction::Drop;
const XDP_PASS: XdpAction = XdpAction::Pass;
const XDP_DROP: XdpAction = XdpAction::Drop;

// * --- *

pub const LIST_SIZE: usize = 3;

// XDP/eBPF based IP-layer firewall to drop all UDP packets.
// And, also drop all TCP packets destined to port 80.
#[xdp]
pub fn xdp_ip_firewall(ctx: XdpContext) -> XdpResult {
    // let cmd = include!("config");
    let cmds: [u32;LIST_SIZE] = include!("test");
    let mut index = 0;

    if let Ok(ip_protocol) = get_ip_protocol(&ctx) {
        /*
        if (ip_protocol as u32) == cmd {
            return Ok(XDP_DROP)
        }
        */
        while index < LIST_SIZE {
            if (ip_protocol as u32) == cmds[index] {
                return Ok(XDP_DROP)
            }
            index += 1;
        }
        match ip_protocol as u32 {
            /*
            IPPROTO_ICMP => {
                if cmd == IPPROTO_ICMP {
                    return Ok(XDP_DROP)
                }
                // return Ok(XDP_DROP)
            },
            */
            IPPROTO_UDP => return Ok(XDP_PASS),
            IPPROTO_TCP => {
                /*
                if let Ok(eth) = ctx.eth() {
                    let eth_clone = eth.clone();
                    h_addr = unsafe { (*eth_clone).h_dest };
                }
                */
                return Ok(XDP_PASS)
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

#![no_std]
#![no_main]

use core::fmt::Error;
use core::str;
use core::str::*;
use core::convert::TryInto;
use cty::*;
use redbpf_probes::xdp::prelude::*;
use redbpf_probes::bindings::*;

program!(0xFFFFFFFE, "GPL");

const XDP_PASS: XdpAction = XdpAction::Pass;
const XDP_DROP: XdpAction = XdpAction::Drop;

// * --- *

// XDP/eBPF based IP-layer firewall to drop all UDP packets.
#[xdp]
pub fn xdp_ip_firewall(ctx: XdpContext) -> XdpResult {
    // Blacklist ips
    let ips = include!("block-ip");
    if let Ok(ip_saddr) = get_ip_saddr(&ctx) {
        for ip in ips {
            if ip_saddr == ip.to_be() {
                return Ok(XDP_DROP)
            }
        }  
    }

    // Blacklist ports
    let ports = include!("block-port");
    if let Ok(sport) = get_sport(&ctx) {
        for port in ports {
            if (port as u16) == sport {
                return Ok(XDP_DROP)
            }
        }
    }

    // Block Protocols
    let cmds = include!("block-proto");
    if let Ok(ip_protocol) = get_ip_protocol(&ctx) {
        for cmd in cmds {
            if (ip_protocol as u32) == cmd {
                return Ok(XDP_DROP)
            }
        }
    }

    return Ok(XDP_PASS);
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

fn get_ip_saddr(ctx: &XdpContext) -> Result<u32, Error> {
    if let Ok(ip) = ctx.ip() {
        unsafe {
            return Ok((*ip).saddr as u32);
        }
    }
    return Ok(0x10000);
}

fn get_sport(ctx: &XdpContext) -> Result<u16, Error> {
    if let Ok(transport) = ctx.transport() {
        return Ok(transport.source())
    }
    return Ok(65353)
}

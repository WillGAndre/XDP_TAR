#![no_std]
#![no_main]

use core::fmt::Error;
use core::{str, mem};
use core::str::*;
use core::convert::TryInto;
use cty::*;
use redbpf_probes::xdp::DevMap;
use redbpf_probes::xdp::prelude::*;
use redbpf_probes::bindings::*;

program!(0xFFFFFFFE, "GPL");

const XDP_PASS: XdpAction = XdpAction::Pass;
const XDP_DROP: XdpAction = XdpAction::Drop;
const XDP_REDIRECT: XdpAction = XdpAction::Redirect;
const XDP_TX: XdpAction = XdpAction::Tx;

// * --- *

#[map]
static mut map: DevMap = DevMap::with_max_entries(2);

// * --- *

// XDP/eBPF based IP-layer firewall to drop all UDP packets.
#[xdp]
pub fn xdp_ip_firewall(ctx: XdpContext) -> XdpResult {
    let data = ctx.data_start();
    let data_end = ctx.data_end();
    let s_eth = mem::size_of::<*const ethhdr>();
    let s_ip = mem::size_of::<*const iphdr>();

    // Block malformed packets
    if data + s_eth > data_end {
        return Ok(XDP_DROP)
    } else if data + s_eth + s_ip > data_end {
        return Ok(XDP_DROP)
    }
    
    /*
    unsafe {
        if let Ok(_) = map.redirect(2 as u32) {
            return Ok(XDP_REDIRECT)
        }
    }
    */

    // Blacklist ips
    let ips = include!("block-ip");
    if let Ok(ip_saddr) = get_ip_saddr(&ctx) {
        for ip in ips {
            if ip_saddr == ip.to_be() {
                /*
                unsafe {
                    if let Ok(_) = map.redirect(1) {
                        return Ok(XDP_REDIRECT)
                    }
                    // return Ok(bpf_redirect((*ctx_xdp_md).ingress_ifindex as u32, 0));
                }
                */
                // return Ok(XDP_REDIRECT)
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

    // Block TCP Flags
    let block_tcp_flags = include!("block-tcp-flags");
    let mut index = 0;
    if let Ok(tcp_flags) = get_tcp_flags(&ctx) {
        while index < 8 {
            if block_tcp_flags[index] != 0 {
                if block_tcp_flags[index] == tcp_flags[index] {
                    return Ok(XDP_DROP)
                }
            }
            index += 1;
        }
    }

    return Ok(XDP_PASS);
}

fn get_ip_protocol(ctx: &XdpContext) -> Result<u32, Error> {
    if let Ok(ip) = ctx.ip() {
        unsafe {
            return Ok((*ip).protocol as u32);
        }
    }
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

fn get_tcp_flags(ctx: &XdpContext) -> Result<[u16; 8], Error> {
    let mut res = [0u16; 8];
    if let Ok(transort) = ctx.transport() {
        match transort {
            Transport::TCP(tcphdr) => {
                unsafe {
                    res[0] = (*tcphdr).res1() as u16;
                    res[1] = (*tcphdr).doff() as u16;
                    res[2] = (*tcphdr).fin() as u16;
                    res[3] = (*tcphdr).syn() as u16;
                    res[4] = (*tcphdr).rst() as u16;
                    res[5] = (*tcphdr).psh() as u16;
                    res[6] = (*tcphdr).ack() as u16;
		            res[7] = (*tcphdr).urg() as u16;
                }
            },
            Transport::UDP(_udphdr) => {
            },
        }
    }

    Ok(res)
}

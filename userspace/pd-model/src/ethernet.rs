//! 802.3x flow control on the customer Ethernet port.
//!
//! Autonegotiation on `eth0` settles on no PAUSE, because the Titan
//! advertises none. The vendor driver turns flow control on anyway:
//!
//! - `gdm_eth_open` sets hardware flow control (EFC) in the DMA operation
//!   mode register, with the RX FIFO thresholds at 2 KB on and 1 KB off. The
//!   MAC then sends a PAUSE frame with the longest pause time (0xffff quanta,
//!   about 33.5 ms at 1 Gb/s) whenever its RX FIFO fills, for example while
//!   the CPU is busy with the LTE interrupt.
//! - At every link-up `gdm_eth_update_link_speed` sets the MAC flow control
//!   register to send PAUSE frames and to obey them (TFE and RFE).
//!
//! A bench unit's `kern eth fc` showed `mac fc(ffff0006): rx=1 tx=1
//! pause-time=ffff` and `dma ctrl(00203306): efc=1` while `ethtool` showed no
//! pause advertised.
//!
//! The vendor kernel's own `kern eth -fc` clears EFC and nothing else. Without
//! EFC the MAC never starts a PAUSE frame by itself, so the Titan stops
//! pausing the customer router. The command does not reset the PHY, the MAC
//! or the DMA rings, and the link stays up.
//!
//! The other half, obeying a router's PAUSE frames (RFE), has no `kern`
//! subcommand. Only a raw register write reaches it, and the driver writes
//! that register again at every link-up. Witcher leaves it alone.
//!
//! The driver sets EFC again whenever the interface is opened, and `rcinit`
//! takes eth0 down and up after every PDN change. So the keeper clears it when
//! it starts and each time eth0 gets its carrier back. `flow_control=stock` in
//! `ethernet.conf` keeps the vendor setting. Turning EFC back on by hand:
//! `kern eth fc 1 2` (the stock 2 KB and 1 KB thresholds).

/// The vendor command that clears EFC.
pub const PROGRAM: &str = "kern";
pub const DISABLE: [&str; 2] = ["eth", "-fc"];

/// `ethernet.conf` asks for the vendor's flow control.
pub fn stock_requested(conf: &str) -> bool {
    conf.lines().any(|line| {
        let mut parts = line.splitn(2, '=');
        parts.next().map(str::trim) == Some("flow_control")
            && parts.next().map(str::trim) == Some("stock")
    })
}

/// When to clear EFC.
#[derive(Default)]
pub struct Watch {
    carrier: Option<bool>,
}

impl Watch {
    /// One look at the port's carrier. True at the first look and each time
    /// the carrier comes back, which covers the interface being opened again.
    pub fn tick(&mut self, carrier: bool) -> bool {
        let apply = self.carrier.is_none_or(|was| !was && carrier);
        self.carrier = Some(carrier);
        apply
    }
}

/// `efc` from the kernel's flow control report, which `kern eth -fc` prints
/// after it changes the register:
/// `  dma ctrl(00203206): efc=0 rfa=1(fill=2KB) rfd=2(fill=1KB)`.
pub fn efc(line: &str) -> Option<bool> {
    let rest = crate::extdev::message(line).strip_prefix("dma ctrl(")?;
    let (_, after) = rest.split_once("): efc=")?;
    match after.as_bytes().first()? {
        b'0' => Some(false),
        b'1' => Some(true),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn efc_is_cleared_at_start_and_after_each_carrier_return() {
        let mut w = Watch::default();
        assert!(w.tick(true), "the keeper just started");
        assert!(!w.tick(true));
        // `rcinit` takes eth0 down; the driver sets EFC again when it opens.
        assert!(!w.tick(false));
        assert!(!w.tick(false));
        assert!(w.tick(true));
        assert!(!w.tick(true));
        // A keeper that starts while the port is down clears it then, and
        // again once the port is open.
        let mut down = Watch::default();
        assert!(down.tick(false));
        assert!(!down.tick(false));
        assert!(down.tick(true));
    }

    #[test]
    fn the_kernel_report_gives_efc() {
        assert_eq!(efc("  dma ctrl(00203306): efc=1 rfa=1(fill=2KB) rfd=2(fill=1KB)"), Some(true));
        assert_eq!(
            efc("4,812,15196123,-;  dma ctrl(00203206): efc=0 rfa=1(fill=2KB) rfd=2(fill=1KB)"),
            Some(false)
        );
        assert_eq!(efc("  mac fc(ffff0006): rx=1 tx=1 pause-time=ffff"), None);
        assert_eq!(efc("set fc: en=0 rfa=0(fill=3KB) rfd=3(fill=0KB)"), None);
        assert_eq!(efc("  dma ctrl(00203206): efc=x"), None);
        assert_eq!(efc(""), None);
    }

    #[test]
    fn only_an_explicit_stock_setting_keeps_vendor_flow_control() {
        assert!(stock_requested("flow_control=stock\n"));
        assert!(stock_requested("# bench A/B\nflow_control = stock\n"));
        assert!(!stock_requested(""));
        assert!(!stock_requested("flow_control=off\n"));
        assert!(!stock_requested("flow_control=stocky\n"));
        assert!(!stock_requested("pause=stock\n"));
    }

    #[test]
    fn the_command_is_the_vendor_disable() {
        assert_eq!(PROGRAM, "kern");
        assert_eq!(DISABLE.join(" "), "eth -fc");
    }
}

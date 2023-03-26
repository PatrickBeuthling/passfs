mod fs;
mod fuse;

use std::sync::{atomic::AtomicBool, atomic::Ordering::Relaxed, Arc};

use fuse::Daemon;
use log::info;
use nix::unistd::{getuid, seteuid};

use signal_hook::consts::signal::*;

fn main() -> anyhow::Result<()> {
    env_logger::init();

    let term = Arc::new(AtomicBool::new(false));
    signal_hook::flag::register(SIGINT, Arc::clone(&term))?;
    signal_hook::flag::register(SIGTERM, Arc::clone(&term))?;
    signal_hook::flag::register(SIGQUIT, Arc::clone(&term))?;

    let mut d = Daemon::new(1)?;
    d.mount()?;

    info!("dropping privileges");
    seteuid(getuid())?;

    while !term.load(Relaxed) {
        std::thread::yield_now();
    }
    info!("terminating");

    Ok(())
}

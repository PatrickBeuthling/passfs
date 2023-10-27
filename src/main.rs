mod fs;
mod fuse;

use std::sync::{atomic::AtomicBool, atomic::Ordering::Relaxed, Arc};

use anyhow::Context;
use fuse::Daemon;
use log::info;
use uzers::switch::switch_user_group;
use uzers::{get_current_uid, get_user_by_uid};

use signal_hook::consts::signal::*;

fn main() -> anyhow::Result<()> {
    env_logger::init();

    let term = Arc::new(AtomicBool::new(false));
    signal_hook::flag::register(SIGINT, Arc::clone(&term))?;
    signal_hook::flag::register(SIGTERM, Arc::clone(&term))?;
    signal_hook::flag::register(SIGQUIT, Arc::clone(&term))?;

    let user = get_user_by_uid(get_current_uid()).context("User not found")?;

    let mut d = Daemon::new(&user, 1)?;
    d.mount()?;

    info!("dropping privileges");
    let switch_guard = switch_user_group(user.uid(), user.primary_group_id())?;

    while !term.load(Relaxed) {
        std::thread::yield_now();
    }
    info!("terminating");

    drop(switch_guard);
    Ok(())
}

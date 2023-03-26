use crate::fs::{Pass, PassFs};

use log::{debug, error, info, warn};
use std::path::PathBuf;
use std::process::Command;
use std::sync::Arc;
use std::thread;

use fuse_backend_rs::api::server::Server as FuseServer;
use fuse_backend_rs::transport::{FuseChannel, FuseSession};
use nix::unistd::{getgid, getuid, User};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Could not resolve User")]
    GetUser,
    #[error("Could convert home dir")]
    Path,
    #[error(transparent)]
    Nix(#[from] nix::Error),
    #[error(transparent)]
    Fuse(#[from] fuse_backend_rs::transport::Error),
    #[error(transparent)]
    IO(#[from] std::io::Error),
}

type Result<T> = core::result::Result<T, Error>;

/// A fusedev daemon example
#[allow(dead_code)]
pub struct Daemon {
    mountpoint: PathBuf,
    server: Arc<FuseServer<Arc<PassFs>>>,
    thread_cnt: u32,
    session: Option<FuseSession>,
}

#[allow(dead_code)]
impl Daemon {
    /// Creates a fusedev daemon instance
    pub fn new(thread_cnt: u32) -> Result<Self> {
        info!("setting up daemon");
        let mut home = User::from_uid(getuid())?.ok_or(Error::GetUser)?.dir;
        let fs = PassFs::new(Arc::new(Pass::new(
            getuid().as_raw(),
            getgid().as_raw(),
            home.to_str().ok_or(Error::Path)?.to_owned(),
        )));

        home.push("pass");
        Ok(Daemon {
            mountpoint: home,
            server: Arc::new(FuseServer::new(Arc::new(fs))), //Arc::new(Server::new(Arc::new(vfs))),
            thread_cnt,
            session: None,
        })
    }

    /// Mounts a fusedev daemon to the mountpoint, then start service threads to handle
    /// FUSE requests.
    pub fn mount(&mut self) -> Result<()> {
        info!("mounting filesystem");
        let mut se = FuseSession::new(self.mountpoint.as_path(), "passfs", "", false)?;
        se.mount()?;

        info!("spawning fuse threads");
        for _ in 0..self.thread_cnt {
            let mut server = Server {
                server: self.server.clone(),
                ch: se.new_channel()?,
            };
            let _thread = thread::Builder::new()
                .name("fuse_server".to_string())
                .spawn(move || {
                    info!("new fuse thread");
                    let _ = server.svc_loop();
                    warn!("fuse service thread exits");
                })?;
        }
        self.session = Some(se);
        Ok(())
    }

    /// Umounts and destroys a fusedev daemon
    pub fn umount(&mut self) -> Result<()> {
        if let Some(se) = self.session.take() {
            // se.umount().unwrap(); // we may not have the permissions to umount
            warn!("unmounting filesystem");
            Command::new("umount")
                .arg(self.mountpoint.as_os_str())
                .output()?;
            debug!("waking fuse session");
            se.wake()?;
        }
        Ok(())
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.umount();
    }
}

struct Server {
    server: Arc<FuseServer<Arc<PassFs>>>,
    ch: FuseChannel,
}

impl Server {
    fn svc_loop(&mut self) -> std::io::Result<()> {
        loop {
            if let Some((reader, writer)) = self
                .ch
                .get_request()
                .map_err(|_| std::io::Error::from_raw_os_error(libc::EINVAL))?
            {
                if let Err(e) = self
                    .server
                    .handle_message(reader, writer.into(), None, None)
                {
                    match e {
                        fuse_backend_rs::Error::EncodeMessage(_ebadf) => {
                            warn!("EncodeMessage");
                            break;
                        }
                        _ => {
                            error!("Handling fuse message failed");
                            continue;
                        }
                    }
                }
            } else {
                info!("fuse server exits");
                break;
            }
        }
        Ok(())
    }
}

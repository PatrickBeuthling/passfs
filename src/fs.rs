use arc_swap::ArcSwap;
use log::debug;
use std::cmp::min;
use std::collections::HashMap;
use std::ffi::CStr;
use std::io::{self, Error, Result, Write};
use std::iter::Peekable;
use std::ops::Deref;
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Child, Command, Output, Stdio};
use std::str::Lines;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

use fuse_backend_rs::abi::fuse_abi::{stat64, Attr, CreateIn};
use fuse_backend_rs::api::filesystem::*;

type Inode = u64;
type AtomicInode = AtomicU64;
type Handle = u64;

const ROOT_INODE: Inode = 1;
const FIRST_INODE: Inode = 2;
const DEFAULT_ATTR_TIMEOUT: u64 = 1 << 32;
const DEFAULT_ENTRY_TIMEOUT: u64 = DEFAULT_ATTR_TIMEOUT;
const FILE_MODE: u32 = libc::S_IFREG | libc::S_IRUSR | libc::S_IWUSR;
const DIR_MODE: u32 = libc::S_IFDIR | libc::S_IRWXU;

fn cleanup_name(input: &str) -> Option<String> {
    Some(
        input
            .split_once(' ')?
            .1
            .replace("\u{1b}[01;34m", "")
            .replace("\u{1b}[0m", ""),
    )
}

#[derive(Debug)]
pub struct Pass {
    uid: u32,
    gid: u32,
    home: String,
}

impl Pass {
    pub fn new(uid: u32, gid: u32, home: String) -> Self {
        Pass { uid, gid, home }
    }

    fn base_command(&self, args: &[&str]) -> io::Result<Child> {
        Command::new("pass")
            .uid(self.uid)
            .gid(self.gid)
            .env("HOME", self.home.clone())
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
    }

    fn output(&self, args: &[&str]) -> io::Result<Output> {
        self.base_command(args)?.wait_with_output()
    }

    fn list_passwords(&self) -> String {
        String::from_utf8(self.output(&[]).unwrap().stdout).unwrap()
    }

    fn get_password(&self, abs_path: &str) -> io::Result<Vec<u8>> {
        Ok(self.output(&[abs_path])?.stdout)
    }

    fn save_password(&self, abs_path: &str, password: &[u8]) -> io::Result<()> {
        self.base_command(&["insert", "-m", "-f", abs_path])?
            .stdin
            .as_mut()
            .ok_or_else(|| Error::from_raw_os_error(libc::ENOENT))?
            .write_all(password)
    }

    fn get_size(&self, abs_path: &str) -> u64 {
        self.get_password(abs_path).map_or(0, |v| v.len() as u64)
    }
}

#[derive(Debug)]
struct PassInode {
    ino: Inode,
    parent: Inode,
    name: String,
    abs_path: String,
    pass: Arc<Pass>,
    children: ArcSwap<Vec<Arc<PassInode>>>,
}

impl PassInode {
    fn new(
        ino: Inode,
        parent: Inode,
        name: String,
        abs_path: String,
        pass: Arc<Pass>,
    ) -> PassInode {
        PassInode {
            ino,
            parent,
            name,
            abs_path,
            pass,
            children: ArcSwap::new(Arc::new(Vec::new())),
        }
    }

    fn insert_child(&self, child: Arc<PassInode>) {
        self.children.rcu(|children| {
            let mut children = children.deref().clone();
            children.push(child.clone());
            children
        });
    }

    fn remove_child(&self, child: Arc<PassInode>) {
        self.children.rcu(|children| {
            let mut children = children.deref().clone();
            if let Some(index) = children.deref().iter().position(|x| x.name == child.name) {
                children.remove(index);
            }
            children
        });
    }

    fn get_child(&self, child_name: &str) -> Option<Arc<PassInode>> {
        for child in self.children.load().iter() {
            if child.name == child_name {
                return Some(child.clone());
            }
        }
        None
    }

    fn to_entry(&self) -> io::Result<Entry> {
        let mut attr = Attr {
            ..Default::default()
        };
        attr.ino = self.ino;
        if self.children.load().len() == 0 {
            attr.mode = FILE_MODE;
            attr.size = self.pass.get_size(&self.abs_path);
        } else {
            attr.mode = DIR_MODE;
            attr.size = 4096;
        }
        let now = SystemTime::now();
        attr.ctime = now
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        attr.mtime = attr.ctime;
        attr.atime = attr.ctime;
        attr.uid = self.pass.uid;
        attr.gid = self.pass.gid;
        Ok(Entry {
            inode: attr.ino,
            generation: 1,
            attr: attr.into(),
            attr_flags: 0,
            attr_timeout: Duration::from_secs(DEFAULT_ATTR_TIMEOUT),
            entry_timeout: Duration::from_secs(DEFAULT_ENTRY_TIMEOUT),
        })
    }
}

pub struct PassFs {
    next_inode: AtomicInode,
    root_inode: Arc<PassInode>,
    pass: Arc<Pass>,
    inodes: ArcSwap<HashMap<u64, Arc<PassInode>>>,
    last_update: ArcSwap<Instant>,
}

impl PassFs {
    pub fn new(pass: Arc<Pass>) -> Self {
        let root_inode = Arc::new(PassInode::new(
            ROOT_INODE,
            ROOT_INODE,
            String::from("/"),
            String::from("/"),
            pass.clone(),
        ));
        let fs = PassFs {
            next_inode: AtomicInode::new(FIRST_INODE),
            root_inode,
            pass,
            inodes: ArcSwap::new(Arc::new(HashMap::new())),
            last_update: ArcSwap::new(Arc::new(Instant::now())),
        };

        fs.update_inodes();
        fs
    }

    fn check_update(&self) {
        if self.last_update.load().elapsed() > Duration::from_secs(5) {
            self.update_inodes();
        }
    }

    fn update_inodes(&self) {
        // there can be races between last_update checks and setting the time
        // which can result in multiple `pass` executions for now i just want to
        // update the state more than once(on init) but ideally not every readdir or lookup call
        self.last_update.store(Arc::new(Instant::now()));
        let output = self.pass.list_passwords();
        let mut lines = output.lines().peekable();
        self.inodes.store(Arc::new(HashMap::new()));
        self.next_inode.store(FIRST_INODE, Ordering::Relaxed);
        self.insert_inode(self.root_inode.clone());
        // Skip the first line as it is not a password
        lines.next();
        debug!("converting `pass` output to inodes");
        self.mk_list(self.root_inode.clone(), &mut lines, None)
    }

    fn mk_list(&self, parent: Arc<PassInode>, it: &mut Peekable<Lines>, level: Option<usize>) {
        loop {
            if let Some(t) = it.peek() {
                let index = t.find('├').or_else(|| t.find('└')).expect(
                    "Neither '├' nor '└' in pass output line found, this should never happen",
                );

                if level.is_none() || index > level.unwrap() {
                    let t = it.next().unwrap();
                    if let Some(name) = cleanup_name(&t[index..]) {
                        let child = match parent.get_child(&name) {
                            Some(child) => child,
                            None => self.create_inode(&name, &parent),
                        };
                        self.mk_list(child, it, Some(index));
                    }
                } else {
                    // Line is not a child of us, returning up for our parent to handle
                    return;
                }
            } else {
                // Iterator is empty no output left to handle
                return;
            }
        }
    }

    fn new_inode(&self, parent: Inode, name: &str, abs_path: &str) -> Arc<PassInode> {
        let ino = self.next_inode.fetch_add(1, Ordering::Relaxed);

        Arc::new(PassInode::new(
            ino,
            parent,
            name.to_owned(),
            abs_path.to_owned(),
            self.pass.clone(),
        ))
    }

    fn insert_inode(&self, inode: Arc<PassInode>) {
        self.inodes.rcu(|hashmap| {
            let mut hashmap = hashmap.deref().clone();
            hashmap.insert(inode.ino, inode.clone());
            hashmap
        });
    }

    fn create_inode(&self, name: &str, parent: &Arc<PassInode>) -> Arc<PassInode> {
        let inode = self.new_inode(
            parent.ino,
            name,
            Path::new(&parent.abs_path).join(name).to_str().unwrap(),
        );

        self.insert_inode(inode.clone());
        parent.insert_child(inode.clone());

        inode
    }

    fn remove_inode(&self, inode: &Arc<PassInode>) {
        self.inodes.rcu(|hashmap| {
            let mut hashmap = hashmap.deref().clone();
            hashmap.remove(&inode.ino);
            hashmap
        });
    }

    fn get_inode(&self, ino: Inode) -> Result<Arc<PassInode>> {
        let inodes = self.inodes.load();
        inodes
            .get(&ino)
            .ok_or_else(|| Error::from_raw_os_error(libc::ENOENT))
            .map(|inode| inode.clone())
    }

    #[allow(dead_code)]
    pub fn evict_inode(&self, ino: Inode) {
        let inodes = self.inodes.load();

        let inode = inodes.get(&ino).unwrap();
        // ino == inode.parent means it is the root inode.
        // Do not evict it.
        if ino == inode.parent {
            return;
        }

        if let Some(parent) = inodes.get(&inode.parent) {
            parent.remove_child(inode.clone());

            self.remove_inode(inode);
        }
    }

    fn get_entry(&self, ino: Inode) -> Result<Entry> {
        self.inodes
            .load()
            .get(&ino)
            .map(|inode| inode.to_entry())
            .ok_or_else(|| Error::from_raw_os_error(libc::ENOENT))?
    }

    fn do_readdir(
        &self,
        parent: u64,
        size: u32,
        offset: u64,
        add_entry: &mut dyn FnMut(DirEntry) -> Result<usize>,
    ) -> Result<()> {
        if size == 0 {
            return Ok(());
        }
        let inodes = self.inodes.load();
        let inode = inodes
            .get(&parent)
            .ok_or_else(|| Error::from_raw_os_error(libc::ENOENT))?;
        let mut offset = offset;
        let children = inode.children.load();

        if offset == 0 {
            match add_entry(DirEntry {
                ino: inode.ino,
                offset: 0,
                type_: libc::DT_DIR as u32,
                name: ".".as_bytes(),
            }) {
                Ok(0) => return Ok(()),
                Ok(_) => offset += 1,
                Err(r) => return Err(r),
            }
        }

        if offset == 1 {
            match add_entry(DirEntry {
                ino: inode.parent,
                offset: 1,
                type_: libc::DT_DIR as u32,
                name: "..".as_bytes(),
            }) {
                Ok(0) => return Ok(()),
                Ok(_) => offset += 1,
                Err(r) => return Err(r),
            }
        }

        let mut next = offset + 1;

        if (offset - 2) >= children.len() as u64 {
            return Ok(());
        }

        for child in children[(offset - 2) as usize..].iter() {
            let type_ = if child.children.load().len() == 0 {
                libc::DT_REG
            } else {
                libc::DT_DIR
            };

            match add_entry(DirEntry {
                ino: child.ino,
                offset: next,
                type_: type_ as u32,
                name: child.name.clone().as_bytes(),
            }) {
                Ok(0) => break,
                Ok(_) => next += 1,
                Err(r) => return Err(r),
            }
        }

        Ok(())
    }
}

impl FileSystem for PassFs {
    type Inode = Inode;
    type Handle = Handle;

    fn lookup(&self, _: &Context, parent: Inode, name: &CStr) -> Result<Entry> {
        debug!("lookup!{parent}!{:?}", name);
        self.check_update();
        let inodes = self.inodes.load();
        let pinode = inodes
            .get(&parent)
            .ok_or_else(|| Error::from_raw_os_error(libc::ENOENT))?;
        let child_name = name
            .to_str()
            .map_err(|_| Error::from_raw_os_error(libc::EINVAL))?;

        if child_name == "." {
            return pinode.to_entry();
        }

        if child_name == ".." {
            return inodes
                .get(&pinode.parent)
                .ok_or_else(|| Error::from_raw_os_error(libc::ENOENT))?
                .to_entry();
        }

        for child in pinode.children.load().iter() {
            if child.name == child_name {
                return child.to_entry();
            }
        }

        Err(Error::from_raw_os_error(libc::ENOENT))
    }

    fn getattr(&self, _: &Context, inode: Inode, _: Option<u64>) -> Result<(stat64, Duration)> {
        debug!("getattr!{inode}");
        let entry = self.get_entry(inode)?;

        Ok((entry.attr, entry.attr_timeout))
    }

    fn readdir(
        &self,
        _ctx: &Context,
        inode: u64,
        _: u64,
        size: u32,
        offset: u64,
        add_entry: &mut dyn FnMut(DirEntry) -> Result<usize>,
    ) -> Result<()> {
        debug!("readdir!{inode}");
        self.check_update();
        self.do_readdir(inode, size, offset, add_entry)
    }

    fn readdirplus(
        &self,
        _ctx: &Context,
        inode: u64,
        _handle: u64,
        size: u32,
        offset: u64,
        add_entry: &mut dyn FnMut(DirEntry, Entry) -> Result<usize>,
    ) -> Result<()> {
        debug!("readdirplus!{inode}");
        self.check_update();
        self.do_readdir(inode, size, offset, &mut |dir_entry| {
            let entry = self.get_entry(dir_entry.ino)?;
            add_entry(dir_entry, entry)
        })
    }

    fn access(&self, _ctx: &Context, inode: u64, _mask: u32) -> Result<()> {
        debug!("access!{inode}");
        Ok(())
    }

    fn create(
        &self,
        _ctx: &Context,
        parent: Self::Inode,
        name: &CStr,
        _args: CreateIn,
    ) -> io::Result<(Entry, Option<Self::Handle>, OpenOptions)> {
        debug!("create!{parent}");
        Ok((
            self.create_inode(
                name.to_str()
                    .map_err(|_| io::Error::from_raw_os_error(libc::ENOSYS))?,
                &self.get_inode(parent)?,
            )
            .to_entry()?,
            None,
            OpenOptions::empty(),
        ))
    }

    fn read(
        &self,
        _ctx: &Context,
        inode: Self::Inode,
        _handle: Self::Handle,
        w: &mut dyn ZeroCopyWriter,
        size: u32,
        offset: u64,
        _lock_owner: Option<u64>,
        _flags: u32,
    ) -> io::Result<usize> {
        debug!("read!{inode}!{size}!{offset}");
        let inode = self.get_inode(inode)?;
        let data = self.pass.get_password(&inode.abs_path)?;
        let end = min(offset + size as u64, data.len() as u64) as usize;
        let start = min(min(offset, data.len() as u64), end as u64) as usize;
        w.write_all(&data[start..end])?;
        Ok(end - start)
    }

    fn write(
        &self,
        _ctx: &Context,
        inode: Self::Inode,
        _handle: Self::Handle,
        r: &mut dyn ZeroCopyReader,
        _size: u32,
        offset: u64,
        _lock_owner: Option<u64>,
        _delayed_write: bool,
        _flags: u32,
        _fuse_flags: u32,
    ) -> io::Result<usize> {
        debug!("write!{inode}");
        let inode = self.get_inode(inode)?;
        let data_in = self
            .pass
            .get_password(&inode.abs_path)
            .unwrap_or_else(|_| Vec::new());
        let mut buf: Vec<u8> = Vec::new();
        r.read_to_end(&mut buf)?;

        let mut data_out: Vec<u8> = Vec::new();
        if offset > 0 {
            data_out.extend(data_in[..offset as usize].iter());
        }
        data_out.extend(buf.iter());
        if offset as usize + buf.len() < data_in.len() {
            data_out.extend(data_in[offset as usize + buf.len()..].iter());
        }
        self.pass.save_password(&inode.abs_path, &data_out)?;
        Ok(buf.len())
    }
}

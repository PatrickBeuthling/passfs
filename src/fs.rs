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
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
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

fn c_to_str(c_str: &CStr) -> Result<&str> {
    c_str
        .to_str()
        .map_err(|_| Error::from_raw_os_error(libc::EINVAL))
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
        let mut child = self.base_command(&["insert", "-m", "-f", abs_path])?;
        let mut stdin = child
            .stdin
            .take()
            .ok_or_else(|| Error::from_raw_os_error(libc::ENOENT))?;
        stdin.write_all(password)?;
        drop(stdin);
        child.wait()?;
        Ok(())
    }

    fn get_size(&self, abs_path: &str) -> u64 {
        self.get_password(abs_path).map_or(0, |v| v.len() as u64)
    }

    fn remove_password(&self, abs_path: &str) -> io::Result<()> {
        self.base_command(&["rm", "-r", "-f", abs_path])?;
        Ok(())
    }
}

#[derive(Debug)]
struct PassInode {
    ino: Inode,
    parent: Inode,
    name: String,
    abs_path: String,
    pass: Arc<Pass>,
    visited: AtomicBool,
    dir: AtomicBool,
    children: ArcSwap<Vec<Arc<PassInode>>>,
}

impl PassInode {
    fn new(
        ino: Inode,
        parent: Inode,
        name: String,
        abs_path: String,
        pass: Arc<Pass>,
        dir: bool,
    ) -> PassInode {
        PassInode {
            ino,
            parent,
            name,
            abs_path,
            pass,
            visited: AtomicBool::new(false),
            dir: AtomicBool::new(dir),
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
        if self.dir.load(Ordering::Relaxed) {
            attr.mode = DIR_MODE;
            attr.size = 4096;
        } else {
            attr.mode = FILE_MODE;
            attr.size = self.pass.get_size(&self.abs_path);
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
            true,
        ));
        let fs = PassFs {
            next_inode: AtomicInode::new(FIRST_INODE),
            root_inode: root_inode.clone(),
            pass,
            inodes: ArcSwap::new(Arc::new(HashMap::new())),
            last_update: ArcSwap::new(Arc::new(Instant::now())),
        };
        fs.insert_inode(root_inode);
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

        lines.next();
        debug!("converting `pass` output to inodes");
        self.mk_list(self.root_inode.clone(), &mut lines, None);
        let mut next_map = HashMap::new();
        for value in self.inodes.load().values() {
            if value.visited.load(Ordering::Relaxed) {
                value.visited.store(false, Ordering::Relaxed);
                next_map.insert(value.ino, value.clone());
            }
        }
        self.inodes.store(Arc::new(next_map));
    }

    fn mk_list(&self, parent: Arc<PassInode>, it: &mut Peekable<Lines>, level: Option<usize>) {
        parent.visited.store(true, Ordering::Relaxed);
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
                            None => self.create_inode(&name, &parent, false),
                        };

                        parent.dir.store(true, Ordering::Relaxed);
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

    fn new_inode(&self, parent: Inode, name: &str, abs_path: &str, dir: bool) -> Arc<PassInode> {
        let ino = self.next_inode.fetch_add(1, Ordering::Relaxed);

        Arc::new(PassInode::new(
            ino,
            parent,
            name.to_owned(),
            abs_path.to_owned(),
            self.pass.clone(),
            dir,
        ))
    }

    fn insert_inode(&self, inode: Arc<PassInode>) {
        self.inodes.rcu(|hashmap| {
            let mut hashmap = hashmap.deref().clone();
            hashmap.insert(inode.ino, inode.clone());
            hashmap
        });
    }

    fn create_inode(&self, name: &str, parent: &Arc<PassInode>, dir: bool) -> Arc<PassInode> {
        let inode = self.new_inode(
            parent.ino,
            name,
            Path::new(&parent.abs_path).join(name).to_str().unwrap(),
            dir,
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

    pub fn evict_inode(&self, ino: Inode) -> Result<()> {
        let inodes = self.inodes.load();

        let inode = self.get_inode(ino)?;
        // ino == inode.parent means it is the root inode.
        // Do not evict it.
        if ino == inode.parent {
            return Ok(());
        }

        if let Some(parent) = inodes.get(&inode.parent) {
            parent.remove_child(inode.clone());

            self.remove_inode(&inode);
        }
        Ok(())
    }

    fn get_entry(&self, ino: Inode) -> Result<Entry> {
        self.get_inode(ino)?.to_entry()
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
        let parent = self.get_inode(parent)?;
        let mut offset = offset;
        let children = parent.children.load();

        if offset == 0 {
            match add_entry(DirEntry {
                ino: parent.ino,
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
                ino: parent.parent,
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
        let parent = self.get_inode(parent)?;
        let name = c_to_str(name)?;

        if name == "." {
            return parent.to_entry();
        }

        if name == ".." {
            return self.get_entry(parent.parent);
        }

        for child in parent.children.load().iter() {
            if child.name == name {
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

    fn setattr(
        &self,
        _ctx: &Context,
        inode: Self::Inode,
        attr: stat64,
        _handle: Option<Self::Handle>,
        valid: SetattrValid,
    ) -> io::Result<(stat64, Duration)> {
        debug!("setattr!{inode}:{valid:?}");
        // let entry = self.get_entry(inode)?;
        // debug!("setattr2!{inode}:{:#?}:{attr:#?}:{valid:?}", entry.attr);
        match valid {
            SetattrValid::SIZE => {
                let inode = self.get_inode(inode)?;
                let mut data = self.pass.get_password(&inode.abs_path)?;
                let attr: Attr = attr.into();
                data.resize(attr.size as usize, 0);
                self.pass.save_password(&inode.abs_path, &data)?;
                let entry = self.get_entry(inode.ino)?;
                Ok((entry.attr, entry.attr_timeout))
            }
            _ => Err(io::Error::from_raw_os_error(libc::ENOSYS)),
        }
    }

    fn readlink(&self, _ctx: &Context, inode: Self::Inode) -> io::Result<Vec<u8>> {
        debug!("readlink!{inode}");
        Err(io::Error::from_raw_os_error(libc::ENOSYS))
    }

    fn symlink(
        &self,
        _ctx: &Context,
        link_name: &CStr,
        _parent: Self::Inode,
        name: &CStr,
    ) -> io::Result<Entry> {
        debug!("symlink!{name:?}:{link_name:?}");
        Err(io::Error::from_raw_os_error(libc::ENOSYS))
    }

    fn mknod(
        &self,
        _ctx: &Context,
        inode: Self::Inode,
        _name: &CStr,
        _mode: u32,
        _rdev: u32,
        _umask: u32,
    ) -> io::Result<Entry> {
        debug!("mknod!{inode}");
        Err(io::Error::from_raw_os_error(libc::ENOSYS))
    }

    fn mkdir(
        &self,
        _ctx: &Context,
        parent: Self::Inode,
        name: &CStr,
        _mode: u32,
        _umask: u32,
    ) -> io::Result<Entry> {
        debug!("mkdir!{name:?}");
        let inode = self.create_inode(c_to_str(name)?, &self.get_inode(parent)?, true);
        inode.to_entry()
        //Err(io::Error::from_raw_os_error(libc::ENOSYS))
    }

    fn unlink(&self, _ctx: &Context, parent: Self::Inode, name: &CStr) -> io::Result<()> {
        debug!("unlink!{name:?}");
        let parent = &self.get_inode(parent)?;
        let child = parent
            .get_child(c_to_str(name)?)
            .ok_or(io::Error::from_raw_os_error(libc::ENOSYS))?;
        self.evict_inode(child.ino)?;
        self.pass.remove_password(&child.abs_path)
    }

    fn rmdir(&self, _ctx: &Context, _parent: Self::Inode, name: &CStr) -> io::Result<()> {
        debug!("rmdir!{name:?}");
        Err(io::Error::from_raw_os_error(libc::ENOSYS))
    }

    fn rename(
        &self,
        _ctx: &Context,
        _old_dir: Self::Inode,
        old_name: &CStr,
        _new_dir: Self::Inode,
        new_name: &CStr,
        _flags: u32,
    ) -> io::Result<()> {
        debug!("rename!{old_name:?}:{new_name:?}");
        Err(io::Error::from_raw_os_error(libc::ENOSYS))
    }

    fn link(
        &self,
        _ctx: &Context,
        inode: Self::Inode,
        _new_parent: Self::Inode,
        new_name: &CStr,
    ) -> io::Result<Entry> {
        debug!("rmdir!{inode}:{new_name:?}");
        Err(io::Error::from_raw_os_error(libc::ENOSYS))
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
            self.create_inode(c_to_str(name)?, &self.get_inode(parent)?, false)
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

    fn flush(
        &self,
        _ctx: &Context,
        inode: Self::Inode,
        _handle: Self::Handle,
        _lock_owner: u64,
    ) -> io::Result<()> {
        debug!("flush!{inode}");
        Err(io::Error::from_raw_os_error(libc::ENOSYS))
    }

    fn fsync(
        &self,
        _ctx: &Context,
        inode: Self::Inode,
        _datasync: bool,
        _handle: Self::Handle,
    ) -> io::Result<()> {
        debug!("fsync!{inode}");
        Err(io::Error::from_raw_os_error(libc::ENOSYS))
    }

    fn fallocate(
        &self,
        _ctx: &Context,
        inode: Self::Inode,
        _handle: Self::Handle,
        _mode: u32,
        _offset: u64,
        _length: u64,
    ) -> io::Result<()> {
        debug!("fallocate!{inode}");
        Ok(())
    }

    fn release(
        &self,
        _ctx: &Context,
        inode: Self::Inode,
        _flags: u32,
        _handle: Self::Handle,
        _flush: bool,
        _flock_release: bool,
        _lock_owner: Option<u64>,
    ) -> io::Result<()> {
        debug!("release!{inode}");
        Err(io::Error::from_raw_os_error(libc::ENOSYS))
    }

    fn setxattr(
        &self,
        _ctx: &Context,
        inode: Self::Inode,
        _name: &CStr,
        _value: &[u8],
        _flags: u32,
    ) -> io::Result<()> {
        debug!("setxattr!{inode}");
        Err(io::Error::from_raw_os_error(libc::ENOSYS))
    }

    fn getxattr(
        &self,
        _ctx: &Context,
        inode: Self::Inode,
        _name: &CStr,
        _size: u32,
    ) -> io::Result<GetxattrReply> {
        debug!("getxattr!{inode}");
        Err(io::Error::from_raw_os_error(libc::ENOSYS))
    }

    fn listxattr(
        &self,
        _ctx: &Context,
        inode: Self::Inode,
        _size: u32,
    ) -> io::Result<ListxattrReply> {
        debug!("listxattr!{inode}");
        Err(io::Error::from_raw_os_error(libc::ENOSYS))
    }

    fn removexattr(&self, _ctx: &Context, inode: Self::Inode, _name: &CStr) -> io::Result<()> {
        debug!("removexattr!{inode}");
        Err(io::Error::from_raw_os_error(libc::ENOSYS))
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

    fn fsyncdir(
        &self,
        _ctx: &Context,
        inode: Self::Inode,
        _datasync: bool,
        _handle: Self::Handle,
    ) -> io::Result<()> {
        debug!("fsyncdir!{inode}");
        Err(io::Error::from_raw_os_error(libc::ENOSYS))
    }

    fn releasedir(
        &self,
        _ctx: &Context,
        inode: Self::Inode,
        _flags: u32,
        _handle: Self::Handle,
    ) -> io::Result<()> {
        debug!("releasedir!{inode}");
        Err(io::Error::from_raw_os_error(libc::ENOSYS))
    }

    fn access(&self, _ctx: &Context, inode: u64, _mask: u32) -> Result<()> {
        debug!("access!{inode}");
        Err(io::Error::from_raw_os_error(libc::ENOSYS))
    }

    fn lseek(
        &self,
        _ctx: &Context,
        inode: Self::Inode,
        _handle: Self::Handle,
        _offset: u64,
        _whence: u32,
    ) -> io::Result<u64> {
        debug!("lseek!{inode}");
        Err(io::Error::from_raw_os_error(libc::ENOSYS))
    }

    fn getlk(
        &self,
        _ctx: &Context,
        inode: Self::Inode,
        _handle: Self::Handle,
        _owner: u64,
        _lock: FileLock,
        _flags: u32,
    ) -> io::Result<FileLock> {
        debug!("getlk!{inode}");
        Err(io::Error::from_raw_os_error(libc::ENOSYS))
    }

    fn setlk(
        &self,
        _ctx: &Context,
        inode: Self::Inode,
        _handle: Self::Handle,
        _owner: u64,
        _lock: FileLock,
        _flags: u32,
    ) -> io::Result<()> {
        debug!("setlk!{inode}");
        Err(io::Error::from_raw_os_error(libc::ENOSYS))
    }

    fn setlkw(
        &self,
        _ctx: &Context,
        inode: Self::Inode,
        _handle: Self::Handle,
        _owner: u64,
        _lock: FileLock,
        _flags: u32,
    ) -> io::Result<()> {
        debug!("setlkw!{inode}");
        Err(io::Error::from_raw_os_error(libc::ENOSYS))
    }

    fn ioctl(
        &self,
        _ctx: &Context,
        inode: Self::Inode,
        _handle: Self::Handle,
        _flags: u32,
        _cmd: u32,
        _data: IoctlData,
        _out_size: u32,
    ) -> io::Result<IoctlData> {
        debug!("ioctl!{inode}");
        // Rather than ENOSYS, let's return ENOTTY so simulate that the ioctl call is implemented
        // but no ioctl number is supported.
        Err(io::Error::from_raw_os_error(libc::ENOTTY))
    }

    fn bmap(
        &self,
        _ctx: &Context,
        inode: Self::Inode,
        _block: u64,
        _block_size: u32,
    ) -> io::Result<u64> {
        debug!("bmap!{inode}");
        Err(io::Error::from_raw_os_error(libc::ENOSYS))
    }

    fn poll(
        &self,
        _ctx: &Context,
        inode: Self::Inode,
        _handle: Self::Handle,
        _k_handle: Self::Handle,
        _flags: u32,
        _events: u32,
    ) -> io::Result<u32> {
        debug!("poll!{inode}");
        Err(io::Error::from_raw_os_error(libc::ENOSYS))
    }
}

//! Optional systemd readiness/status messages; no credential or request data.
use std::os::linux::net::SocketAddrExt;
use std::{
    ffi::OsStr,
    io,
    os::unix::{
        ffi::OsStrExt,
        net::{SocketAddr, UnixDatagram},
    },
};

fn send(path: Option<&OsStr>, message: &str) -> io::Result<()> {
    let Some(path) = path else {
        return Ok(());
    };
    let socket = UnixDatagram::unbound()?;
    if let Some(name) = path.as_bytes().strip_prefix(b"@") {
        socket.connect_addr(&SocketAddr::from_abstract_name(name)?)?;
    } else {
        socket.connect(path)?;
    }
    socket.send(message.as_bytes())?;
    Ok(())
}

pub fn notify(message: &str) -> io::Result<()> {
    send(std::env::var_os("NOTIFY_SOCKET").as_deref(), message)
}

pub fn supervised() -> bool {
    std::env::var_os("NOTIFY_SOCKET").is_some()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn readiness_uses_private_notification_socket_and_is_optional() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("notify.sock");
        let listener = UnixDatagram::bind(&path).unwrap();
        listener
            .set_read_timeout(Some(std::time::Duration::from_secs(1)))
            .unwrap();
        send(Some(path.as_os_str()), "READY=1\nSTATUS=Slack connected").unwrap();
        let mut buffer = [0; 128];
        let size = listener.recv(&mut buffer).unwrap();
        assert_eq!(&buffer[..size], b"READY=1\nSTATUS=Slack connected");
        send(None, "READY=1").unwrap();
    }
}

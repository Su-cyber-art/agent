//! The normal service only writes a request. A root-owned executable, launched
//! by systemd.path, asks the hub to authorize it before removing fixed paths.
//! No hub-supplied command, path, executable or shell text is ever executed.

use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const ROOT: &str = "/opt/monitor";
const UNITS: &str = "/etc/systemd/system";
const REQUEST: &str = "uninstall.json";

#[derive(Deserialize, Serialize)]
pub struct Request {
    pub id: String,
}

impl Request {
    fn valid(&self) -> bool {
        self.id.len() == 64 && self.id.bytes().all(|c| c.is_ascii_hexdigit())
    }
}

#[derive(Serialize)]
pub struct Progress {
    pub id: String,
    pub status: &'static str,
    pub message: String,
}

pub fn enabled() -> bool {
    cfg!(target_os = "linux")
        && std::env::var("MONITOR_ALLOW_UNINSTALL").as_deref() == Ok("1")
        && std::env::current_exe().is_ok_and(|path| path == Path::new(ROOT).join("agent/monitor-agent"))
        && Path::new(ROOT).join("agent-uninstall").is_file()
        && Path::new(UNITS).join("monitor-agent-uninstall.path").is_file()
}

pub async fn request(params: serde_json::Value, upgrading: bool) -> Result<Progress> {
    let request: Request = serde_json::from_value(params)?;
    anyhow::ensure!(request.valid(), "invalid uninstall request ID");
    let error = if !enabled() {
        Some("此 agent 尚未启用远程卸载，请先以 root 运行新版安装脚本的 --upgrade")
    } else if upgrading {
        Some("正在升级，暂时不能卸载")
    } else {
        None
    };
    let outcome = match error {
        Some(message) => Err(anyhow::anyhow!(message)),
        None => enqueue(&Path::new(ROOT).join("agent"), &request).await,
    };
    Ok(match outcome {
        Ok(()) => Progress { id: request.id, status: "accepted", message: String::new() },
        Err(e) => {
            Progress { id: request.id, status: "failed", message: format!("无法启动卸载：{e:#}") }
        }
    })
}

async fn enqueue(directory: &Path, request: &Request) -> Result<()> {
    let temporary = directory.join("uninstall.tmp");
    remove_file(&temporary)?;
    let mut file =
        tokio::fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(&temporary).await?;
    file.write_all(&serde_json::to_vec(request)?).await?;
    file.sync_all().await?;
    drop(file);
    tokio::fs::rename(temporary, directory.join(REQUEST)).await?;
    Ok(())
}

struct Paths {
    root: PathBuf,
    units: PathBuf,
    log: PathBuf,
}

impl Paths {
    fn installed() -> Self {
        Self { root: ROOT.into(), units: UNITS.into(), log: "/var/log/monitor-agent.log".into() }
    }
}

pub async fn helper() -> Result<()> {
    anyhow::ensure!(cfg!(target_os = "linux"), "remote uninstall helper requires Linux/systemd");
    anyhow::ensure!(rustix::process::geteuid().is_root(), "uninstall helper must run as root");
    let server = std::env::var("MONITOR_SERVER").context("MONITOR_SERVER is missing")?;
    let node_token = std::env::var("MONITOR_TOKEN").context("MONITOR_TOKEN is missing")?;
    let insecure = std::env::var("MONITOR_INSECURE").as_deref() == Ok("1");
    let ws = crate::ws_url(&server, insecure)?;
    let base = ws
        .strip_suffix("/api/agent/ws")
        .expect("agent WebSocket URL")
        .replacen("wss://", "https://", 1)
        .replacen("ws://", "http://", 1);
    run(&Paths::installed(), &base, &node_token, Path::new("systemctl"), Path::new("userdel")).await
}

async fn run(paths: &Paths, base: &str, node_token: &str, systemctl: &Path, userdel: &Path) -> Result<()> {
    let marker = paths.root.join("agent").join(REQUEST);
    // The request is writable by the service user: bound the read and treat it
    // as data. In particular, never source it or follow paths named inside it.
    let mut bytes = Vec::new();
    tokio::fs::File::open(&marker).await?.take(1024).read_to_end(&mut bytes).await?;
    remove_file(&marker)?;
    let request: Request = serde_json::from_slice(&bytes)?;
    anyhow::ensure!(request.valid(), "invalid uninstall request ID");
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .redirect(reqwest::redirect::Policy::none())
        .build()?;
    let url = format!("{base}/api/agent/removal");
    // An arbitrary marker, an old request or an expired request cannot authorize
    // privileged cleanup: this must succeed before stopping anything.
    report(&client, &url, &request.id, node_token, "stopping", "").await?;
    let result = cleanup(paths, systemctl, userdel, &client, &url, &request.id, node_token).await;
    match result {
        Ok(()) => report(&client, &url, &request.id, node_token, "succeeded", "").await,
        Err(e) => {
            if let Err(report_error) =
                report(&client, &url, &request.id, node_token, "failed", &format!("卸载失败：{e:#}")).await
            {
                eprintln!("reporting uninstall failure: {report_error:#}");
            }
            Err(e)
        }
    }
}

async fn report(
    client: &reqwest::Client,
    url: &str,
    id: &str,
    node_token: &str,
    status: &str,
    message: &str,
) -> Result<()> {
    // The final reply may be lost after the hub commits the deletion. Callbacks
    // are idempotent and use the scoped request credential rather than the now
    // revoked node token. Retry only transport errors and server failures.
    for attempt in 0..3 {
        let response = client
            .post(url)
            .bearer_auth(id)
            .header("X-Node-Token", node_token)
            .json(&serde_json::json!({"status": status, "message": message}))
            .send()
            .await;
        match response {
            Ok(reply) if reply.status().is_success() => return Ok(()),
            Ok(reply) if !reply.status().is_server_error() || attempt == 2 => {
                bail!("uninstall callback returned {}", reply.status())
            }
            Err(e) if attempt == 2 => return Err(e).context("uninstall callback failed"),
            _ => tokio::time::sleep(Duration::from_secs(attempt + 1)).await,
        }
    }
    unreachable!()
}

async fn command(program: &Path, args: &[&str]) -> Result<()> {
    let output = tokio::process::Command::new(program)
        .args(args)
        .kill_on_drop(true)
        .output()
        .await
        .with_context(|| format!("starting {}", program.display()))?;
    anyhow::ensure!(
        output.status.success(),
        "{} {}: {}",
        program.display(),
        args.join(" "),
        String::from_utf8_lossy(&output.stderr).trim()
    );
    Ok(())
}

async fn cleanup(
    paths: &Paths,
    systemctl: &Path,
    userdel: &Path,
    client: &reqwest::Client,
    url: &str,
    id: &str,
    node_token: &str,
) -> Result<()> {
    // Check stopping separately: disabling a unit must not hide a stop failure.
    command(systemctl, &["stop", "monitor-agent.service"]).await?;
    command(systemctl, &["disable", "monitor-agent.service"]).await?;
    command(systemctl, &["disable", "--now", "monitor-agent-uninstall.path"]).await?;
    if let Err(e) = report(client, url, id, node_token, "removing", "").await {
        // Authorization already succeeded. A missing intermediate progress
        // response must not leave an intentionally stopped agent half removed.
        eprintln!("reporting uninstall progress: {e:#}");
    }
    for name in ["monitor-agent.service", "monitor-agent-uninstall.path", "monitor-agent-uninstall.service"] {
        remove_file(&paths.units.join(name))?;
    }
    for name in ["monitor-agent", "monitor-agent.old", "agent.env", "agent-uninstall"] {
        remove_file(&paths.root.join(name))?;
    }
    remove_file(&paths.log)?;
    let directory = paths.root.join("agent");
    match std::fs::remove_dir_all(&directory) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e).context("removing agent files"),
    }
    command(systemctl, &["daemon-reload"]).await?;
    command(userdel, &["monitor-agent"]).await?;
    match std::fs::remove_dir(&paths.root) {
        Ok(()) => {}
        Err(e)
            if matches!(e.kind(), std::io::ErrorKind::DirectoryNotEmpty | std::io::ErrorKind::NotFound) => {}
        Err(e) => return Err(e).context("removing empty agent root"),
    }
    Ok(())
}

fn remove_file(path: &Path) -> Result<()> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e).with_context(|| format!("removing {}", path.display())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{symlink, PermissionsExt};
    use std::sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Mutex,
    };
    use tokio::net::TcpListener;

    static NEXT: AtomicU64 = AtomicU64::new(0);
    const ID: &str = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";

    struct Fixture {
        directory: PathBuf,
        paths: Paths,
        ctl: PathBuf,
        userdel: PathBuf,
        server: tokio::task::JoinHandle<()>,
        base: String,
        reports: Arc<Mutex<Vec<String>>>,
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            self.server.abort();
            std::fs::remove_dir_all(&self.directory).unwrap();
        }
    }

    impl Fixture {
        async fn new(reject_authorization: bool, fail_stop: bool) -> Self {
            let directory = std::env::temp_dir().join(format!(
                "monitor-uninstall-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            let paths = Paths {
                root: directory.join("monitor"),
                units: directory.join("units"),
                log: directory.join("agent.log"),
            };
            std::fs::create_dir_all(paths.root.join("agent")).unwrap();
            std::fs::create_dir_all(&paths.units).unwrap();
            for name in
                ["monitor-agent.service", "monitor-agent-uninstall.path", "monitor-agent-uninstall.service"]
            {
                std::fs::write(paths.units.join(name), "unit").unwrap();
            }
            for name in [
                "agent/monitor-agent",
                "agent/monitor-agent.previous",
                "agent-uninstall",
                "agent.env",
                "monitor-agent.old",
            ] {
                std::fs::write(paths.root.join(name), "agent file").unwrap();
            }
            symlink("agent/monitor-agent", paths.root.join("monitor-agent")).unwrap();
            std::fs::write(&paths.log, "log").unwrap();
            std::fs::write(paths.root.join("monitor-hub"), "keep hub").unwrap();
            std::fs::create_dir(paths.root.join("data")).unwrap();
            std::fs::write(paths.root.join("data/monitor.db"), "keep database").unwrap();
            std::fs::write(directory.join("another-agent"), "keep other probe").unwrap();
            symlink(directory.join("another-agent"), paths.root.join("agent/escape")).unwrap();
            enqueue(&paths.root.join("agent"), &Request { id: ID.into() }).await.unwrap();
            let ctl = directory.join("systemctl");
            let userdel = directory.join("userdel");
            let log = directory.join("commands").to_string_lossy().replace('\'', "'\\''");
            std::fs::write(
                &ctl,
                format!(
                    "#!/bin/sh\nprintf '%s\\n' \"$*\" >>'{log}'\n{}\n",
                    if fail_stop { "exit 1" } else { "exit 0" }
                ),
            )
            .unwrap();
            std::fs::write(&userdel, "#!/bin/sh\n[ \"$*\" = monitor-agent ]\n").unwrap();
            for executable in [&ctl, &userdel] {
                std::fs::set_permissions(executable, std::fs::Permissions::from_mode(0o755)).unwrap();
            }
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let base = format!("http://{}", listener.local_addr().unwrap());
            let reports = Arc::new(Mutex::new(Vec::new()));
            let seen = reports.clone();
            let server = tokio::spawn(async move {
                loop {
                    let (mut stream, _) = listener.accept().await.unwrap();
                    let mut bytes = Vec::new();
                    let (header_end, length) = loop {
                        let mut chunk = [0; 1024];
                        let count = stream.read(&mut chunk).await.unwrap();
                        assert_ne!(count, 0);
                        bytes.extend_from_slice(&chunk[..count]);
                        if let Some(end) = bytes.windows(4).position(|window| window == b"\r\n\r\n") {
                            let headers = String::from_utf8_lossy(&bytes[..end]).to_ascii_lowercase();
                            assert!(headers.starts_with("post /api/agent/removal "));
                            assert!(headers.contains(&format!("authorization: bearer {ID}")));
                            assert!(headers.contains("x-node-token: node-token"));
                            let length: usize = headers
                                .lines()
                                .find_map(|line| line.strip_prefix("content-length: "))
                                .unwrap()
                                .parse()
                                .unwrap();
                            break (end + 4, length);
                        }
                    };
                    while bytes.len() < header_end + length {
                        let mut chunk = [0; 1024];
                        let count = stream.read(&mut chunk).await.unwrap();
                        assert_ne!(count, 0);
                        bytes.extend_from_slice(&chunk[..count]);
                    }
                    let body: serde_json::Value =
                        serde_json::from_slice(&bytes[header_end..header_end + length]).unwrap();
                    seen.lock().unwrap().push(body["status"].as_str().unwrap().into());
                    let status = if reject_authorization { "409 Conflict" } else { "200 OK" };
                    stream
                        .write_all(
                            format!(
                                "HTTP/1.1 {status}\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{{}}"
                            )
                            .as_bytes(),
                        )
                        .await
                        .unwrap();
                }
            });
            Self { directory, paths, ctl, userdel, server, base, reports }
        }
    }

    #[tokio::test]
    async fn cleanup_reports_real_stages_and_leaves_the_hub_database_and_other_probes_intact() {
        let fixture = Fixture::new(false, false).await;
        assert_eq!(
            std::fs::metadata(fixture.paths.root.join("agent/uninstall.json")).unwrap().permissions().mode()
                & 0o777,
            0o600
        );
        run(&fixture.paths, &fixture.base, "node-token", &fixture.ctl, &fixture.userdel).await.unwrap();
        assert_eq!(*fixture.reports.lock().unwrap(), ["stopping", "removing", "succeeded"]);
        assert!(!fixture.paths.root.join("agent").exists());
        assert!(!fixture.paths.root.join("agent.env").exists());
        assert!(!fixture.paths.root.join("agent-uninstall").exists());
        assert!(!fixture.paths.root.join("monitor-agent").is_symlink());
        assert!(!fixture.paths.log.exists());
        assert_eq!(std::fs::read_dir(&fixture.paths.units).unwrap().count(), 0);
        assert_eq!(std::fs::read_to_string(fixture.paths.root.join("monitor-hub")).unwrap(), "keep hub");
        assert_eq!(
            std::fs::read_to_string(fixture.paths.root.join("data/monitor.db")).unwrap(),
            "keep database"
        );
        assert_eq!(
            std::fs::read_to_string(fixture.directory.join("another-agent")).unwrap(),
            "keep other probe"
        );
        assert_eq!(std::fs::read_to_string(fixture.directory.join("commands")).unwrap(), "stop monitor-agent.service\ndisable monitor-agent.service\ndisable --now monitor-agent-uninstall.path\ndaemon-reload\n");
    }

    #[tokio::test]
    async fn an_unapproved_marker_cannot_stop_services_or_remove_any_installed_file() {
        let fixture = Fixture::new(true, false).await;
        assert!(run(&fixture.paths, &fixture.base, "node-token", &fixture.ctl, &fixture.userdel)
            .await
            .is_err());
        assert!(!fixture.directory.join("commands").exists());
        assert!(fixture.paths.root.join("agent/monitor-agent").exists());
        assert!(fixture.paths.root.join("agent.env").exists());
        assert_eq!(*fixture.reports.lock().unwrap(), ["stopping"]);
    }

    #[tokio::test]
    async fn failure_to_stop_the_service_reports_failure_and_keeps_the_program_and_configuration() {
        let fixture = Fixture::new(false, true).await;
        assert!(run(&fixture.paths, &fixture.base, "node-token", &fixture.ctl, &fixture.userdel)
            .await
            .is_err());
        assert_eq!(*fixture.reports.lock().unwrap(), ["stopping", "failed"]);
        assert!(fixture.paths.root.join("agent/monitor-agent").exists());
        assert!(fixture.paths.root.join("agent.env").exists());
    }

    #[tokio::test]
    async fn malformed_requests_cannot_trigger_any_privileged_action() {
        for id in ["", "../monitor-hub", "$(rm -rf /)", "short"] {
            assert!(!Request { id: id.into() }.valid());
        }
        let fixture = Fixture::new(false, false).await;
        std::fs::write(fixture.paths.root.join("agent/uninstall.json"), r#"{"id":"../monitor-hub"}"#)
            .unwrap();
        assert!(run(&fixture.paths, &fixture.base, "node-token", &fixture.ctl, &fixture.userdel)
            .await
            .is_err());
        assert!(!fixture.directory.join("commands").exists());
        assert!(fixture.reports.lock().unwrap().is_empty());
        assert!(fixture.paths.root.join("agent/monitor-agent").exists());
    }
}

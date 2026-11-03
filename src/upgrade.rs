//! Self-updates stay inside the executable's directory, writable only by this
//! agent's service user. No root helper, shell, or hub-supplied command is run.

use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Serialize};
use tokio::io::AsyncWriteExt;
use tokio::task::JoinHandle;
use tokio::time::Instant;

const MAX_BINARY: usize = 16 << 20;
const DEADLINE: Duration = Duration::from_secs(240);
const RECOVERY: Duration = Duration::from_secs(90);

#[derive(Debug, Clone, Deserialize)]
pub struct Request {
    pub id: String,
    pub version: String,
}

impl Request {
    fn valid(&self) -> bool {
        !self.id.is_empty()
            && self.id.len() <= 64
            && self.id.bytes().all(|c| c.is_ascii_alphanumeric())
            && !self.version.is_empty()
            && self.version.len() <= 64
            && self.version.as_bytes()[0].is_ascii_digit()
            && self.version.bytes().all(|c| c.is_ascii_alphanumeric() || matches!(c, b'.' | b'-' | b'+'))
    }
}

#[derive(Clone, Serialize)]
pub struct Progress {
    pub id: String,
    pub status: &'static str,
    pub message: String,
}

/// Survives a service restart before the new process has connected. A second
/// unconfirmed boot restores the old binary instead of repeating a crash loop.
#[derive(Deserialize, Serialize)]
struct Pending {
    id: String,
    version: String,
    boots: u32,
}

fn pending_path(executable: &Path) -> PathBuf {
    sibling(executable, "upgrade.json")
}

fn save_pending(executable: &Path, pending: &Pending) -> Result<()> {
    let temporary = sibling(executable, "upgrade.tmp");
    std::fs::write(&temporary, serde_json::to_vec(pending)?)?;
    std::fs::rename(temporary, pending_path(executable))?;
    Ok(())
}

#[cfg(unix)]
fn launch(executable: &Path) -> Result<()> {
    use std::os::unix::process::CommandExt;
    Err(std::process::Command::new(executable).args(std::env::args_os().skip(1)).exec())
        .context("starting agent")
}

#[cfg(windows)]
fn launch(executable: &Path) -> Result<()> {
    if std::env::args().any(|arg| arg == "--service") {
        // SCM's configured recovery action starts the new image in the service.
        std::process::exit(1);
    }
    std::process::Command::new(executable)
        .args(std::env::args_os().skip(1))
        .spawn()
        .context("starting agent")?;
    std::process::exit(0);
}

fn rollback(executable: &Path) -> Result<()> {
    #[cfg(unix)]
    std::fs::rename(sibling(executable, "previous"), executable).context("restoring previous agent")?;
    #[cfg(windows)]
    replace(executable, &sibling(executable, "previous"), &sibling(executable, "failed"))?;
    launch(executable)
}

pub struct Updater {
    pub enabled: bool,
    executable: PathBuf,
    base: String,
    job: Option<Request>,
    task: Option<JoinHandle<Result<PathBuf>>>,
    ready: Option<PathBuf>,
    pub progress: Option<Progress>,
    pub confirmation: Option<String>,
    confirmed: bool,
    started: Instant,
}

impl Updater {
    #[cfg(target_os = "linux")]
    pub fn busy(&self) -> bool {
        self.task.is_some() || self.ready.is_some() || (self.confirmation.is_some() && !self.confirmed)
    }

    pub fn new(enabled: bool, ws_url: &str) -> Result<Self> {
        let base = ws_url.strip_suffix("/api/agent/ws").context("unexpected agent WebSocket URL")?;
        let base = base.replacen("wss://", "https://", 1).replacen("ws://", "http://", 1);
        let executable = std::env::current_exe()?;
        let mut confirmation = None;
        let mut progress = None;
        match std::fs::read(pending_path(&executable)) {
            Ok(bytes) => {
                let mut pending: Pending =
                    serde_json::from_slice(&bytes).context("reading pending agent upgrade")?;
                if pending.version != env!("CARGO_PKG_VERSION") {
                    progress = Some(Progress {
                        id: pending.id,
                        status: "failed",
                        message: "升级未完成，已恢复原版本".into(),
                    });
                    std::fs::remove_file(pending_path(&executable))?;
                } else if pending.boots > 0 {
                    rollback(&executable)?;
                } else {
                    pending.boots += 1;
                    save_pending(&executable, &pending)?;
                    confirmation = Some(pending.id);
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e).context("reading pending agent upgrade"),
        }
        Ok(Self {
            enabled,
            executable,
            base,
            job: None,
            task: None,
            ready: None,
            progress,
            confirmation,
            confirmed: false,
            started: Instant::now(),
        })
    }

    pub fn request(&mut self, request: Request) -> Result<Progress> {
        anyhow::ensure!(request.valid(), "invalid upgrade request");
        let refuse =
            |message: &str| Progress { id: request.id.clone(), status: "failed", message: message.into() };
        if !self.enabled {
            return Ok(refuse("此 agent 未启用远程升级，请用新版安装脚本更新一次"));
        }
        if self.task.is_some() || self.ready.is_some() {
            return Ok(if self.job.as_ref().is_some_and(|job| job.id == request.id) {
                self.progress.clone().expect("active upgrade has progress")
            } else {
                refuse("已有升级正在执行")
            });
        }
        if request.version == env!("CARGO_PKG_VERSION") {
            return Ok(refuse("agent 已运行目标版本"));
        }
        let progress = Progress { id: request.id.clone(), status: "downloading", message: String::new() };
        let base = self.base.clone();
        let executable = self.executable.clone();
        let version = request.version.clone();
        self.task = Some(tokio::spawn(async move { download(&base, &version, &executable).await }));
        self.job = Some(request);
        self.progress = Some(progress.clone());
        Ok(progress)
    }

    /// The handle outlives a WebSocket session, so reconnects do not start a
    /// second download or abandon a file that is ready to install.
    pub async fn finished(&mut self) -> Result<PathBuf> {
        match &mut self.task {
            Some(task) => task.await.context("upgrade task stopped")?,
            None => std::future::pending().await,
        }
    }

    pub fn finish(&mut self, outcome: Result<PathBuf>) -> Progress {
        self.task = None;
        let progress = match outcome {
            Ok(path) => {
                self.ready = Some(path);
                self.report("restarting", String::new())
            }
            Err(e) => self.report("failed", format!("升级失败，保留原版本：{e:#}")),
        };
        self.progress = Some(progress.clone());
        progress
    }

    fn report(&self, status: &'static str, message: String) -> Progress {
        Progress { id: self.job.as_ref().expect("upgrade request").id.clone(), status, message }
    }

    /// Returns only on failure. exec retains the PID, environment and service
    /// sandbox, and works with systemd as well as OpenRC supervision.
    pub fn restart(&mut self) -> Result<()> {
        let Some(staged) = self.ready.take() else { return Ok(()) };
        let backup = sibling(&self.executable, "previous");
        let job = self.job.as_ref().expect("upgrade request");
        save_pending(
            &self.executable,
            &Pending { id: job.id.clone(), version: job.version.clone(), boots: 0 },
        )?;
        if let Err(e) = replace(&self.executable, &staged, &backup) {
            std::fs::remove_file(pending_path(&self.executable))?;
            return Err(e);
        }
        let error = launch(&self.executable).expect_err("launch only returns on failure");
        #[cfg(unix)]
        std::fs::rename(&backup, &self.executable).context("could not restore the previous agent")?;
        #[cfg(windows)]
        replace(&self.executable, &backup, &sibling(&self.executable, "failed"))?;
        std::fs::remove_file(pending_path(&self.executable))?;
        Err(error).context("could not start the new agent; previous binary restored")
    }

    pub fn restart_failed(&mut self, error: anyhow::Error) -> Progress {
        let progress = self.report("failed", format!("升级失败：{error:#}"));
        self.progress = Some(progress.clone());
        progress
    }

    pub fn confirmed(&mut self) {
        if self.confirmation.is_some() && !self.confirmed {
            self.confirmed = true;
            if let Err(e) = std::fs::remove_file(pending_path(&self.executable)) {
                eprintln!("removing pending agent upgrade: {e}");
            }
            if let Err(e) = std::fs::remove_file(sibling(&self.executable, "previous")) {
                eprintln!("removing previous agent: {e}");
            }
        }
    }

    /// If the replacement starts but cannot reach the hub, return to the binary
    /// which reported before the update. Its next hello reports the rollback.
    pub fn recover_if_due(&self) -> Result<()> {
        let Some(_) = &self.confirmation else { return Ok(()) };
        if self.confirmed {
            return Ok(());
        }
        if self.started.elapsed() < RECOVERY {
            return Ok(());
        }
        rollback(&self.executable)
    }
}

fn sibling(executable: &Path, suffix: &str) -> PathBuf {
    let extension = if cfg!(windows) && matches!(suffix, "download" | "previous" | "failed" | "backup") {
        ".exe"
    } else {
        ""
    };
    executable.with_file_name(format!("monitor-agent.{suffix}{extension}"))
}

/// The old pathname always exists until rename atomically publishes the new
/// one. A hard link retains the running inode without copying its bytes.
#[cfg(unix)]
fn replace(executable: &Path, staged: &Path, backup: &Path) -> Result<()> {
    let link = sibling(executable, "backup");
    if link.exists() {
        std::fs::remove_file(&link)?;
    }
    std::fs::hard_link(executable, &link).context("keeping previous agent")?;
    std::fs::rename(&link, backup)?;
    std::fs::rename(staged, executable).context("publishing agent update")
}

// Windows permits renaming the running image, but not overwriting it.
// Restore the original pathname if publishing the staged image fails.
#[cfg(windows)]
fn replace(executable: &Path, staged: &Path, backup: &Path) -> Result<()> {
    if backup.exists() {
        std::fs::remove_file(backup)?;
    }
    std::fs::rename(executable, backup).context("keeping previous agent")?;
    if let Err(error) = std::fs::rename(staged, executable) {
        std::fs::rename(backup, executable).context("restoring agent after failed publication")?;
        return Err(error).context("publishing agent update");
    }
    Ok(())
}

async fn download(base: &str, version: &str, executable: &Path) -> Result<PathBuf> {
    let staged = sibling(executable, "download");
    let operation = async {
        let client = reqwest::Client::builder().redirect(reqwest::redirect::Policy::none()).build()?;
        let url = format!("{base}/agent/{}", std::env::consts::ARCH);
        let mut response = None;
        let mut query = vec![("version", version)];
        if !cfg!(target_os = "linux") {
            query.push(("os", std::env::consts::OS));
        }
        // The relay has four slots. A batch can legitimately fill them; retry
        // its explicit 503 and connection failures within the overall budget.
        for attempt in 0..3 {
            let fetched = client.get(&url).query(&query).send().await;
            match fetched {
                Ok(res) if res.status() != reqwest::StatusCode::SERVICE_UNAVAILABLE || attempt == 2 => {
                    response = Some(res);
                    break;
                }
                Err(e) if attempt == 2 => return Err(e.into()),
                _ => tokio::time::sleep(Duration::from_secs(5)).await,
            }
        }
        let mut response = response.context("agent relay did not answer")?;
        anyhow::ensure!(response.status().is_success(), "hub download returned {}", response.status());
        anyhow::ensure!(
            response.content_length().unwrap_or(0) <= MAX_BINARY as u64,
            "agent binary exceeds 16 MiB"
        );
        let mut file = tokio::fs::File::create(&staged)
            .await
            .context("agent directory is not writable; rerun the new installer")?;
        let mut size = 0;
        while let Some(chunk) = response.chunk().await? {
            size += chunk.len();
            anyhow::ensure!(size <= MAX_BINARY, "agent binary exceeds 16 MiB");
            file.write_all(&chunk).await?;
        }
        file.sync_all().await?;
        drop(file);
        validate(&staged, version).await?;
        Ok(staged.clone())
    };
    let result = tokio::time::timeout(DEADLINE, operation)
        .await
        .unwrap_or_else(|_| Err(anyhow!("agent download timed out")));
    if result.is_err() {
        match tokio::fs::remove_file(&staged).await {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => eprintln!("removing incomplete agent download: {e}"),
        }
    }
    result
}

async fn validate(path: &Path, version: &str) -> Result<()> {
    let binary = tokio::fs::read(path).await?;
    anyhow::ensure!(
        crate::platform::built_for(&binary, std::env::consts::OS, std::env::consts::ARCH),
        "download is not an agent binary for this platform"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        tokio::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).await?;
    }
    let output = tokio::time::timeout(
        Duration::from_secs(5),
        tokio::process::Command::new(path).arg("--version").kill_on_drop(true).output(),
    )
    .await
    .context("new agent version check timed out")??;
    anyhow::ensure!(
        output.status.success()
            && String::from_utf8_lossy(&output.stdout).trim() == format!("monitor-agent {version}"),
        "downloaded agent does not report the requested version {version}"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[cfg(windows)]
    #[test]
    fn a_running_windows_image_can_be_replaced() {
        if std::env::var_os("MONITOR_TEST_REPLACE").is_some() {
            let executable = std::env::current_exe().unwrap();
            replace(&executable, &sibling(&executable, "download"), &sibling(&executable, "previous"))
                .unwrap();
            return;
        }
        let scratch = Scratch::new();
        let executable = scratch.0.join("monitor-agent.exe");
        std::fs::copy(std::env::current_exe().unwrap(), &executable).unwrap();
        std::fs::write(sibling(&executable, "download"), b"replacement").unwrap();
        let output = std::process::Command::new(&executable)
            .args(["--exact", "upgrade::tests::a_running_windows_image_can_be_replaced", "--nocapture"])
            .env("MONITOR_TEST_REPLACE", "1")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{} {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(std::fs::read(&executable).unwrap(), b"replacement");
        assert!(sibling(&executable, "previous").metadata().unwrap().len() > 1024);
    }

    struct Scratch(PathBuf);
    impl Scratch {
        fn new() -> Self {
            static NEXT: AtomicUsize = AtomicUsize::new(0);
            let path = std::env::temp_dir().join(format!(
                "monitor-update-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            std::fs::create_dir(&path).unwrap();
            Self(path)
        }
    }
    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn a_replacement_keeps_the_old_inode_until_the_new_process_is_confirmed() {
        use std::io::Read;
        let scratch = Scratch::new();
        let current = scratch.0.join("monitor-agent");
        let staged = sibling(&current, "download");
        let backup = sibling(&current, "previous");
        std::fs::write(&current, b"old").unwrap();
        let mut running = std::fs::File::open(&current).unwrap();
        std::fs::write(&staged, b"new").unwrap();
        replace(&current, &staged, &backup).unwrap();
        assert_eq!(std::fs::read(&current).unwrap(), b"new");
        assert_eq!(std::fs::read(&backup).unwrap(), b"old");
        let mut held = Vec::new();
        running.read_to_end(&mut held).unwrap();
        assert_eq!(held, b"old", "the running process still holds its original inode");
        drop(running);
        std::fs::remove_file(&current).unwrap();
        std::fs::rename(&backup, &current).unwrap();
        assert_eq!(std::fs::read(&current).unwrap(), b"old");
        assert!(replace(&current, &staged, &backup).is_err());
        assert_eq!(
            std::fs::read(&current).unwrap(),
            b"old",
            "failed publication leaves the live pathname intact"
        );
    }

    #[tokio::test]
    async fn refused_downloads_leave_the_working_binary_and_no_partial_file() {
        for (declared, body) in [(4, b"html".as_slice()), (MAX_BINARY + 1, b"x"), (50, b"cut")] {
            let scratch = Scratch::new();
            let current = scratch.0.join("monitor-agent");
            std::fs::write(&current, b"working agent").unwrap();
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let base = format!("http://{}", listener.local_addr().unwrap());
            let body = body.to_vec();
            let server = tokio::spawn(async move {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut request = vec![0; 2048];
                let count = stream.read(&mut request).await.unwrap();
                let request = String::from_utf8_lossy(&request[..count]);
                let os = if cfg!(target_os = "linux") {
                    String::new()
                } else {
                    format!("&os={}", std::env::consts::OS)
                };
                assert!(
                    request.starts_with(&format!("GET /agent/{}?version=1.3.1{os} ", std::env::consts::ARCH))
                );
                stream
                    .write_all(
                        format!("HTTP/1.1 200 OK\r\nContent-Length: {declared}\r\nConnection: close\r\n\r\n")
                            .as_bytes(),
                    )
                    .await
                    .unwrap();
                stream.write_all(&body).await.unwrap();
            });
            assert!(download(&base, "1.3.1", &current).await.is_err());
            server.await.unwrap();
            assert_eq!(std::fs::read(&current).unwrap(), b"working agent");
            assert!(!sibling(&current, "download").exists());
        }
    }

    #[tokio::test]
    async fn disabled_and_duplicate_commands_cannot_start_another_update() {
        let request = Request { id: "first".into(), version: "1.3.1".into() };
        let mut updater = Updater::new(false, "http://127.0.0.1:1/api/agent/ws").unwrap();
        assert_eq!(updater.request(request.clone()).unwrap().status, "failed");
        assert!(updater.task.is_none());
        updater.enabled = true;
        assert_eq!(updater.request(request.clone()).unwrap().status, "downloading");
        assert_eq!(updater.request(request).unwrap().status, "downloading");
        assert_eq!(
            updater.request(Request { id: "other".into(), version: "1.3.2".into() }).unwrap().status,
            "failed"
        );
        assert_eq!(updater.job.as_ref().unwrap().id, "first");
        updater.task.take().unwrap().abort();
        for version in ["../new", "1.3.1?url=other", "", "1.3.1/path"] {
            assert!(!Request { id: "first".into(), version: version.into() }.valid());
        }
    }

    #[cfg(unix)]
    #[tokio::test(start_paused = true)]
    async fn a_reconnect_timeout_restores_the_previous_binary_and_keeps_the_rollback_receipt() {
        let scratch = Scratch::new();
        let executable = scratch.0.join("monitor-agent");
        std::fs::write(&executable, b"new").unwrap();
        std::fs::write(sibling(&executable, "previous"), b"old").unwrap();
        save_pending(&executable, &Pending { id: "request".into(), version: "1.3.1".into(), boots: 1 })
            .unwrap();
        let mut updater = Updater::new(false, "http://127.0.0.1/api/agent/ws").unwrap();
        updater.executable = executable.clone();
        updater.confirmation = Some("request".into());
        updater.recover_if_due().unwrap();
        assert_eq!(std::fs::read(&executable).unwrap(), b"new");
        tokio::time::advance(RECOVERY).await;
        // Text fixtures cannot exec. The real pathname is restored first, so
        // the test can inspect what the supervisor's next boot receives.
        assert!(updater.recover_if_due().is_err());
        assert_eq!(std::fs::read(&executable).unwrap(), b"old");
        let pending: Pending =
            serde_json::from_slice(&std::fs::read(pending_path(&executable)).unwrap()).unwrap();
        assert_eq!(pending.id, "request");
    }
}

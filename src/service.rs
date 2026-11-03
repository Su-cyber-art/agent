//! Windows Service Control Manager entry point. Credentials stay in an ACL-
//! protected file next to the agent directory, not in the service command line.
use std::collections::HashMap;
use std::ffi::OsString;
use std::time::Duration;

use anyhow::Result;
use windows_service::service::{
    ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus, ServiceType,
};
use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
use windows_service::{define_windows_service, service_dispatcher};

const NAME: &str = "monitor-agent";
define_windows_service!(service_entry, service_main);

pub fn dispatch() -> Result<()> {
    service_dispatcher::start(NAME, service_entry)?;
    Ok(())
}

fn service_main(_: Vec<OsString>) {
    if let Err(error) = serve() {
        eprintln!("monitor-agent service: {error:#}");
        std::process::exit(1);
    }
}

fn serve() -> Result<()> {
    let (stop, mut stopped) = tokio::sync::mpsc::channel(1);
    let handle = service_control_handler::register(NAME, move |event| match event {
        ServiceControl::Stop | ServiceControl::Shutdown => {
            let _ = stop.try_send(());
            ServiceControlHandlerResult::NoError
        }
        ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
        _ => ServiceControlHandlerResult::NotImplemented,
    })?;
    let status = |state, code| ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: state,
        controls_accepted: if state == ServiceState::Running {
            ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN
        } else {
            ServiceControlAccept::empty()
        },
        exit_code: ServiceExitCode::Win32(code),
        checkpoint: 0,
        wait_hint: Duration::default(),
        process_id: None,
    };
    handle.set_service_status(status(ServiceState::StartPending, 0))?;
    let exe = std::env::current_exe()?;
    let config = exe
        .parent()
        .and_then(|p| p.parent())
        .ok_or_else(|| anyhow::anyhow!("missing installation directory"))?
        .join("agent.json");
    let environment: HashMap<String, String> = serde_json::from_slice(&std::fs::read(config)?)?;
    for name in [
        "MONITOR_SERVER",
        "MONITOR_TOKEN",
        "MONITOR_IFACE",
        "MONITOR_INTERVAL",
        "MONITOR_INSECURE",
        "MONITOR_ALLOW_UPGRADE",
    ] {
        if let Some(value) = environment.get(name) {
            std::env::set_var(name, value);
        }
    }
    let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
    handle.set_service_status(status(ServiceState::Running, 0))?;
    let result = runtime.block_on(async {
        tokio::select! {
            result = crate::run_agent() => result,
            _ = stopped.recv() => Ok(()),
        }
    });
    handle.set_service_status(status(ServiceState::Stopped, if result.is_ok() { 0 } else { 1 }))?;
    result
}

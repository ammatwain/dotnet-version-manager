use clap::{Parser, Subcommand};
use std::process::Command;
use serde_json::json;
use std::fs::{self, File, remove_file, remove_dir_all};
use std::path::{Path, PathBuf};
use reqwest::header;
use serde::Deserialize;
use serde::de::Deserializer;
//use std::error::Error;
//use std::fmt;

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Get current dotnet version
    Current,
    /// List installed SDK versions
    List,
    /// Set SDK version via global.json
    Use { version: String },
    /// Check if dotnet is installed and install if not
    Install {
        /// Install LTS version
        #[arg(long)]
        lts: bool,
        /// Specific version to install
        #[arg(long)]
        version: Option<String>,
        /// The path to install the SDK to
        #[arg(long)]
        install_path: Option<String>,
    },
    /// Uninstall SDK versions
    Uninstall {
        /// Version to uninstall (full or major)
        version: Option<String>,
        /// Remove all SDKs managed by this tool
        #[arg(long)]
        all: bool,
    },
    /// Check for common issues
    Doctor,
    /// List all SDK versions available on Microsoft repository
    Remote {
        /// Show only LTS versions
        #[arg(long)]
        lts: bool,
    },
}

// Structs per releases JSON
#[derive(Debug, Deserialize)]
pub struct ReleaseIndex {
    #[serde(rename = "releases-index")]
    pub releases_index: Vec<ReleaseChannel>,
}

#[derive(Debug, Deserialize)]
pub struct ReleaseChannel {
    #[serde(rename = "channel-version")]
    pub channel_version: Option<String>,

    #[serde(rename = "latest-release")]
    pub latest_release: Option<String>,

    #[serde(rename = "release-type")]
    pub release_type: Option<String>, // "lts" o "sts"

    #[serde(rename = "releases.json")]
    pub releases_json: String,
}

#[derive(Debug, Deserialize)]
pub struct ChannelReleases {
    #[serde(default)]
    pub releases: Vec<Release>, // sempre un vecchio anche se null nel JSON
}

#[derive(Debug, Deserialize)]
pub struct Release {
    #[serde(default)]
    pub release_date: Option<String>,

    #[serde(rename = "release-version")]
    pub version: Option<String>,

    #[serde(default)]
    pub lts: Option<bool>,

    #[serde(default)]
    pub security: Option<bool>,

    #[serde(rename = "cve-list", default, deserialize_with = "null_to_vec")]
    pub cve_list: Vec<CVE>,

    #[serde(rename = "release-notes", default)]
    pub release_notes: Option<String>,

    #[serde(default)]
    pub runtime: Option<DotnetRuntime>,

    #[serde(default)]
    pub sdk: Option<DotnetSdk>,

    #[serde(default, deserialize_with = "null_to_vec")]
    pub sdks: Vec<DotnetSdk>, // può essere vuoto se null nel JSON

    #[serde(rename = "aspnetcore-runtime", default)]
    pub aspnetcore_runtime: Option<AspNetCoreRuntime>,

    #[serde(default)]
    pub windowsdesktop: Option<WindowsDesktop>,
}

#[derive(Debug, Deserialize)]
pub struct CVE {
    #[serde(rename = "cve-id")]
    pub cve_id: String,

    #[serde(rename = "cve-url")]
    pub cve_url: String,
}

#[derive(Debug, Deserialize)]
pub struct FileInfo {
    pub name: String,
    pub rid: Option<String>,
    pub url: String,
    pub hash: Option<String>,
    #[serde(default)]
    pub akams: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct DotnetRuntime {
    pub version: Option<String>,
    #[serde(rename = "version-display")]
    pub version_display: Option<String>,
    #[serde(rename = "vs-version")]
    pub vs_version: Option<String>,
    #[serde(rename = "vs-mac-version")]
    pub vs_mac_version: Option<String>,
    #[serde(default)]
    pub files: Vec<FileInfo>, // può essere vuoto se null
}

#[derive(Debug, Deserialize)]
pub struct DotnetSdk {
    pub version: Option<String>,
    #[serde(rename = "version-display")]
    pub version_display: Option<String>,
    #[serde(rename = "runtime-version")]
    pub runtime_version: Option<String>,
    #[serde(rename = "vs-version")]
    pub vs_version: Option<String>,
    #[serde(rename = "vs-mac-version")]
    pub vs_mac_version: Option<String>,
    #[serde(rename = "vs-support")]
    pub vs_support: Option<String>,
    #[serde(rename = "vs-mac-support")]
    pub vs_mac_support: Option<String>,
    #[serde(rename = "csharp-version")]
    pub csharp_version: Option<String>,
    #[serde(rename = "fsharp-version")]
    pub fsharp_version: Option<String>,
    #[serde(rename = "vb-version")]
    pub vb_version: Option<String>,
    #[serde(default)]
    pub files: Vec<FileInfo>,
}

#[derive(Debug, Deserialize)]
pub struct AspNetCoreRuntime {
    pub version: Option<String>,
    #[serde(rename = "version-display")]
    pub version_display: Option<String>,
    #[serde(rename = "version-aspnetcoremodule", default, deserialize_with = "null_to_vec")]
    pub version_aspnetcoremodule: Vec<String>, // può essere vuoto se null
    #[serde(rename = "vs-version")]
    pub vs_version: Option<String>,
    #[serde(default)]
    pub files: Vec<FileInfo>,
}

#[derive(Debug, Deserialize)]
pub struct WindowsDesktop {
    pub version: Option<String>,
    #[serde(rename = "version-display")]
    pub version_display: Option<String>,
    #[serde(default)]
    pub files: Vec<FileInfo>,
}

// --- Funzioni di utilità ---
fn get_home_dir() -> Option<PathBuf> {
    if cfg!(windows) {
        std::env::var_os("USERPROFILE").map(PathBuf::from)
    } else {
        std::env::var_os("HOME").map(PathBuf::from)
    }
}

fn is_dotnet_installed() -> bool {
    Command::new("dotnet")
        .arg("--version")
        .output()
        .map(|output| output.status.success())
        .unwrap_or(false)
}

fn null_to_vec<'de, D, T>(deserializer: D) -> Result<Vec<T>, D::Error>
where
    D: Deserializer<'de>,
    T: serde::Deserialize<'de>,
{
    Ok(Option::deserialize(deserializer)?.unwrap_or_default())
}


fn list_installed_sdks() -> Result<Vec<(String, PathBuf)>, Box<dyn std::error::Error>> {
    let output = Command::new("dotnet")
        .args(["--list-sdks"])
        .output()?;
    if !output.status.success() {
        return Err("Failed to list SDKs".into());
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut sdks = Vec::new();
    for line in stdout.lines() {
        if let Some((ver_part, path_part)) = line.split_once('[') {
            let version = ver_part.trim().split_whitespace().next().unwrap_or("").to_string();
            let base = path_part.trim().trim_end_matches(']').trim();
            if version.is_empty() || base.is_empty() { continue; }
            let mut pb = PathBuf::from(base);
            pb.push(&version);
            sdks.push((version, pb));
        }
    }
    Ok(sdks)
}

// --- Download e installazione ---
async fn download_install_script() -> Result<PathBuf, Box<dyn std::error::Error>> {
    let script_url = if cfg!(windows) {
        "https://dotnet.microsoft.com/download/dotnet/scripts/v1/dotnet-install.ps1"
    } else {
        "https://dotnet.microsoft.com/download/dotnet/scripts/v1/dotnet-install.sh"
    };

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()?;

    let response = client
        .get(script_url)
        .header(header::USER_AGENT, "dver/0.1 (dotnet-version-manager)")
        .send()
        .await?;

    if !response.status().is_success() {
        return Err(format!("Failed to download installer script: HTTP {}", response.status()).into());
    }

    let script_content = response.bytes().await?;

    let mut file_path = std::env::temp_dir();
    let script_name = if cfg!(windows) { "dotnet-install.ps1" } else { "dotnet-install.sh" };
    let unique = format!("{}_{}", script_name, std::process::id());
    file_path.push(unique);

    let mut file = File::create(&file_path)?;
    std::io::Write::write_all(&mut file, &script_content)?;

    if !cfg!(windows) {
        let mut perms = fs::metadata(&file_path)?.permissions();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            perms.set_mode(0o755);
            fs::set_permissions(&file_path, perms)?;
        }
    }

    Ok(file_path)
}

async fn install_dotnet(lts: bool, version: Option<String>, install_path: Option<String>) -> Result<(), Box<dyn std::error::Error>> {
    let script_path = download_install_script().await?;

    let mut command = if cfg!(windows) {
        let mut cmd = Command::new("powershell");
        cmd.arg("-NoLogo").arg("-NoProfile").arg("-NonInteractive");
        cmd.arg("-ExecutionPolicy").arg("Bypass");
        cmd.arg("-File").arg(&script_path);
        cmd
    } else {
        let mut cmd = Command::new("bash");
        cmd.arg(&script_path);
        cmd
    };

    if lts {
        command.arg("-Channel").arg("LTS");
    } else if let Some(v) = version {
        command.arg("-Version").arg(v);
    }

    if let Some(path) = install_path {
        command.arg("-InstallDir").arg(path);
    }

    let output = command.output()?;
    let _ = remove_file(&script_path);

    if !output.status.success() {
        eprintln!("dotnet-install script failed with status: {:?}", output.status.code());
        let stderr = String::from_utf8_lossy(&output.stderr);
        if !stderr.is_empty() { eprintln!("{}", stderr.trim()); }
        let stdout = String::from_utf8_lossy(&output.stdout);
        if !stdout.is_empty() { eprintln!("{}", stdout.trim()); }
        return Err("dotnet installation failed".into());
    }

    println!("{}", String::from_utf8_lossy(&output.stdout));
    Ok(())
}

// --- Controlli comuni ---
fn run_doctor_checks() {
    println!("Checking for common issues...");
    if is_dotnet_installed() {
        println!("✅ dotnet command is available in your PATH.");
    } else {
        println!("❌ dotnet command not found. Please install .NET and ensure PATH is correct.");
        return;
    }

    if let Some(home_dir) = get_home_dir() {
        let dotnet_dir = home_dir.join(".dotnet");
        if let Ok(path_var) = std::env::var("PATH") {
            if path_var.split(':').any(|p| Path::new(p) == dotnet_dir) {
                println!("✅ .NET SDK installation directory is in your PATH.");
            } else {
                println!("⚠️ .NET SDK installation directory (~/.dotnet) might not be in PATH.");
            }
        }
    }
}

// --- Funzione Remote (tutte le patch disponibili) ---
pub async fn list_remote_patch_sdks(lts_only: bool) -> Result<(), Box<dyn std::error::Error>> {
    let index_url = "https://dotnetcli.blob.core.windows.net/dotnet/release-metadata/releases-index.json";

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()?;

    let resp = client.get(index_url)
        .header(reqwest::header::USER_AGENT, "dver/0.1 (dotnet-version-manager)")
        .send()
        .await?;

    if !resp.status().is_success() {
        return Err(format!("Failed to fetch releases-index.json: HTTP {}", resp.status()).into());
    }

    let body = resp.text().await?;
    let index: ReleaseIndex = serde_json::from_str(&body)?;

    println!("Remote .NET SDK versions available:");

    for channel in &index.releases_index {
        // sicuro perché usiamo default se mancante
        let channel_version = channel.channel_version.as_deref().unwrap_or("unknown");
        let release_type = channel.release_type.as_deref().unwrap_or("unknown");

        if lts_only && release_type != "lts" {
            continue;
        }

        println!("Channel: {} ({})", channel_version, release_type);
        println!("Fetching releases from: {}", channel.releases_json);

        let releases_resp = client.get(&channel.releases_json)
            .header(reqwest::header::USER_AGENT, "dver/0.1 (dotnet-version-manager)")
            .send()
            .await?;

        if !releases_resp.status().is_success() {
            eprintln!("Failed to fetch {}: HTTP {}", channel.releases_json, releases_resp.status());
            continue;
        }

        let releases_body = releases_resp.text().await?;
        let channel_releases: ChannelReleases = serde_json::from_str(&releases_body)?;

        for release in &channel_releases.releases {
            println!("{}", release.version.as_deref().unwrap_or("unknown"));
        }

    }

    Ok(())
}


// --- MAIN ---
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    match &cli.command {
        Commands::Current => {
            let output = Command::new("dotnet")
                .arg("--version")
                .output()?;
            if output.status.success() {
                let version = String::from_utf8_lossy(&output.stdout);
                println!("Current dotnet version: {}", version.trim());
            } else {
                let stderr = String::from_utf8_lossy(&output.stderr);
                eprintln!("Failed to get current dotnet version{}{}",
                          if stderr.trim().is_empty() { "" } else { ": " }, stderr.trim());
            }
        }
        Commands::List => {
            let output = Command::new("dotnet")
                .args(["--list-sdks"])
                .output()?;
            if output.status.success() {
                let sdks = String::from_utf8_lossy(&output.stdout);
                let mut versions: Vec<String> = sdks
                    .lines()
                    .filter_map(|line| line.split_whitespace().next().map(|s| s.to_string()))
                    .collect();
                versions.sort();
                versions.dedup();
                for v in versions {
                    println!("{}", v);
                }
            } else {
                eprintln!("Failed to list SDK versions");
            }
        }
        Commands::Use { version } => {
            let json_data = json!({
                "sdk": {
                    "version": version
                }
            });
            let file_path = std::env::current_dir()?.join("global.json");
            if file_path.exists() {
                let backup = file_path.with_extension("json.bak");
                let _ = fs::copy(&file_path, &backup);
            }
            let file = File::create(&file_path)?;
            serde_json::to_writer_pretty(file, &json_data)?;
            println!("SDK version set to {} in {:?}", version, file_path);
        }
        Commands::Install { lts, version, install_path } => {
            if is_dotnet_installed() {
                println!("dotnet is already installed.");
                let output = Command::new("dotnet")
                    .arg("--version")
                    .output()?;
                println!("Current version: {}", String::from_utf8_lossy(&output.stdout).trim());
            } else {
                println!("Installing dotnet...");
                install_dotnet(*lts, version.clone(), install_path.clone()).await?;
                println!("dotnet installation completed.");
            }
        }
        Commands::Uninstall { version, all } => {
            let sdks = list_installed_sdks()?;
            let mut roots: Vec<PathBuf> = sdks
                .iter()
                .filter_map(|(_, p)| p.parent().map(|pp| pp.to_path_buf()))
                .collect();
            roots.sort();
            roots.dedup();

            let targets: Vec<(String, PathBuf)> = if *all {
                sdks
            } else if let Some(v) = version {
                if v.contains('.') {
                    sdks.into_iter().filter(|(ver, _)| ver == v).collect()
                } else {
                    let prefix = format!("{}.", v);
                    sdks.into_iter().filter(|(ver, _)| ver.starts_with(&prefix)).collect()
                }
            } else {
                eprintln!("Provide a version or --all to uninstall.");
                Vec::new()
            };

            if targets.is_empty() {
                println!("No matching SDKs found.");
            } else {
                for (ver, path) in targets {
                    let is_under_root = roots.iter().any(|r| path.starts_with(r));
                    if !is_under_root {
                        eprintln!("Skipping {}: path {:?} outside known SDK roots", ver, path);
                        continue;
                    }
                    if path.exists() {
                        match remove_dir_all(&path) {
                            Ok(_) => println!("Removed {}", ver),
                            Err(e) => eprintln!("Failed to remove {}: {}", ver, e),
                        }
                    } else {
                        println!("Directory for {} not found", ver);
                    }
                }
            }
        }
        Commands::Doctor => run_doctor_checks(),
        Commands::Remote { lts } => {
            if let Err(e) = list_remote_patch_sdks(*lts).await {
                eprintln!("Failed to list remote SDKs: {}", e);
            }
        }
    }

    Ok(())
}

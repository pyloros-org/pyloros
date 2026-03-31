//! Pyloros CLI - A filtering HTTPS proxy for agent network access control

use clap::{Parser, Subcommand};
use std::path::PathBuf;
use std::sync::Arc;
use tracing_subscriber::EnvFilter;

use pyloros::{AuditLogger, Config, GeneratedCa, ProxyServer};

#[derive(Parser)]
#[command(name = "pyloros")]
#[command(about = "A filtering HTTPS proxy for agent network access control")]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Run the proxy server
    Run {
        /// Path to configuration file
        #[arg(short, long)]
        config: Option<PathBuf>,

        /// Path to CA certificate (overrides config)
        #[arg(long)]
        ca_cert: Option<PathBuf>,

        /// Path to CA private key (overrides config)
        #[arg(long)]
        ca_key: Option<PathBuf>,

        /// Bind address (overrides config)
        #[arg(short, long)]
        bind: Option<String>,

        /// Direct HTTPS listener bind address (optional, enables SNI-based direct TLS mode)
        #[arg(long)]
        direct_https_bind: Option<String>,

        /// Auto-generate CA certificate at configured paths if files don't exist
        #[arg(long)]
        auto_generate_ca: bool,

        /// Log level (error, warn, info, debug, trace)
        #[arg(short, long, default_value = "info")]
        log_level: String,
    },

    /// Generate a new CA certificate
    GenerateCa {
        /// Output directory for ca.crt and ca.key
        #[arg(short, long, default_value = ".")]
        out: PathBuf,

        /// Certificate filename
        #[arg(long, default_value = "ca.crt")]
        cert_name: String,

        /// Key filename
        #[arg(long, default_value = "ca.key")]
        key_name: String,
    },

    /// Validate a configuration file
    ValidateConfig {
        /// Path to configuration file
        #[arg(short, long)]
        config: PathBuf,
    },

    /// Generate /etc/hosts entries for direct HTTPS mode
    GenerateHosts {
        /// Path to configuration file
        #[arg(short, long)]
        config: PathBuf,

        /// IP address to map hostnames to
        #[arg(long, default_value = "127.0.0.12")]
        ip: String,
    },
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    let cli = Cli::parse();

    match cli.command {
        Commands::Run {
            config,
            ca_cert,
            ca_key,
            bind,
            direct_https_bind,
            auto_generate_ca,
            log_level,
        } => {
            // Initialize logging
            let filter =
                EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(&log_level));

            tracing_subscriber::fmt()
                .with_env_filter(filter)
                .with_target(false)
                .with_writer(std::io::stderr)
                .init();

            // Load config
            let mut cfg = if let Some(ref config_path) = config {
                tracing::info!(path = %config_path.display(), "Loading configuration");
                Config::from_file(config_path)?
            } else {
                tracing::info!("Using default configuration");
                Config::parse("")?
            };

            // Apply CLI overrides
            if let Some(cert) = ca_cert {
                cfg.proxy.ca_cert = Some(cert.to_string_lossy().to_string());
            }
            if let Some(key) = ca_key {
                cfg.proxy.ca_key = Some(key.to_string_lossy().to_string());
            }
            if let Some(addr) = bind {
                cfg.proxy.bind_address = addr;
            }
            if let Some(addr) = direct_https_bind {
                cfg.proxy.direct_https_bind = Some(addr);
            }

            // Validate CA cert/key paths are specified
            if cfg.proxy.ca_cert.is_none() || cfg.proxy.ca_key.is_none() {
                eprintln!("Error: CA certificate and key paths are required.");
                eprintln!();
                eprintln!("Specify them in the config file or via --ca-cert and --ca-key flags.");
                eprintln!("Use --auto-generate-ca to create them automatically if missing.");
                eprintln!();
                eprintln!("To generate a CA certificate manually:");
                eprintln!("  pyloros generate-ca --out ./certs/");
                std::process::exit(1);
            }

            // Auto-generate CA files at configured paths if they don't exist
            if auto_generate_ca {
                let cert_path = cfg.proxy.ca_cert.as_ref().unwrap();
                let key_path = cfg.proxy.ca_key.as_ref().unwrap();
                if !std::path::Path::new(cert_path).exists()
                    || !std::path::Path::new(key_path).exists()
                {
                    tracing::info!("Auto-generating CA certificate...");
                    let ca = GeneratedCa::generate()?;
                    if let Some(parent) = std::path::Path::new(cert_path).parent() {
                        std::fs::create_dir_all(parent)?;
                    }
                    if let Some(parent) = std::path::Path::new(key_path).parent() {
                        std::fs::create_dir_all(parent)?;
                    }
                    ca.save(cert_path, key_path)?;
                    tracing::info!(
                        cert = %cert_path,
                        key = %key_path,
                        "CA certificate generated"
                    );
                }
            }

            // Extract optional overrides before moving cfg
            let upstream_override_port = cfg.proxy.upstream_override_port;
            let upstream_tls_ca = cfg.proxy.upstream_tls_ca.clone();
            let audit_log_path = cfg.logging.audit_log.clone();

            // Create and run server
            let mut server = ProxyServer::new(cfg)?;

            // Enable live-reload if config file was provided
            if let Some(config_path) = config {
                server = server.with_config_path(config_path);
            }

            if let Some(port) = upstream_override_port {
                server = server.with_upstream_port_override(port);
            }
            if let Some(ref ca_path) = upstream_tls_ca {
                let pem = std::fs::read(ca_path)
                    .map_err(|e| format!("Failed to read upstream TLS CA '{}': {}", ca_path, e))?;
                let mut root_store = rustls::RootCertStore::empty();
                for cert in rustls_pemfile::certs(&mut &pem[..]) {
                    root_store.add(cert?)?;
                }
                let mut tls_config = rustls::ClientConfig::builder()
                    .with_root_certificates(root_store)
                    .with_no_client_auth();
                tls_config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
                server = server.with_upstream_tls(Arc::new(tls_config));
            }

            // Open audit logger if configured
            if let Some(ref audit_path) = audit_log_path {
                match AuditLogger::open(audit_path) {
                    Ok(logger) => {
                        tracing::info!(path = %audit_path, "Audit log enabled");
                        server = server.with_audit_logger(Arc::new(logger));
                    }
                    Err(e) => {
                        eprintln!("Error: Failed to open audit log '{}': {}", audit_path, e);
                        std::process::exit(1);
                    }
                }
            }

            tracing::info!("Starting proxy server...");
            if !server.bind_address().contains('/') {
                tracing::info!("Configure clients with:");
                tracing::info!("  export HTTP_PROXY=http://{}", server.bind_address());
                tracing::info!("  export HTTPS_PROXY=http://{}", server.bind_address());
            }

            // Handle SIGINT (Ctrl+C) and SIGTERM.
            // Use tokio::signal::unix::signal() for both — it installs the handler
            // eagerly at construction time, avoiding a race where the default handler
            // fires before the async select loop is polled.
            let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
            #[cfg(unix)]
            let mut sigint =
                tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())
                    .expect("failed to install SIGINT handler");
            #[cfg(unix)]
            let mut sigterm =
                tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                    .expect("failed to install SIGTERM handler");
            tokio::spawn(async move {
                #[cfg(unix)]
                {
                    tokio::select! {
                        _ = sigint.recv() => {},
                        _ = sigterm.recv() => {},
                    }
                }
                #[cfg(not(unix))]
                {
                    tokio::signal::ctrl_c().await.ok();
                }
                tracing::info!("Shutting down...");
                let _ = shutdown_tx.send(());
            });

            server.run_until_shutdown(shutdown_rx).await?;
        }

        Commands::GenerateCa {
            out,
            cert_name,
            key_name,
        } => {
            // Create output directory if needed
            std::fs::create_dir_all(&out)?;

            let cert_path = out.join(&cert_name);
            let key_path = out.join(&key_name);

            println!("Generating CA certificate...");

            let ca = GeneratedCa::generate()?;
            ca.save(&cert_path, &key_path)?;

            println!("CA certificate generated successfully!");
            println!();
            println!("  Certificate: {}", cert_path.display());
            println!("  Private key: {}", key_path.display());
            println!();
            println!("To use with the proxy:");
            println!(
                "  pyloros run --ca-cert {} --ca-key {}",
                cert_path.display(),
                key_path.display()
            );
            println!();
            println!("To trust the CA on Ubuntu/Debian:");
            println!(
                "  sudo cp {} /usr/local/share/ca-certificates/pyloros.crt",
                cert_path.display()
            );
            println!("  sudo update-ca-certificates");
            println!();
            println!("IMPORTANT: Keep the private key secure!");
        }

        Commands::ValidateConfig { config } => {
            println!("Validating configuration: {}", config.display());

            let cfg = Config::from_file(&config)?;

            println!("Configuration is valid!");
            println!();
            println!("  Bind address: {}", cfg.proxy.bind_address);
            println!(
                "  CA cert: {}",
                cfg.proxy.ca_cert.as_deref().unwrap_or("(not set)")
            );
            println!(
                "  CA key: {}",
                cfg.proxy.ca_key.as_deref().unwrap_or("(not set)")
            );
            println!("  Log level: {}", cfg.logging.level);
            println!(
                "  Log allowed requests: {}",
                cfg.logging.log_allowed_requests
            );
            println!(
                "  Log blocked requests: {}",
                cfg.logging.log_blocked_requests
            );
            println!(
                "  Audit log: {}",
                cfg.logging.audit_log.as_deref().unwrap_or("disabled")
            );
            println!("  Permissive mode: {}", cfg.proxy.permissive);
            if let (Some(username), Some(password)) =
                (&cfg.proxy.auth_username, &cfg.proxy.auth_password)
            {
                println!("  Authentication: enabled (username: {})", username);
                // Try resolving password to catch env var issues early
                pyloros::config::resolve_credential_value(password)?;
            } else {
                println!("  Authentication: disabled");
            }
            println!("  Rules: {}", cfg.rules.len());

            if !cfg.rules.is_empty() {
                println!();
                println!("Rules:");
                for (i, rule) in cfg.rules.iter().enumerate() {
                    if let Some(ref git) = rule.git {
                        let branches_desc = rule
                            .branches
                            .as_ref()
                            .map(|b| format!(" branches={:?}", b))
                            .unwrap_or_default();
                        println!("  {}. git={} {}{}", i + 1, git, rule.url, branches_desc);
                    } else {
                        let ws = if rule.websocket { " [WebSocket]" } else { "" };
                        println!(
                            "  {}. {} {}{}",
                            i + 1,
                            rule.method.as_deref().unwrap_or("?"),
                            rule.url,
                            ws
                        );
                    }
                }
            }

            // Try to compile rules
            let engine = pyloros::FilterEngine::new(cfg.rules)?;
            println!();
            println!("All {} rules compiled successfully.", engine.rule_count());

            // Validate and display credentials
            println!("  Credentials: {}", cfg.credentials.len());
            if !cfg.credentials.is_empty() {
                let (cred_engine, _) = pyloros::CredentialEngine::new(cfg.credentials)?;
                println!();
                println!("Credentials:");
                for (i, desc) in cred_engine.credential_descriptions().iter().enumerate() {
                    println!("  {}. {}", i + 1, desc);
                }
                println!();
                println!(
                    "All {} credentials compiled successfully.",
                    cred_engine.credential_count()
                );
            }
        }

        Commands::GenerateHosts { config, ip } => {
            let cfg = Config::from_file(&config)?;
            let (literal_hosts, wildcard_hosts) = cfg.extract_hosts();

            // Warn about skipped wildcard patterns
            for pattern in &wildcard_hosts {
                eprintln!(
                    "Warning: skipping wildcard pattern '{}' (cannot be used in /etc/hosts)",
                    pattern
                );
            }

            // Output /etc/hosts format
            for host in &literal_hosts {
                println!("{} {}", ip, host);
            }

            if literal_hosts.is_empty() {
                eprintln!("Warning: no literal hostnames found in config rules");
            } else {
                eprintln!(
                    "Generated {} host entries ({} wildcard patterns skipped)",
                    literal_hosts.len(),
                    wildcard_hosts.len()
                );
            }
        }
    }

    Ok(())
}

use std::io::Write;
use figment::{Figment};
use figment::providers::{Yaml, Format};
use serde::{Deserialize, Serialize};
use clap::{Command, Arg, ArgAction};
use handlebars::{Handlebars};
use log::{debug, error, info};

#[derive(Serialize, Deserialize, Debug)]
struct Config {
    servers: Vec<ServerConfig>,
    proxy_config: ProxyConfig
}

#[derive(Serialize, Deserialize, Debug)]
struct ProxyConfig {
    listen_port: u16,
    tls: bool,
    tls_cert: String,
    quic: bool,
    http_redirect: bool,
    username: String,
    group: String,
}

#[derive(Serialize, Deserialize, Debug)]
struct ServerConfig {
    name: String,
    port: u16,
    host: String,
    health_check: bool,
    domain: String,
}

fn main() {
    env_logger::init();
    info!("Scanning for HAProxy executable");

    let haproxy_binary_path = which::which("haproxy");
    match haproxy_binary_path.clone() {
        Ok(path) => {
            info!("Found HAProxy executable at {}", path.clone().display());
        }
        Err(e) => {
            error!("Could not find HAProxy executable, can't reload or validate: {}", e);
        }
    }

    let args = Command::new("hapcfg")
        .version("0.1.0")
        .about("Haproxy config generator")
        .arg(
            Arg::new("config")
                .short('c')
                .long("config")
                .value_name("FILE")
                .help("reads HAProxyConfGen config from file")
                .default_value("config.yml"),
        )
        .arg(
            Arg::new("output")
                .short('o')
                .long("output")
                .value_name("FILE")
                .help("write haproxy config to file")
                .default_value("haproxy.cfg"),
        )
        .arg(
            Arg::new("reload")
                .short('r')
                .long("reload")
                .help("Reload haproxy systemd service after generating config")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("novalidate")
                .short('n')
                .long("novalidate")
                .help("Don't validate generated config")
                .action(ArgAction::SetTrue),
        )
        .get_matches();

    let config_path = args.get_one::<String>("config").unwrap();
    let config = Figment::new().merge(Yaml::file(config_path)).extract::<Config>().unwrap();

    let mut handlebars = Handlebars::new();

    handlebars.register_partial("frontend", include_str!("templates/frontend.hbs")).expect("how did this happen lmao");
    handlebars.register_partial("backend", include_str!("templates/backend.hbs")).expect("how did this happen lmao");
    handlebars.register_template_string("haproxy", include_str!("templates/haproxy.hbs")).expect("how did this happen lmao");
    handlebars.register_escape_fn(handlebars::no_escape);

    debug!("config: {:?}", config);

    // render config
    let conf = match handlebars.render("haproxy", &config) {
        Ok(rendered) => rendered,
        Err(e) => {
            error!("Could not render config: {}", e);
            std::process::exit(1);
        }
    };

    // write config to file
    let default_path = "haproxy.cfg".to_string();
    let output_path = args.get_one::<String>("output").unwrap_or(&default_path);

    let tempdir = tempfile::tempdir().expect("Unable to create tempdir");
    let tempfile = tempdir.path().join("haproxy.cfg");
    let mut file = std::fs::File::create(&tempfile).expect("Unable to create tempfile");
    file.write_all(conf.as_bytes()).expect("Unable to write tempfile");

    // validate config
    if !args.get_one::<bool>("novalidate").unwrap() && !&haproxy_binary_path.is_err() {

        let mut cmd = std::process::Command::new(haproxy_binary_path.clone().unwrap());
        cmd.arg("vv");
        cmd.arg(output_path);
        let output = cmd.output().expect("failed to execute process");
        if output.status.success() {
            // Check for compiled-in QUIC support, substring "+QUIC", lacking is "-QUIC"
            let build_flags = String::from_utf8_lossy(&output.stderr);
            if !build_flags.contains("+QUIC") && config.proxy_config.quic {
                error!("Config validation failed, HAProxy does not have QUIC support compiled in but you have it enabled!");
                std::process::exit(1);
            }
            std::process::exit(1);
        }

        // Check for existence of the certificate file, if TLS is enabled
        if config.proxy_config.tls && !std::path::Path::new(&config.proxy_config.tls_cert).exists() {
            error!("Config validation failed, TLS is enabled but the certificate file at {} does not exist or is not accessible!", config.proxy_config.tls_cert);
            std::process::exit(1);
        }

        // Check for the given user and group existing
        let mut cmd = std::process::Command::new("id");
        cmd.arg("-u");
        cmd.arg(&config.proxy_config.username);
        let output = cmd.output().expect("failed to execute process");
        if !output.status.success() {
            error!("Config validation failed, user {} does not exist, but is listed as user in config!", &config.proxy_config.username);
            std::process::exit(1);
        }

        let mut cmd = std::process::Command::new("id");
        cmd.arg("-g");
        cmd.arg(&config.proxy_config.group);
        let output = cmd.output().expect("failed to execute process");
        if !output.status.success() {
            error!("Config validation failed, group {} does not exist, but is listed as group in config!", &config.proxy_config.group);
            std::process::exit(1);
        }


        // Run HAProxy config validation
        let mut cmd = std::process::Command::new(haproxy_binary_path.clone().unwrap());
        cmd.arg("-c");
        cmd.arg("-f");
        cmd.arg(tempfile.as_path());
        let output = cmd.output().expect("failed to execute process");
        if !output.status.success() {
            error!("Config validation failed, HAProxy output follows: {}", String::from_utf8_lossy(&output.stderr));
            std::process::exit(1);
        }

        info!("Config validation successful");
    }


    info!("Generation successful, writing config to {}", output_path);

    // Write config to real output file
    std::fs::copy(tempfile, output_path).expect("Unable to copy tempfile to output file");

    // reload haproxy
    if *args.get_one::<bool>("reload").unwrap() {
        let mut cmd = std::process::Command::new("systemctl");
        cmd.arg("reload haproxy");
        let output = cmd.output().expect("failed to execute process");
        if !output.status.success() {
            error!("Config reload failed: {}", String::from_utf8_lossy(&output.stderr));
            std::process::exit(1);
        }

        info!("Systemd reload of HAProxy issued");
    }

}

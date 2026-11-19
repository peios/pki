//! pki: manage the Peios certificate authority, through pkid and the
//! Registry. See pki(8).

mod cli;
mod failure;
mod files;
mod host;
mod run;
mod secret;
mod show;

#[cfg(test)]
mod tests;

use std::ffi::OsString;
use std::process::ExitCode;

use clap::error::{ContextKind, ContextValue, ErrorKind};
use clap::FromArgMatches;
use serde_json::json;

use crate::cli::{Cli, Command};
use crate::failure::{Failure, Kind};
use crate::host::{Host, Live};

fn main() -> ExitCode {
    // Exit quietly when output is cut short (`pki ca list | head`).
    // SAFETY: restoring the default disposition of one signal at startup.
    unsafe { libc::signal(libc::SIGPIPE, libc::SIG_DFL) };
    let args: Vec<OsString> = std::env::args_os().collect();
    let json = args
        .iter()
        .skip(1)
        .any(|arg| arg == "-j" || arg == "--json");
    match parse(&args) {
        Ok(cli) => execute(&Live::new(), cli),
        Err(Stop::Print { text, error }) => {
            if error {
                eprint!("{text}");
                ExitCode::from(Kind::Usage.status())
            } else {
                print!("{text}");
                ExitCode::SUCCESS
            }
        }
        Err(Stop::Fail(failure)) => report(&failure, json),
    }
}

/// Why pki stops before running a command.
#[derive(Debug)]
pub enum Stop {
    /// Help or the version, on stdout, or help on stderr for a command run
    /// without the command it needs.
    Print {
        text: String,
        error: bool,
    },
    Fail(Failure),
}

pub fn parse(args: &[OsString]) -> Result<Cli, Stop> {
    let matches = cli::command().try_get_matches_from(args).map_err(stop)?;
    let parsed = Cli::from_arg_matches(&matches).map_err(stop)?;
    if let Command::Help { command } = &parsed.command {
        // `pki help <command>` prints what `pki <command> --help` does.
        let mut again: Vec<OsString> = vec!["pki".into()];
        again.extend(command.iter().map(OsString::from));
        again.push("--help".into());
        return Err(match cli::command().try_get_matches_from(&again) {
            Ok(_) => Stop::Fail(Failure::usage(format!(
                "unknown command '{}'",
                command.join(" ")
            ))),
            Err(error) => stop(error),
        });
    }
    Ok(parsed)
}

fn stop(error: clap::Error) -> Stop {
    match error.kind() {
        ErrorKind::DisplayHelp | ErrorKind::DisplayVersion => Stop::Print {
            text: cli::tidy(&error.render().to_string()),
            error: false,
        },
        ErrorKind::DisplayHelpOnMissingArgumentOrSubcommand => Stop::Print {
            text: cli::tidy(&error.render().to_string()),
            error: true,
        },
        _ => Stop::Fail(Failure::usage(usage_message(&error))),
    }
}

fn context(error: &clap::Error, kind: ContextKind) -> String {
    match error.get(kind) {
        Some(ContextValue::String(text)) => text.clone(),
        Some(ContextValue::Strings(texts)) => texts.join(", "),
        Some(ContextValue::StyledStr(text)) => text.to_string(),
        Some(ContextValue::StyledStrs(texts)) => texts
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(", "),
        Some(ContextValue::Number(number)) => number.to_string(),
        _ => String::new(),
    }
}

/// A usage error in PSC's form: clap's own messages differ.
fn usage_message(error: &clap::Error) -> String {
    let arg = || context(error, ContextKind::InvalidArg);
    let value = || context(error, ContextKind::InvalidValue);
    match error.kind() {
        ErrorKind::InvalidSubcommand => {
            format!(
                "unknown command '{}'",
                context(error, ContextKind::InvalidSubcommand)
            )
        }
        ErrorKind::UnknownArgument => {
            let arg = arg();
            if arg.starts_with('-') {
                format!("unknown option '{arg}'")
            } else {
                format!("unexpected argument '{arg}'")
            }
        }
        ErrorKind::MissingRequiredArgument => {
            let missing: Vec<String> = match error.get(ContextKind::InvalidArg) {
                Some(ContextValue::Strings(items)) => {
                    items.iter().map(|item| alternatives(item)).collect()
                }
                _ => vec![arg()],
            };
            format!("missing {}", missing.join(" and "))
        }
        ErrorKind::MissingSubcommand => "missing command".to_string(),
        ErrorKind::InvalidValue if value().is_empty() => format!("{}: missing value", arg()),
        ErrorKind::InvalidValue => format!(
            "{}: '{}' is not one of {}",
            arg(),
            value(),
            context(error, ContextKind::ValidValue)
        ),
        ErrorKind::ValueValidation => format!("{}: '{}' is not valid", arg(), value()),
        ErrorKind::ArgumentConflict => format!(
            "'{}' cannot be used with '{}'",
            arg(),
            context(error, ContextKind::PriorArg)
        ),
        _ => {
            let text = error.to_string();
            let line = text.lines().next().unwrap_or_default();
            line.trim_start_matches("error: ").to_string()
        }
    }
}

/// A group of options of which one is required, which clap writes as
/// `<--root|--issuer <ca>>`, as `--root or --issuer`.
fn alternatives(item: &str) -> String {
    let Some(inner) = item
        .strip_prefix("<--")
        .and_then(|rest| rest.strip_suffix('>'))
    else {
        return item.to_owned();
    };
    let flags: Vec<String> = format!("--{inner}")
        .split('|')
        .filter_map(|choice| choice.split_whitespace().next())
        .map(str::to_owned)
        .collect();
    match flags.split_last() {
        Some((last, rest)) if !rest.is_empty() => format!("{} or {last}", rest.join(", ")),
        _ => item.to_owned(),
    }
}

fn execute(host: &dyn Host, cli: Cli) -> ExitCode {
    match run::run(host, cli.command) {
        Ok(output) => {
            if cli.json {
                println!("{}", output.json);
            } else {
                print!("{}", output.text);
            }
            ExitCode::SUCCESS
        }
        Err(failure) => report(&failure, cli.json),
    }
}

fn report(failure: &Failure, json: bool) -> ExitCode {
    if json {
        eprintln!(
            "{}",
            json!({"error": {"code": failure.kind.tag(), "message": failure.message}})
        );
    } else {
        eprintln!("pki: {}", failure.message);
        match &failure.hint {
            Some(hint) => eprintln!("{hint}"),
            None if failure.kind == Kind::Usage => {
                eprintln!("Try 'pki --help' for more information.")
            }
            None => {}
        }
    }
    ExitCode::from(failure.kind.status())
}

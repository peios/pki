//! pki's commands and options. clap builds the help from these definitions;
//! [`command`] gives every command the help layout PSC sets out.

use std::path::PathBuf;

use clap::{Args, CommandFactory, Parser, Subcommand};

/// The help layout, after the description.
const TEMPLATE: &str = "{about}\n\n{usage-heading} {usage}\n\n{all-args}\n\nSee pki(8).";

/// The default lifetime of a root CA, in days.
pub const ROOT_LIFETIME_DAYS: u32 = 3650;
/// The default lifetime of any other CA certificate, in days.
pub const SUBORDINATE_LIFETIME_DAYS: u32 = 1825;

#[derive(Debug, Parser)]
#[command(
    name = "pki",
    about = "Manage the Peios certificate authority",
    version,
    override_usage = "pki [options] <command>"
)]
pub struct Cli {
    /// Print output as JSON
    #[arg(short, long, global = true)]
    pub json: bool,

    #[command(subcommand)]
    pub command: Command,
}

// Parsed once per run; its size doesn't matter.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Subcommand)]
pub enum Command {
    /// Prepare this machine for pkid
    Setup,
    /// Create and manage CAs
    #[command(subcommand)]
    Ca(Ca),
    /// Submit certificate requests, and approve or deny them
    #[command(subcommand)]
    Request(RequestCommand),
    /// Find and revoke issued certificates
    #[command(subcommand)]
    Cert(Cert),
    /// Make a key here, have it certified, and save both as PKCS #12
    Enroll(Enroll),
    /// Define the kinds of certificate CAs issue
    #[command(subcommand)]
    Template(TemplateCommand),
    /// Decide who can request certificates for which names
    #[command(subcommand)]
    Name(NameCommand),
    /// Print help for pki or one of its commands
    #[command(override_usage = "pki help [<command>]")]
    Help {
        /// The command to print help for
        #[arg(value_name = "command")]
        command: Vec<String>,
    },
}

#[derive(Debug, Subcommand)]
pub enum Ca {
    /// List the CAs
    List,
    /// Show a CA
    Show {
        /// The CA, by name or ID
        #[arg(value_name = "ca")]
        ca: String,
        /// Write its certificate, or its pending request, to a file
        #[arg(short, long, value_name = "file")]
        out: Option<PathBuf>,
    },
    /// Create a CA with a new key
    Create(Create),
    /// Sign a subordinate CA's request for a CA elsewhere
    Sign {
        /// The CA to sign with
        #[arg(value_name = "ca")]
        ca: String,
        /// The subordinate CA's request, in PEM or DER
        #[arg(value_name = "request-file")]
        request: PathBuf,
        /// Name the subordinate CA
        #[arg(long, value_name = "name")]
        name: String,
        /// Set its lifetime in days (default: 1825)
        #[arg(long, value_name = "days", default_value_t = SUBORDINATE_LIFETIME_DAYS, hide_default_value = true)]
        lifetime: u32,
        /// Limit how many CAs can sit below it
        #[arg(long, value_name = "count")]
        path_length: Option<u8>,
        /// Write the certificate to a file (default: standard output)
        #[arg(short, long, value_name = "file")]
        out: Option<PathBuf>,
        /// Read the CA key's passphrase from a file
        #[arg(long, value_name = "file")]
        passphrase_file: Option<PathBuf>,
    },
    /// Install the certificate a CA awaits
    Install {
        /// The CA awaiting its certificate
        #[arg(value_name = "ca")]
        ca: String,
        /// The certificate, in PEM or DER
        #[arg(value_name = "certificate-file")]
        certificate: PathBuf,
    },
    /// Take up an existing CA from its certificate and sealed key
    Import(Import),
    /// Export a CA's key as a sealed key file
    ExportKey {
        /// The CA whose key to export
        #[arg(value_name = "ca")]
        ca: String,
        /// The sealed key file to write
        #[arg(value_name = "file")]
        out: PathBuf,
        /// Read the key's current passphrase from a file
        #[arg(long, value_name = "file")]
        passphrase_file: Option<PathBuf>,
        /// Read the exported file's passphrase from a file
        #[arg(long, value_name = "file")]
        new_passphrase_file: Option<PathBuf>,
    },
    /// Change which templates a CA issues and where its CRL is published
    Set(Set),
}

#[derive(Debug, Subcommand)]
pub enum RequestCommand {
    /// Submit a certificate request
    Submit {
        /// The CA to ask
        #[arg(value_name = "ca")]
        ca: String,
        /// The template to issue from, by name or GUID
        #[arg(value_name = "template")]
        template: String,
        /// The request, in PEM or DER
        #[arg(value_name = "request-file")]
        request: PathBuf,
        /// Write the certificate to a file (default: standard output)
        #[arg(short, long, value_name = "file")]
        out: Option<PathBuf>,
    },
    /// List a CA's requests, oldest first
    List {
        /// The CA, by name or ID
        #[arg(value_name = "ca")]
        ca: String,
        /// List only requests that are pending, issued or denied
        #[arg(
            long,
            value_name = "status",
            value_parser = ["pending", "issued", "denied"],
            hide_possible_values = true,
        )]
        status: Option<String>,
    },
    /// Show a request
    Show {
        /// The CA, by name or ID
        #[arg(value_name = "ca")]
        ca: String,
        /// The request's number
        #[arg(value_name = "request")]
        request: i64,
    },
    /// Approve a pending request, issuing its certificate
    Approve {
        /// The CA, by name or ID
        #[arg(value_name = "ca")]
        ca: String,
        /// The request's number
        #[arg(value_name = "request")]
        request: i64,
        /// Write the certificate to a file
        #[arg(short, long, value_name = "file")]
        out: Option<PathBuf>,
    },
    /// Deny a pending request
    Deny {
        /// The CA, by name or ID
        #[arg(value_name = "ca")]
        ca: String,
        /// The request's number
        #[arg(value_name = "request")]
        request: i64,
        /// Record why
        #[arg(long, value_name = "text")]
        reason: Option<String>,
    },
}

#[derive(Debug, Subcommand)]
pub enum Cert {
    /// List the certificates a CA has issued
    List {
        /// The CA, by name or ID
        #[arg(value_name = "ca")]
        ca: String,
        /// Leave out revoked certificates
        #[arg(long)]
        unrevoked: bool,
    },
    /// Show a certificate
    Show {
        /// The CA, by name or ID
        #[arg(value_name = "ca")]
        ca: String,
        /// The certificate's serial number, in hex
        #[arg(value_name = "serial")]
        serial: String,
        /// Write the certificate to a file
        #[arg(short, long, value_name = "file")]
        out: Option<PathBuf>,
    },
    /// Fetch the certificate issued for a request
    Get {
        /// The CA, by name or ID
        #[arg(value_name = "ca")]
        ca: String,
        /// The request's number
        #[arg(value_name = "request")]
        request: i64,
        /// Write the certificate to a file (default: standard output)
        #[arg(short, long, value_name = "file")]
        out: Option<PathBuf>,
    },
    /// Revoke a certificate
    Revoke {
        /// The CA, by name or ID
        #[arg(value_name = "ca")]
        ca: String,
        /// The certificate's serial number, in hex
        #[arg(value_name = "serial")]
        serial: String,
        /// Give the reason, as RFC 5280 names it (default: unspecified)
        #[arg(
            long,
            value_name = "reason",
            default_value = "unspecified",
            hide_default_value = true,
            value_parser = REASONS.map(|(name, _)| name),
            hide_possible_values = true,
        )]
        reason: String,
    },
}

#[derive(Debug, Subcommand)]
pub enum TemplateCommand {
    /// List the templates
    List,
    /// Show a template
    Show {
        /// The template, by name or GUID
        #[arg(value_name = "template")]
        template: String,
    },
    /// Create a template
    Create {
        /// The new template's name
        #[arg(value_name = "name")]
        name: String,
        /// Start from a copy of another template
        #[arg(long, value_name = "template")]
        from: Option<String>,
        #[command(flatten)]
        fields: TemplateFields,
    },
    /// Change a template
    Set {
        /// The template, by name or GUID
        #[arg(value_name = "template")]
        template: String,
        /// Rename it
        #[arg(long, value_name = "name")]
        name: Option<String>,
        #[command(flatten)]
        fields: TemplateFields,
    },
    /// Delete a template no CA issues from
    Delete {
        /// The template, by name or GUID
        #[arg(value_name = "template")]
        template: String,
    },
}

/// A template's values, as given to create or change it. Each list given
/// replaces the template's list.
#[derive(Debug, Args)]
pub struct TemplateFields {
    /// Give certificates an extended key usage; repeat for more
    #[arg(long = "purpose", value_name = "purpose")]
    pub purposes: Vec<String>,
    /// Give certificates a key usage; repeat for more
    #[arg(long = "key-usage", value_name = "usage")]
    pub key_usages: Vec<String>,
    /// Set how long certificates last, in days
    #[arg(long, value_name = "days")]
    pub lifetime: Option<u32>,
    /// Set how many days before expiry renewal is due
    #[arg(long, value_name = "days")]
    pub renewal_window: Option<u32>,
    /// Accept a kind of key in requests; repeat for more
    #[arg(long = "key-algorithm", value_name = "algorithm")]
    pub key_algorithms: Vec<String>,
    /// Allow a kind of name in certificates; repeat for more
    #[arg(
        long = "name-type",
        value_name = "type",
        value_parser = ["dns", "email", "upn"],
        hide_possible_values = true,
    )]
    pub name_types: Vec<String>,
    /// Choose where the common name comes from
    #[arg(
        long,
        value_name = "source",
        value_parser = ["none", "first-name", "owner-display-name"],
        hide_possible_values = true,
    )]
    pub common_name: Option<String>,
    /// Issue at once or hold every request for approval
    #[arg(
        long,
        value_name = "issuance",
        value_parser = ["immediate", "approval"],
        hide_possible_values = true,
    )]
    pub issuance: Option<String>,
    /// Set who can enroll, as SDDL
    #[arg(long, value_name = "sddl")]
    pub enroll_security: Option<String>,
}

impl TemplateFields {
    pub fn is_empty(&self) -> bool {
        self.purposes.is_empty()
            && self.key_usages.is_empty()
            && self.lifetime.is_none()
            && self.renewal_window.is_none()
            && self.key_algorithms.is_empty()
            && self.name_types.is_empty()
            && self.common_name.is_none()
            && self.issuance.is_none()
            && self.enroll_security.is_none()
    }
}

#[derive(Debug, Subcommand)]
pub enum NameCommand {
    /// List the names with settings of their own
    List,
    /// Show who can request a name, and who owns it
    Show {
        /// The name, such as lab.home, jack@home or @home
        #[arg(value_name = "name")]
        name: String,
    },
    /// Add a name to a tree
    Add {
        /// The name, such as lab.home, jack@home or @home
        #[arg(value_name = "name")]
        name: String,
        /// Make a principal the name's owner, by SID
        #[arg(long, value_name = "sid")]
        owner: Option<String>,
    },
    /// Remove a name with no names below it
    Remove {
        /// The name, such as lab.home, jack@home or @home
        #[arg(value_name = "name")]
        name: String,
    },
    /// Set who can request a name and the names below it
    #[command(override_usage = "pki name set-security [options] <name> <sddl>
       pki name set-security [options] <name> --inherit")]
    SetSecurity {
        /// The name, such as lab.home, jack@home or @home
        #[arg(value_name = "name")]
        name: String,
        /// The descriptor, as SDDL
        #[arg(value_name = "sddl", required_unless_present = "inherit")]
        sddl: Option<String>,
        /// Remove the name's own descriptor, so it inherits again
        #[arg(long, conflicts_with = "sddl")]
        inherit: bool,
    },
    /// Set or clear a name's owner
    #[command(override_usage = "pki name set-owner [options] <name> <sid>
       pki name set-owner [options] <name> --none")]
    SetOwner {
        /// The name, such as lab.home, jack@home or @home
        #[arg(value_name = "name")]
        name: String,
        /// The owner, by SID
        #[arg(value_name = "sid", required_unless_present = "none")]
        owner: Option<String>,
        /// Leave the name with no owner
        #[arg(long, conflicts_with = "owner")]
        none: bool,
    },
}

/// The revocation reasons pki offers, with their RFC 5280 codes.
/// certificateHold is left out: pkid can't release a hold, so it would be
/// a permanent revocation under a temporary name.
pub const REASONS: [(&str, u8); 7] = [
    ("unspecified", 0),
    ("key-compromise", 1),
    ("ca-compromise", 2),
    ("affiliation-changed", 3),
    ("superseded", 4),
    ("cessation-of-operation", 5),
    ("privilege-withdrawn", 9),
];

#[derive(Debug, Args)]
#[command(
    override_usage = "pki enroll [options] <ca> <template> --out <file> <names>
       pki enroll [options] <ca> --request <request> --key <file> --out <file>"
)]
pub struct Enroll {
    /// The CA to ask
    #[arg(value_name = "ca")]
    pub ca: String,
    /// The template to issue from, by name or GUID
    #[arg(value_name = "template", required_unless_present = "request")]
    pub template: Option<String>,
    /// Name a host; repeat for more
    #[arg(long = "dns", value_name = "name", conflicts_with = "request")]
    pub dns: Vec<String>,
    /// Name an email address; repeat for more
    #[arg(long = "email", value_name = "address", conflicts_with = "request")]
    pub emails: Vec<String>,
    /// Name a user principal, such as for EAP-TLS; repeat for more
    #[arg(long = "upn", value_name = "name", conflicts_with = "request")]
    pub upns: Vec<String>,
    /// Write the key and its certificates to this PKCS #12 file
    #[arg(short, long, value_name = "file")]
    pub out: PathBuf,
    /// Choose the key algorithm (default: ecdsa-p256)
    #[arg(
        long,
        value_name = "algorithm",
        default_value = "ecdsa-p256",
        hide_default_value = true,
        value_parser = ["ecdsa-p256", "ecdsa-p384", "rsa-2048", "rsa-3072", "rsa-4096"],
        hide_possible_values = true,
        conflicts_with = "request",
    )]
    pub algorithm: String,
    /// Label the key in the file (default: the first name)
    #[arg(long, value_name = "text")]
    pub friendly_name: Option<String>,
    /// Collect the certificate for a request that was held for approval
    #[arg(
        long,
        value_name = "request",
        requires = "key",
        conflicts_with = "template"
    )]
    pub request: Option<i64>,
    /// The key pki enroll sealed while the request was held
    #[arg(long, value_name = "file", requires = "request")]
    pub key: Option<PathBuf>,
    /// Read the passphrase from a file
    #[arg(long, value_name = "file")]
    pub passphrase_file: Option<PathBuf>,
}

/// Who signs a new CA's certificate.
#[derive(Debug, Args)]
#[group(required = true, multiple = false)]
pub struct Issuer {
    /// Make it a root, signing its own certificate
    #[arg(long)]
    pub root: bool,
    /// Have a CA on this pkid sign it
    #[arg(long, value_name = "ca")]
    pub issuer: Option<String>,
    /// Write a request for a CA elsewhere to sign
    #[arg(long, value_name = "request-file")]
    pub offline: Option<PathBuf>,
}

/// What a CA issues, as given when it is created or imported.
#[derive(Debug, Args)]
pub struct Issuing {
    /// Issue from a template; repeat for more
    #[arg(long = "template", value_name = "template")]
    pub templates: Vec<String>,
    /// Name a CRL distribution point; repeat for more
    #[arg(long = "crl", value_name = "url")]
    pub crls: Vec<String>,
}

/// Where a CA's key is kept.
#[derive(Debug, Args)]
pub struct Keeping {
    /// Keep the key in a sealed file instead of pkid's store
    #[arg(long, value_name = "path")]
    pub key_file: Option<PathBuf>,
    /// Let a key in pkid's store be exported
    #[arg(long)]
    pub exportable: bool,
}

#[derive(Debug, Args)]
#[command(override_usage = "pki ca create [options] --root <name>
       pki ca create [options] --issuer <ca> <name>
       pki ca create [options] --offline <request-file> <name>")]
pub struct Create {
    /// The new CA's name
    #[arg(value_name = "name")]
    pub name: String,
    #[command(flatten)]
    pub issuer: Issuer,
    #[command(flatten)]
    pub keeping: Keeping,
    /// Choose the key algorithm (default: ecdsa-p384)
    #[arg(
        long,
        value_name = "algorithm",
        default_value = "ecdsa-p384",
        hide_default_value = true,
        value_parser = ["ecdsa-p256", "ecdsa-p384", "rsa-2048", "rsa-3072", "rsa-4096"],
        hide_possible_values = true,
    )]
    pub algorithm: String,
    /// Set its lifetime in days (default: 3650 for a root, 1825 otherwise)
    #[arg(long, value_name = "days")]
    pub lifetime: Option<u32>,
    /// Limit how many CAs can sit below it
    #[arg(long, value_name = "count")]
    pub path_length: Option<u8>,
    #[command(flatten)]
    pub issuing: Issuing,
    /// Read the new key file's passphrase from a file
    #[arg(long, value_name = "file", requires = "key_file")]
    pub passphrase_file: Option<PathBuf>,
    /// Read the issuing CA key's passphrase from a file
    #[arg(long, value_name = "file", requires = "issuer")]
    pub issuer_passphrase_file: Option<PathBuf>,
}

#[derive(Debug, Args)]
pub struct Import {
    /// The CA's name
    #[arg(value_name = "name")]
    pub name: String,
    /// The CA's certificate, in PEM or DER
    #[arg(value_name = "certificate-file")]
    pub certificate: PathBuf,
    /// The CA's key, as pki ca export-key writes it
    #[arg(value_name = "sealed-key-file")]
    pub sealed_key: PathBuf,
    #[command(flatten)]
    pub keeping: Keeping,
    #[command(flatten)]
    pub issuing: Issuing,
    /// Read the sealed key file's passphrase from a file
    #[arg(long, value_name = "file")]
    pub passphrase_file: Option<PathBuf>,
    /// Read the new key file's passphrase from a file
    #[arg(long, value_name = "file", requires = "key_file")]
    pub new_passphrase_file: Option<PathBuf>,
}

#[derive(Debug, Args)]
pub struct Set {
    /// The CA to change
    #[arg(value_name = "ca")]
    pub ca: String,
    /// Issue from these templates only; repeat for more
    #[arg(
        long = "template",
        value_name = "template",
        conflicts_with = "no_templates"
    )]
    pub templates: Vec<String>,
    /// Issue from no templates
    #[arg(long)]
    pub no_templates: bool,
    /// Publish these CRL distribution points only; repeat for more
    #[arg(long = "crl", value_name = "url", conflicts_with = "no_crls")]
    pub crls: Vec<String>,
    /// Publish no CRL distribution points
    #[arg(long)]
    pub no_crls: bool,
}

/// pki's command tree, with every command given the help layout.
pub fn command() -> clap::Command {
    fn shape(command: clap::Command) -> clap::Command {
        let names: Vec<String> = command
            .get_subcommands()
            .map(|sub| sub.get_name().to_owned())
            .collect();
        let command = command
            .help_template(TEMPLATE)
            .term_width(80)
            .disable_help_subcommand(true)
            .subcommand_value_name("command")
            .subcommand_help_heading("Commands")
            // A command with commands of its own, run alone, prints its help.
            .arg_required_else_help(!names.is_empty());
        names
            .iter()
            .fold(command, |command, name| command.mut_subcommand(name, shape))
    }
    shape(Cli::command())
}

/// clap writes the options placeholder in capitals; PSC writes it in
/// lowercase.
pub fn tidy(text: &str) -> String {
    let mut text = text.replace("[OPTIONS]", "[options]");
    if !text.ends_with('\n') {
        text.push('\n');
    }
    text
}

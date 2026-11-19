//! Building the certificate profile for an approved request.

use pki_core::{CommonName, DisplayName, LeafProfile, LeafSubject, Validity};
use time::{Duration, OffsetDateTime};

use crate::evaluate::{Decision, Outcome};
use crate::template::{CommonNameRule, Template};
use crate::PolicyError;

/// How far before issuance a certificate becomes valid, so verifiers with
/// slightly slow clocks accept it at once.
const CLOCK_SKEW_ALLOWANCE: Duration = Duration::minutes(5);

/// What the CA supplies when issuing, besides the template and decision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IssueContext {
    pub now: OffsetDateTime,
    /// When the issuing CA's own certificate expires. Certificates never
    /// outlive their issuer, so lifetimes are cut short to it.
    pub issuer_not_after: OffsetDateTime,
    pub crl_distribution_points: Vec<String>,
    /// The `SidSecurityExtension` setting. On by default.
    pub sid_extension: bool,
}

/// Builds the profile for a request whose decision is to issue, or which an
/// officer approved.
///
/// `owner_display_name` must come from identity data about `decision.owner`
/// (authd or a directory), never from the request. It is only used when the
/// template's common-name rule asks for it.
pub fn leaf_profile(
    template: &Template,
    decision: &Decision,
    owner_display_name: Option<&DisplayName>,
    context: &IssueContext,
) -> Result<LeafProfile, PolicyError> {
    if decision.outcome == Outcome::Reject {
        return Err(PolicyError::Profile("the request was refused".into()));
    }
    let alt_names = decision.approved_names();
    let common_name = match template.common_name {
        CommonNameRule::None => None,
        CommonNameRule::FirstName => alt_names.first().cloned().map(CommonName::Name),
        CommonNameRule::OwnerDisplayName => {
            if decision.owner.is_none() {
                return Err(PolicyError::Profile(format!(
                    "{} needs the names to have a single owner",
                    template.name
                )));
            }
            let display = owner_display_name.ok_or_else(|| {
                PolicyError::Profile("the owner's display name is not available".into())
            })?;
            Some(CommonName::DisplayName(display.clone()))
        }
    };
    let not_before = context.now - CLOCK_SKEW_ALLOWANCE;
    let not_after = (context.now + template.lifetime).min(context.issuer_not_after);
    let validity = Validity::new(not_before, not_after)
        .map_err(|_| PolicyError::Profile("the issuing CA expires too soon".into()))?;
    Ok(LeafProfile {
        subject: LeafSubject {
            common_name,
            attributes: Vec::new(),
        },
        alt_names,
        key_usages: template.key_usages.clone(),
        extended_key_usages: template.purposes.clone(),
        validity,
        owner_sid: if context.sid_extension {
            decision.owner.clone()
        } else {
            None
        },
        crl_distribution_points: context.crl_distribution_points.clone(),
    })
}

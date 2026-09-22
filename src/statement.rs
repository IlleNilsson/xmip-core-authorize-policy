//! A statement: one effect, and the who, what and where it applies to.

use authorize::{Action, Attempt};
use context::IdentityFacts;
use serde::{Deserialize, Deserializer};
use xcore::PartyId;

/// What a statement concludes where it applies.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum Effect {
    /// The attempt is allowed, unless a denying statement also applies.
    Permit,
    /// The attempt is refused.
    Deny,
}

/// A claim the identity must carry: evidence the gate recorded, by name.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Claim {
    /// The name the gate recorded it under — `department`, `scope`.
    pub name: String,
    /// The value it must have, exactly.
    pub value: String,
}

/// One statement of the document.
///
/// Every key but `name` and `effect` is optional, and a key left out applies
/// to everything: a statement that says only `effect = "deny"` and
/// `action = "send"` denies every send by anyone anywhere. The keys that are
/// there must all match.
///
/// ```toml
/// [[statement]]
/// name = "partners-receive"
/// effect = "permit"
/// mechanism = "mutual-tls"                         # who
/// party = "00000000-0000-0000-0000-000000000007"
/// claim = { name = "department", value = "edi" }
/// action = "receive"                               # what
/// location = "partner-*"                           # where
/// ```
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Statement {
    /// The name a denial by this statement carries.
    pub name: String,
    /// Permit or deny.
    pub effect: Effect,
    /// Who, by the name of the mechanism the transport identity was proven by.
    #[serde(default)]
    pub mechanism: Option<String>,
    /// Who, by the Party the transport identity resolved to.
    #[serde(default)]
    pub party: Option<PartyId>,
    /// Who, by a claim either identity carries.
    #[serde(default)]
    pub claim: Option<Claim>,
    /// What: `receive`, `process` or `send`.
    #[serde(default, deserialize_with = "action")]
    pub action: Option<Action>,
    /// Where, by artifact: a name, or every name under a prefix when it ends
    /// in `*`.
    #[serde(default)]
    pub artifact: Option<String>,
    /// Where, by Location: as `artifact`, and only where the attempt
    /// receives or sends, because an Xmip Process is not a Location.
    #[serde(default)]
    pub location: Option<String>,
}

impl Statement {
    /// Whether the statement applies to this identity attempting this.
    #[must_use]
    pub fn applies(&self, identity: &IdentityFacts, attempt: &Attempt) -> bool {
        self.who(identity) && self.what(attempt) && self.place(attempt)
    }

    fn who(&self, identity: &IdentityFacts) -> bool {
        let accountable = identity.accountable();

        let mechanism = self
            .mechanism
            .as_ref()
            .is_none_or(|name| accountable.mechanism.name() == name);
        let party = self
            .party
            .is_none_or(|party| accountable.party_id == Some(party));
        let claim = self.claim.as_ref().is_none_or(|claim| {
            std::iter::once(accountable)
                .chain(identity.message.as_ref())
                .flat_map(|held| held.evidence.iter())
                .any(|(name, value)| *name == claim.name && *value == claim.value)
        });

        mechanism && party && claim
    }

    fn what(&self, attempt: &Attempt) -> bool {
        self.action.is_none_or(|action| action == attempt.action)
    }

    fn place(&self, attempt: &Attempt) -> bool {
        let artifact = self
            .artifact
            .as_ref()
            .is_none_or(|pattern| authorize::pattern::matches(pattern, &attempt.artifact));
        let location = self.location.as_ref().is_none_or(|pattern| {
            attempt.action != Action::Process
                && authorize::pattern::matches(pattern, &attempt.artifact)
        });

        artifact && location
    }
}

/// `authorize::Action` is the capability's and is not a serde type, so the
/// three words are read here and anything else is refused by name.
fn action<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Option<Action>, D::Error> {
    let word = String::deserialize(deserializer)?;

    match word.as_str() {
        "receive" => Ok(Some(Action::Receive)),
        "process" => Ok(Some(Action::Process)),
        "send" => Ok(Some(Action::Send)),
        other => Err(serde::de::Error::custom(format!(
            "unknown action '{other}': an action is receive, process or send"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use context::{Alignment, AuthenticatedIdentity, Verified};
    use xcore::{Established, mechanism};

    fn partner() -> IdentityFacts {
        IdentityFacts::evaluate(
            Alignment::None,
            AuthenticatedIdentity::new(
                mechanism::mutual_tls(),
                "CN=partner-x.example",
                Established::Passed,
                Verified::Proven,
            )
            .resolving_to(PartyId::new(7))
            .with_evidence("department", "edi"),
            None,
        )
    }

    fn statement(text: &str) -> Statement {
        toml::from_str(text).expect("a statement")
    }

    #[test]
    fn every_key_that_is_there_must_match_and_a_key_left_out_matches_everything() {
        let narrow = statement(
            r#"
            name = "partners-receive"
            effect = "permit"
            mechanism = "mutual-tls"
            party = "00000000-0000-0000-0000-000000000007"
            claim = { name = "department", value = "edi" }
            action = "receive"
            location = "partner-*"
            "#,
        );
        let wide = statement("name = \"everything\"\neffect = \"deny\"");

        assert!(narrow.applies(&partner(), &Attempt::new(Action::Receive, "partner-x")));
        assert!(!narrow.applies(&partner(), &Attempt::new(Action::Send, "partner-x")));
        assert!(!narrow.applies(&partner(), &Attempt::new(Action::Receive, "Billing")));
        assert!(wide.applies(&partner(), &Attempt::new(Action::Process, "Approval")));
        assert_eq!(wide.effect, Effect::Deny);
    }

    #[test]
    fn who_is_the_mechanism_the_party_and_a_claim() {
        let other_party = statement(
            "name = \"a\"\neffect = \"permit\"\nparty = \"00000000-0000-0000-0000-000000000008\"",
        );
        let other_mechanism = statement("name = \"b\"\neffect = \"permit\"\nmechanism = \"jwt\"");
        let other_claim = statement(
            "name = \"c\"\neffect = \"permit\"\nclaim = { name = \"department\", value = \"hr\" }",
        );
        let attempt = Attempt::new(Action::Receive, "partner-x");

        assert!(!other_party.applies(&partner(), &attempt));
        assert!(!other_mechanism.applies(&partner(), &attempt));
        assert!(!other_claim.applies(&partner(), &attempt));
    }

    #[test]
    fn an_artifact_is_exact_or_a_prefix_and_a_process_is_not_a_location() {
        let exact = statement("name = \"a\"\neffect = \"permit\"\nartifact = \"Billing\"");
        let under = statement("name = \"b\"\neffect = \"permit\"\nlocation = \"Billing*\"");

        assert!(exact.applies(&partner(), &Attempt::new(Action::Process, "Billing")));
        assert!(!exact.applies(&partner(), &Attempt::new(Action::Process, "Billing-EU")));
        assert!(under.applies(&partner(), &Attempt::new(Action::Send, "Billing-EU")));
        assert!(!under.applies(&partner(), &Attempt::new(Action::Process, "Billing-EU")));
    }
}

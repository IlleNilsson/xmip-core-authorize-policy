#![forbid(unsafe_code)]

//! The policy authorize technology — a technology of `xmip-core-authorize`.
//!
//! One policy at the transport layer: a declarative policy document in the
//! estate's own TOML (ADR-0050 section 5). The [`Document`] is a list of
//! [`Statement`]s, each with an effect — permit or deny — and what it
//! applies to: who (the mechanism, the Party, a claim), what (the action)
//! and where (the artifact or the Location, by name or by prefix).
//!
//! The document is read once, at load, and read strictly: a key nobody reads
//! is refused with its name and never ignored, because a policy with a
//! misspelled `effect` that loads is a policy that is not the one its author
//! wrote. At the gate, deny wins: any denying statement that applies refuses
//! the attempt, naming the statement, however many others permit; failing
//! that, a permitting statement that applies allows; where no statement
//! applies the policy has no opinion and the question is the next policy's.
//!
//! The vocabulary is this crate's own and small. A rule about roles, scopes
//! or Contracts is `rbac`'s, `scope`'s or `contract`'s to decide; this
//! depends on none of them (ADR-0050 section 6).

pub mod statement;

use authorize::{Attempt, AuthorizeError, Authorizer, Decision};
use context::IdentityFacts;
use serde::Deserialize;
use xcore::Layer;

pub use statement::{Claim, Effect, Statement};

/// The manifest leaf, and the name a denial carries.
pub const NAME: &str = "policy";

/// A policy document, loaded.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Document {
    #[serde(default, rename = "statement")]
    statements: Vec<Statement>,
}

impl Document {
    /// Load a document from its TOML text.
    ///
    /// # Errors
    ///
    /// Refuses text that is not TOML, a key the document does not define —
    /// naming it — an effect that is not `permit` or `deny`, an action that
    /// is not `receive`, `process` or `send`, a Party that is not an
    /// identifier, a statement with an empty name, and two statements with
    /// one name, since a denial names the statement and must name one.
    pub fn load(text: &str) -> Result<Self, AuthorizeError> {
        let document: Self = toml::from_str(text).map_err(|refused| {
            AuthorizeError::new(format!("the policy document is refused: {refused}"))
        })?;

        for (index, statement) in document.statements.iter().enumerate() {
            if statement.name.trim().is_empty() {
                return Err(AuthorizeError::new(format!(
                    "the policy document is refused: statement {} has an empty name",
                    index + 1
                )));
            }

            let earlier = &document.statements[..index];
            if earlier.iter().any(|other| other.name == statement.name) {
                return Err(AuthorizeError::new(format!(
                    "the policy document is refused: two statements are named '{}'",
                    statement.name
                )));
            }
        }

        Ok(document)
    }

    /// The statements, in the document's order.
    #[must_use]
    pub fn statements(&self) -> &[Statement] {
        &self.statements
    }
}

impl Authorizer for Document {
    fn name(&self) -> &str {
        NAME
    }

    fn layer(&self) -> Layer {
        Layer::Transport
    }

    fn decide(&self, identity: &IdentityFacts, attempt: &Attempt) -> Option<Decision> {
        let mut applying = self
            .statements
            .iter()
            .filter(|statement| statement.applies(identity, attempt))
            .peekable();

        applying.peek()?;

        let denial = applying.find(|statement| statement.effect == Effect::Deny);

        Some(denial.map_or(Decision::Allowed, |statement| {
            Decision::denied(
                NAME,
                format!(
                    "statement '{}' denies {} on '{}'",
                    statement.name, attempt.action, attempt.artifact
                ),
            )
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use authorize::Action;
    use context::{Alignment, AuthenticatedIdentity, Verified};
    use xcore::{Established, PartyId, mechanism};

    const DOCUMENT: &str = r#"
        [[statement]]
        name = "partners-receive"
        effect = "permit"
        mechanism = "mutual-tls"
        action = "receive"
        location = "partner-*"

        [[statement]]
        name = "party-seven-sends-billing"
        effect = "permit"
        party = "00000000-0000-0000-0000-000000000007"
        action = "send"
        artifact = "Billing"

        [[statement]]
        name = "contractors-never-send"
        effect = "deny"
        claim = { name = "employment", value = "contractor" }
        action = "send"
    "#;

    fn partner(employment: &str) -> IdentityFacts {
        IdentityFacts::evaluate(
            Alignment::None,
            AuthenticatedIdentity::new(
                mechanism::mutual_tls(),
                "CN=partner-x.example",
                Established::Passed,
                Verified::Proven,
            )
            .resolving_to(PartyId::new(7))
            .with_evidence("employment", employment),
            None,
        )
    }

    fn document() -> Document {
        Document::load(DOCUMENT).expect("the document loads")
    }

    #[test]
    fn a_permitting_statement_that_applies_allows() {
        let decision = document().decide(
            &partner("staff"),
            &Attempt::new(Action::Receive, "partner-x"),
        );

        assert_eq!(decision, Some(Decision::Allowed));
        assert_eq!(document().name(), "policy");
        assert_eq!(document().layer(), Layer::Transport);
        assert_eq!(document().statements().len(), 3);
    }

    #[test]
    fn deny_wins_and_names_the_statement_wherever_it_stands_in_the_document() {
        // Party 7 may send Billing, and the statement saying so comes first;
        // the contractor statement after it still refuses.
        let decision = document()
            .decide(
                &partner("contractor"),
                &Attempt::new(Action::Send, "Billing"),
            )
            .expect("an opinion");

        assert_eq!(
            decision.to_string(),
            "denied by policy: statement 'contractors-never-send' denies send on 'Billing'"
        );
        assert_eq!(
            document().decide(&partner("staff"), &Attempt::new(Action::Send, "Billing")),
            Some(Decision::Allowed)
        );
    }

    #[test]
    fn nothing_applying_is_no_opinion() {
        assert_eq!(
            document().decide(
                &partner("staff"),
                &Attempt::new(Action::Process, "Approval")
            ),
            None
        );
        assert_eq!(
            Document::load("")
                .expect("an empty document loads")
                .decide(&partner("staff"), &Attempt::new(Action::Send, "Billing")),
            None
        );
    }

    #[test]
    fn an_unknown_key_is_refused_at_load_with_its_name_and_never_ignored() {
        let misspelled =
            Document::load("[[statement]]\nname = \"a\"\neffect = \"deny\"\nacton = \"send\"\n")
                .expect_err("a key nobody reads");
        let top_level = Document::load("[[rule]]\nname = \"a\"\n").expect_err("no such table");
        let in_claim = Document::load(
            "[[statement]]\nname = \"a\"\neffect = \"deny\"\n\
             claim = { name = \"n\", value = \"v\", issuer = \"i\" }\n",
        )
        .expect_err("a key nobody reads");

        assert!(misspelled.message.contains("acton"), "{misspelled}");
        assert!(top_level.message.contains("rule"), "{top_level}");
        assert!(in_claim.message.contains("issuer"), "{in_claim}");
    }

    #[test]
    fn a_document_that_does_not_say_what_it_means_is_refused_at_load() {
        let refused = |text: &str| Document::load(text).expect_err("refused").message;

        assert!(
            refused("[[statement]]\nname = \"a\"\neffect = \"allow\"\n").contains("allow"),
            "an effect is permit or deny"
        );
        assert!(
            refused("[[statement]]\nname = \"a\"\neffect = \"deny\"\naction = \"publish\"\n")
                .contains("unknown action 'publish'")
        );
        assert!(refused("[[statement]]\neffect = \"deny\"\n").contains("name"));
        assert!(refused("[[statement]]\nname = \" \"\neffect = \"deny\"\n").contains("empty name"));
        assert!(
            refused(
                "[[statement]]\nname = \"a\"\neffect = \"deny\"\n\
                 [[statement]]\nname = \"a\"\neffect = \"permit\"\n"
            )
            .contains("two statements are named 'a'")
        );
        assert!(
            refused("[[statement]]\nname = \"a\"\neffect = \"deny\"\nparty = \"seven\"\n")
                .contains("the policy document is refused")
        );
    }
}

//! refusal — the words `mandu-exec-box` prints when it refuses a HumanShell
//! exec whose approval was withheld (docs/design/integrity/exec-routing.md §5, "The
//! refusal message"; release checklist d5 in packaging.md). PURE: no
//! privileges, in the default build, unit-tested here. The bin itself is
//! `required-features = ["kernel"]`, so the text lives in this module where a
//! plain `cargo test` reaches it.
//!
//! The message says what actually happened, per withheld approval kind, in the
//! dashboard product page's vocabulary (placeholder, your OK, the dashboard
//! Inbox), mirroring exec-wrap's `plainApproval` (`interceptors/exec-wrap/src/
//! gate.ts`) so the two exec block messages read alike:
//!   - `secret_symbol` (confidentiality §7.1): a secret's real value would have
//!     gone into a command line, which it never does. Since 2026-10-05 the
//!     arbiter leaves a secret's placeholder in the argv and the command runs
//!     (the egress proxy puts the value in, at a bound host only), so this kind
//!     comes back only from its defense-in-depth check;
//!   - `symbol_as_command` (the FROZEN integrity axis): untrusted text would run
//!     as a command;
//!   - `unsupported_command`: shell syntax the gate cannot check safely.
//!
//! No approval queue exists for an exec (the arbiter's `resolveExecArgv` files
//! none), so the message never promises one for the command itself; the only
//! Inbox it names is the network egress gate's, which is where a secret's way
//! out actually is.

use mandu_arbiter::protocol::ExecApprovalItem;

/// The fixed head of every refusal line (the launcher's live suite keys on it).
pub const REFUSAL_PREFIX: &str = "mandu-exec-box: blocked, nothing ran";
/// The fixed machine tail (the audit form a bug report keys on).
pub const REFUSAL_DETAIL: &str = "detail: approval withheld (fail-closed)";

/// Why one withheld item blocked the command, and what the person can do.
fn plain_approval(item: &ExecApprovalItem) -> (String, &'static str) {
    match item.kind.as_str() {
        "secret_symbol" => (
            "the command line carries a placeholder for a secret, and Mandu never writes a \
             secret's real value into a command line"
                .into(),
            "a secret leaves only inside a network request to a site it may go to \
             (`mandu why <file>` lists them); any other site asks for your OK on the dashboard's \
             Approvals page (`mandu dashboard`)",
        ),
        "symbol_as_command" => (
            "the command would use data from an untrusted source (a placeholder) as a command \
             or argument, which Mandu never does"
                .into(),
            "if you trust that data, run the command yourself, outside the agent",
        ),
        "unsupported_command" => {
            // The arbiter's reason ends in the offending construct, e.g.
            // "shell_construct_unsupported ({)" — surface it, as exec-wrap does.
            let syntax = item
                .reason
                .trim_end()
                .strip_suffix(')')
                .and_then(|r| r.rsplit_once('('))
                .map(|(_, s)| s)
                .filter(|s| !s.is_empty() && !s.contains(['(', ')']));
            let why = match syntax {
                Some(s) => format!(
                    "the command carries a placeholder for protected data and uses shell syntax \
                     Mandu cannot check safely ({s}), so Mandu will not put the real value in"
                ),
                None => "the command carries a placeholder for protected data and uses shell \
                         syntax Mandu cannot check safely, so Mandu will not put the real value in"
                    .into(),
            };
            (
                why,
                "write it as one plain command (no pipes, redirects, $( ), { } or wildcards) and \
                 Mandu fills the value in where it is allowed to go; otherwise run it yourself, \
                 outside the agent",
            )
        }
        _ => ("Mandu rules do not allow it".into(), "`mandu dashboard` lists the rules"),
    }
}

/// The one-line refusal for a HumanShell exec refused pending approval.
///
/// `withheld` is the plan's approval items; `gate_unreachable` is true when
/// the arbiter's gate did not answer (the supervisor then withholds every
/// symbol itself — its synthesized item names no real policy decision, so the
/// message says the service is not answering instead of guessing a kind).
/// Duplicate reasons are printed once; the machine kinds follow the fixed
/// `detail:` tail.
pub fn refusal_message(withheld: &[ExecApprovalItem], gate_unreachable: bool) -> String {
    let mut parts: Vec<String> = Vec::new();
    let mut kinds: Vec<&str> = Vec::new();
    if gate_unreachable {
        parts.push(
            "the Mandu service is not answering, and a checked command never runs unchecked; \
             what to do: `mandu status` shows the service"
                .into(),
        );
        kinds.push("gate_unreachable");
    } else {
        let mut seen: Vec<String> = Vec::new();
        for item in withheld {
            if !kinds.contains(&item.kind.as_str()) {
                kinds.push(item.kind.as_str());
            }
            let (why, next) = plain_approval(item);
            if seen.contains(&why) {
                continue;
            }
            parts.push(format!("{why}; what to do: {next}"));
            seen.push(why);
        }
        if parts.is_empty() {
            let (why, next) = plain_approval(&ExecApprovalItem {
                kind: String::new(),
                symbols: vec![],
                reason: String::new(),
            });
            parts.push(format!("{why}; what to do: {next}"));
        }
    }
    let kinds = if kinds.is_empty() { String::new() } else { format!(" [{}]", kinds.join(", ")) };
    format!("{REFUSAL_PREFIX}: {}. {REFUSAL_DETAIL}{kinds}", parts.join(". Also: "))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn item(kind: &str, reason: &str) -> ExecApprovalItem {
        ExecApprovalItem {
            kind: kind.into(),
            symbols: vec!["$MDU:nomodel_ab12".into()],
            reason: reason.into(),
        }
    }

    const SECRET_REASON: &str = "secret-labeled symbol in a net-enabled HumanShell argv → \
        withhold; release only via the network egress gate (confidentiality §7.1)";

    #[test]
    fn secret_symbol_says_a_secret_never_enters_a_command_line() {
        let m = refusal_message(&[item("secret_symbol", SECRET_REASON)], false);
        assert!(m.starts_with("mandu-exec-box: blocked, nothing ran: "), "{m}");
        assert!(m.contains("placeholder for a secret"), "{m}");
        assert!(m.contains("never writes a secret's real value into a command line"), "{m}");
        assert!(m.contains("`mandu why <file>`"), "{m}");
        assert!(m.contains("dashboard's Approvals page (`mandu dashboard`)"), "{m}");
        assert!(m.ends_with("detail: approval withheld (fail-closed) [secret_symbol]"), "{m}");
        // The integrity wording must NOT appear for a confidentiality refusal.
        assert!(!m.contains("untrusted"), "{m}");
        assert!(!m.contains("which Mandu never does"), "{m}");
        // No symbol text or internal vocabulary leaks into the product line.
        assert!(!m.contains("$MDU:"), "{m}");
        assert!(!m.contains("HumanShell") && !m.contains("arbiter"), "{m}");
    }

    #[test]
    fn symbol_as_command_keeps_the_integrity_wording() {
        let m = refusal_message(&[item("symbol_as_command", "symbol used as command")], false);
        assert!(
            m.contains("data from an untrusted source (a placeholder) as a command or argument, which Mandu never does"),
            "{m}"
        );
        assert!(m.contains("run the command yourself, outside the agent"), "{m}");
        assert!(!m.contains("secret"), "{m}");
        assert!(m.ends_with("[symbol_as_command]"), "{m}");
    }

    #[test]
    fn unsupported_command_names_the_construct() {
        let m = refusal_message(&[item("unsupported_command", "shell_construct_unsupported ({)")], false);
        assert!(m.contains("shell syntax Mandu cannot check safely ({)"), "{m}");
        assert!(m.contains("write it as one plain command"), "{m}");
        let bare = refusal_message(&[item("unsupported_command", "no construct here")], false);
        assert!(bare.contains("cannot check safely, so Mandu"), "{bare}");
    }

    #[test]
    fn mixed_kinds_print_each_reason_once() {
        let m = refusal_message(
            &[
                item("secret_symbol", SECRET_REASON),
                item("symbol_as_command", "x"),
                item("secret_symbol", SECRET_REASON),
            ],
            false,
        );
        assert_eq!(m.matches("placeholder for a secret").count(), 1, "{m}");
        assert_eq!(m.matches("untrusted source").count(), 1, "{m}");
        assert!(m.contains(". Also: "), "{m}");
        assert!(m.ends_with("[secret_symbol, symbol_as_command]"), "{m}");
    }

    #[test]
    fn empty_and_unknown_kinds_get_the_generic_line() {
        let m = refusal_message(&[], false);
        assert!(m.starts_with("mandu-exec-box: blocked, nothing ran: Mandu rules do not allow it"), "{m}");
        assert!(m.ends_with("detail: approval withheld (fail-closed)"), "{m}");
        let u = refusal_message(&[item("future_kind", "r")], false);
        assert!(u.contains("Mandu rules do not allow it"), "{u}");
        assert!(u.ends_with("[future_kind]"), "{u}");
    }

    #[test]
    fn gate_unreachable_says_the_service_is_not_answering() {
        // plan_exec's fail-closed path synthesizes a symbol_as_command item; the
        // message must not blame untrusted data for an unreachable service.
        let m = refusal_message(&[item("symbol_as_command", "resolveExecArgv unreachable")], true);
        assert!(m.contains("the Mandu service is not answering"), "{m}");
        assert!(m.contains("`mandu status`"), "{m}");
        assert!(!m.contains("untrusted"), "{m}");
        assert!(m.ends_with("detail: approval withheld (fail-closed) [gate_unreachable]"), "{m}");
    }
}

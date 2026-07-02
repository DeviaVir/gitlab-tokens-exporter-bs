//! Generates the prometheus metrics
use core::fmt::Write as _;

use tracing::instrument;

use crate::gitlab::token::Token;

/// Generates the prometheus metric line for a single token.
///
/// The metric is always `gitlab_token_expiration` and its value is the number
/// of days before the token expires (`NaN` when the token has no expiry date),
/// with generalized labels (`token_type`, `full_path`, `token_name`, `active`).
#[expect(clippy::arithmetic_side_effects, reason = "not handled by chrono")]
#[instrument(err, skip_all)]
pub fn build(gitlab_token: &Token) -> Result<String, anyhow::Error> {
    let mut res = String::new();
    let date_now = chrono::Utc::now().date_naive();

    let token_type = match *gitlab_token {
        Token::Group { .. } => "group",
        Token::Project { .. } => "project",
        Token::User { .. } => "user",
    };

    let (name, active, expires_at, full_path) = match gitlab_token {
        Token::Group {
            token, full_path, ..
        }
        | Token::Project {
            token, full_path, ..
        } => (&token.name, token.active, token.expires_at, full_path),
        Token::User { token, full_path } => {
            (&token.name, token.active, token.expires_at, full_path)
        }
    };

    // The 7d/14d alerts match on the numeric value, so non-expiring tokens must
    // *not* land in the `0..=14` range: `NaN` keeps them out of every comparison.
    let days = match expires_at {
        Some(expiry) => (expiry - date_now).num_days().to_string(),
        None => "NaN".to_owned(),
    };

    writeln!(
        res,
        "gitlab_token_expiration{{token_type=\"{token_type}\",full_path=\"{full_path}\",token_name=\"{name}\",active=\"{active}\"}} {days}"
    )?;

    Ok(res)
}

#[cfg(test)]
mod tests {
    use chrono::{Days, Utc};

    use super::build;
    use crate::gitlab::token::{AccessLevel, AccessToken, AccessTokenScope, Token};

    /// Builds a project token, optionally with an expiry `days` in the future
    fn project_token(active: bool, expiry_in_days: Option<u64>) -> Token {
        let expires_at = expiry_in_days.map(|days| {
            Utc::now()
                .date_naive()
                .checked_add_days(Days::new(days))
                .unwrap()
        });
        Token::Project {
            token: AccessToken {
                access_level: AccessLevel::Guest,
                active,
                expires_at,
                id: 1,
                name: "ci-token".to_owned(),
                revoked: false,
                scopes: vec![AccessTokenScope::ReadApi],
            },
            full_path: "group/project".to_owned(),
            web_url: "https://gl.example.com/group/project".to_owned(),
        }
    }

    #[test]
    fn expiring_token_emits_day_count() {
        let out = build(&project_token(true, Some(30))).unwrap();
        assert_eq!(
            out.trim_end(),
            "gitlab_token_expiration{token_type=\"project\",full_path=\"group/project\",token_name=\"ci-token\",active=\"true\"} 30"
        );
    }

    #[test]
    fn non_expiring_token_emits_nan() {
        let out = build(&project_token(true, None)).unwrap();
        assert!(out.trim_end().ends_with("} NaN"), "got: {out}");
        // must stay out of the `>= 0` alert comparison
        assert!(!out.contains("} 0"), "got: {out}");
    }

    #[test]
    fn inactive_token_carries_active_false_label() {
        let out = build(&project_token(false, Some(3))).unwrap();
        assert!(out.contains("active=\"false\""), "got: {out}");
    }
}

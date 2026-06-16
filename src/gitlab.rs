//! Handles the communication with gitlab

use core::error::Error;
use core::fmt::Write as _; // To be able to use the `Write` trait
use core::fmt::{Display, Formatter};
use core::time::Duration;
use serde::Deserialize;
use serde_repr::Deserialize_repr;
use std::collections::HashMap;
use std::collections::hash_map::Entry::{Occupied, Vacant};
use std::env;
use std::sync::LazyLock;
use tokio::time::sleep;
use tracing::{debug, error, instrument, warn};

/// Number of times a transient gitlab API error is retried before giving up
/// (env `MAX_RETRIES`, default `4`; set to `0` to disable retrying)
static MAX_RETRIES: LazyLock<u32> = LazyLock::new(|| {
    env::var("MAX_RETRIES")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(4)
});

/// Base delay for the retry exponential backoff (env `RETRY_BACKOFF_MS`, default `500`)
static RETRY_BACKOFF: LazyLock<Duration> = LazyLock::new(|| {
    let millis: u64 = env::var("RETRY_BACKOFF_MS")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(500);
    Duration::from_millis(millis)
});

/// Upper bound for the backoff exponent, capping the per-attempt delay at 64x the base
const MAX_BACKOFF_EXPONENT: u32 = 6;

/// HTTP status codes worth retrying.
///
/// These are typically returned by an overloaded, restarting or rate-limiting
/// gitlab instance and usually succeed on a subsequent attempt. Any other
/// status (eg `401` or `404`) fails immediately, as retrying would not help.
const RETRYABLE_STATUS: [u16; 5] = [429, 500, 502, 503, 504];

/// Computes the capped exponential backoff delay before retry `attempt` (0-based)
fn backoff_delay(attempt: u32) -> Duration {
    let exponent = attempt.min(MAX_BACKOFF_EXPONENT);
    let one: u32 = 1;
    let multiplier = one.checked_shl(exponent).unwrap_or(u32::MAX);
    RETRY_BACKOFF.saturating_mul(multiplier)
}

/// Performs an authenticated `GET`, retrying transient failures with exponential
/// backoff.
///
/// A failure is considered transient when it is either a transport error
/// (timeout / connection error) or one of the [`RETRYABLE_STATUS`] HTTP status
/// codes; such failures are retried up to [`MAX_RETRIES`] times. On a final,
/// non-retryable status error the response body is logged before returning,
/// preserving the previous diagnostics.
#[instrument(skip(http_client, token))]
async fn get_with_retry(
    http_client: &reqwest::Client,
    url: &str,
    token: &str,
) -> Result<reqwest::Response, Box<dyn Error + Send + Sync>> {
    let mut attempt: u32 = 0;

    loop {
        match http_client
            .get(url)
            .header("PRIVATE-TOKEN", token)
            .send()
            .await
        {
            Ok(resp) => match resp.error_for_status_ref() {
                Ok(_) => return Ok(resp),
                Err(status_err) => {
                    let status = status_err.status().map_or(0, |code| code.as_u16());
                    if RETRYABLE_STATUS.contains(&status) && attempt < *MAX_RETRIES {
                        let backoff = backoff_delay(attempt);
                        warn!(
                            url,
                            attempt = attempt.saturating_add(1),
                            status,
                            backoff_ms = backoff.as_millis(),
                            "transient gitlab error, retrying after backoff"
                        );
                        sleep(backoff).await;
                        attempt = attempt.saturating_add(1);
                        continue;
                    }
                    let body = resp.text().await.unwrap_or_default();
                    error!("{url} - {status} : {body}");
                    return Err(Box::new(status_err));
                }
            },
            Err(send_err) => {
                if (send_err.is_timeout() || send_err.is_connect()) && attempt < *MAX_RETRIES {
                    let backoff = backoff_delay(attempt);
                    warn!(
                        url,
                        attempt = attempt.saturating_add(1),
                        error = %send_err,
                        backoff_ms = backoff.as_millis(),
                        "transient gitlab error, retrying after backoff"
                    );
                    sleep(backoff).await;
                    attempt = attempt.saturating_add(1);
                    continue;
                }
                return Err(Box::new(send_err));
            }
        }
    }
}

/// cf <https://docs.gitlab.com/api/project_access_tokens/#create-a-project-access-token>
#[derive(Debug, Deserialize_repr)]
#[repr(u8)]
pub enum AccessLevel {
    Developer = 30,
    Guest = 10,
    Maintainer = 40,
    Owner = 50,
    Reporter = 20,
}

impl Display for AccessLevel {
    #[expect(clippy::min_ident_chars, reason = "Parameter name from std trait")]
    #[expect(clippy::absolute_paths, reason = "Use a specific Result type")]
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "{}",
            match *self {
                Self::Guest => "guest",
                Self::Reporter => "reporter",
                Self::Developer => "developer",
                Self::Maintainer => "maintainer",
                Self::Owner => "owner",
            },
        )
    }
}

/// Defines a [gitlab access token](https://docs.gitlab.com/api/project_access_tokens/#list-project-access-tokens)
#[derive(Debug, Deserialize)]
pub struct AccessToken {
    /// Access level
    pub access_level: AccessLevel,
    /// Active
    pub active: bool,
    /// Expiration date (null when no expiration is set)
    pub expires_at: Option<chrono::NaiveDate>,
    /// Name
    pub name: String,
    /// Revoked
    pub revoked: bool,
    /// [Scopes](https://docs.gitlab.com/user/project/settings/project_access_tokens/#scopes-for-a-project-access-token)
    pub scopes: Vec<AccessTokenScope>,
}

#[expect(clippy::missing_trait_methods, reason = "we don't need it")]
impl OffsetBasedPagination<Self> for AccessToken {}

/// Scopes used by [`AccessToken`] ([`Project`] and [`Group`])
#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AccessTokenScope {
    /// Grants permission to perform API actions for GitLab Duo
    AiFeatures,
    /// Grants complete read and write access to the scoped group and related project API
    Api,
    /// Grants permission to create runners
    CreateRunner,
    /// Grants permission to perform Kubernetes API calls using the agent for Kubernetes
    K8sProxy,
    /// Grants permission to manage runners
    ManageRunner,
    /// Grants read access to the scoped group and related project API
    ReadApi,
    /// Grants read access (pull) to project observability data
    ReadObservability,
    /// Grants read access (pull) to the container registry images
    ReadRegistry,
    /// Grants read access (pull) to the repository or all repositories within a group
    ReadRepository,
    /// If a project is private and authorization is required, grants read-only (pull) access to container images through the dependency proxy
    ReadVirtualRegistry,
    /// Grants permission to rotate this token
    SelfRotate,
    /// Grants write access (push) to project observability data
    WriteObservability,
    /// Grants write access (push) to the container registry
    WriteRegistry,
    /// Grants read and write access (pull and push) to the repository or to all repositories within a group
    WriteRepository,
    /// If a project is private and authorization is required, grants read (pull), write (push), and delete access to container images through the dependency proxy
    WriteVirtualRegistry,
}

#[expect(clippy::absolute_paths, reason = "Specific Trait and Result type")]
impl core::fmt::Display for AccessTokenScope {
    #[expect(
        clippy::min_ident_chars,
        reason = "Using the default function parameter name"
    )]
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        match *self {
            Self::AiFeatures => write!(f, "ai_features"),
            Self::Api => write!(f, "api"),
            Self::CreateRunner => write!(f, "create_runner"),
            Self::K8sProxy => write!(f, "k8s_proxy"),
            Self::ManageRunner => write!(f, "manage_runner"),
            Self::ReadApi => write!(f, "read_api"),
            Self::ReadObservability => write!(f, "read_observability"),
            Self::ReadRegistry => write!(f, "read_registry"),
            Self::ReadRepository => write!(f, "read_repository"),
            Self::ReadVirtualRegistry => write!(f, "read_virtual_repository"),
            Self::SelfRotate => write!(f, "self_rotate"),
            Self::WriteObservability => write!(f, "write_observability"),
            Self::WriteRegistry => write!(f, "write_registry"),
            Self::WriteRepository => write!(f, "write_repository"),
            Self::WriteVirtualRegistry => write!(f, "write_virtual_registry"),
        }
    }
}

/// Defines a [gitlab group](https://docs.gitlab.com/api/groups/)
#[derive(Clone, Debug, Deserialize)]
pub struct Group {
    /// Group id
    pub id: usize,
    /// Group parent id
    pub parent_id: Option<usize>,
    /// Group path
    pub path: String,
    /// Group URL
    pub web_url: String,
}

#[expect(clippy::missing_trait_methods, reason = "we don't need it")]
impl OffsetBasedPagination<Self> for Group {}

/// cf <https://docs.gitlab.com/api/rest/#offset-based-pagination>
pub trait OffsetBasedPagination<T: for<'serde> serde::Deserialize<'serde>> {
    #[instrument(skip_all)]
    async fn get_all(
        http_client: &reqwest::Client,
        url: String,
        token: &str,
    ) -> Result<Vec<T>, Box<dyn Error + Send + Sync>> {
        let mut result: Vec<T> = Vec::new();
        let mut next_url: Option<String> = Some(url);

        while let Some(ref current_url) = next_url {
            let resp = get_with_retry(http_client, current_url, token).await?;

            next_url = resp
                .headers()
                .get("link")
                .and_then(|header_value| header_value.to_str().ok())
                .and_then(|header_value_str| {
                    parse_link_header::parse_with_rel(header_value_str).ok()
                })
                .and_then(|links| links.get("next").map(|link| link.raw_uri.clone()));

            let mut items: Vec<T> = resp.json().await?;
            result.append(&mut items);
        }

        Ok(result)
    }
}

/// Defines a [gitlab personal access token](https://docs.gitlab.com/api/personal_access_tokens/#list-personal-access-tokens)
#[derive(Debug, Deserialize)]
pub struct PersonalAccessToken {
    /// Active
    pub active: bool,
    /// Expiration date (null when no expiration is set)
    pub expires_at: Option<chrono::NaiveDate>,
    /// Name
    pub name: String,
    /// Revoked
    pub revoked: bool,
    /// [Scopes](https://docs.gitlab.com/user/profile/personal_access_tokens/#personal-access-token-scopes)
    pub scopes: Vec<PersonalAccessTokenScope>,
    /// User id
    pub user_id: usize,
}

#[expect(clippy::missing_trait_methods, reason = "we don't need it")]
impl OffsetBasedPagination<Self> for PersonalAccessToken {}

/// Scopes used by [`PersonalAccessToken`]
#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PersonalAccessTokenScope {
    /// Grants permission to perform API actions when Admin Mode is enabled
    AdminMode,
    /// Grants permission to perform API actions for features like GitLab Duo, Code Suggestions API and Duo Chat API
    AiFeatures,
    /// Grants complete read/write access to the API
    Api,
    /// Grants permission to create runners
    CreateRunner,
    /// Grants permission to perform Kubernetes API calls using the agent for Kubernetes
    K8sProxy,
    /// Grants permission to manage runners
    ManageRunner,
    /// Grants read access to the API
    ReadApi,
    /// Grants read access (pull) to project observability data
    ReadObservability,
    /// Grants read-only (pull) access to container registry images if a project is private and authorization is required
    ReadRegistry,
    /// Grants read-only access to repositories on private projects
    ReadRepository,
    /// Grant access to download Service Ping payload through the API when authenticated as an admin use
    ReadServicePing,
    /// Grants read-only access to the authenticated user’s profile through the /user API endpoint
    ReadUser,
    /// If a project is private and authorization is required, grants read-only (pull) access to container images through the dependency proxy
    ReadVirtualRegistry,
    /// Grants permission to rotate this token
    SelfRotate,
    /// Grants permission to perform API actions as any user in the system, when authenticated as an administrator
    Sudo,
    /// Grants write access (push) to project observability data
    WriteObservability,
    /// Grants read-write (push) access to container registry images if a project is private and authorization is required
    WriteRegistry,
    /// Grants read-write access to repositories on private projects
    WriteRepository,
    /// If a project is private and authorization is required, grants read (pull), write (push), and delete access to container images through the dependency proxy
    WriteVirtualRegistry,
}

#[expect(clippy::absolute_paths, reason = "Specific Trait and Result type")]
impl core::fmt::Display for PersonalAccessTokenScope {
    #[expect(
        clippy::min_ident_chars,
        reason = "Using the default function parameter name"
    )]
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        match *self {
            Self::AdminMode => write!(f, "admin_mode"),
            Self::AiFeatures => write!(f, "ai_features"),
            Self::Api => write!(f, "api"),
            Self::CreateRunner => write!(f, "create_runner"),
            Self::K8sProxy => write!(f, "k8s_proxy"),
            Self::ManageRunner => write!(f, "manage_runner"),
            Self::ReadApi => write!(f, "read_api"),
            Self::ReadObservability => write!(f, "read_observability"),
            Self::ReadRegistry => write!(f, "read_registry"),
            Self::ReadRepository => write!(f, "read_repository"),
            Self::ReadServicePing => write!(f, "read_service_ping"),
            Self::ReadUser => write!(f, "read_user"),
            Self::ReadVirtualRegistry => write!(f, "read_virtual_registry"),
            Self::SelfRotate => write!(f, "self_rotate"),
            Self::Sudo => write!(f, "sudo"),
            Self::WriteObservability => write!(f, "write_observability"),
            Self::WriteRegistry => write!(f, "write_registry"),
            Self::WriteRepository => write!(f, "write_repository"),
            Self::WriteVirtualRegistry => write!(f, "write_virtual_registry"),
        }
    }
}

/// Defines a [gitlab project](https://docs.gitlab.com/api/projects/#get-a-single-project)
#[derive(Debug, Deserialize)]
pub struct Project {
    /// Project id
    pub id: usize,
    /// Project path
    pub path_with_namespace: String,
    /// Project URL
    pub web_url: String,
}

#[expect(clippy::missing_trait_methods, reason = "we don't need it")]
impl OffsetBasedPagination<Self> for Project {}

#[derive(Debug)]
#[expect(clippy::missing_docs_in_private_items, reason = "self documented ;)")]
/// A common token type
pub enum Token {
    /// Group token
    Group {
        token: AccessToken,
        full_path: String,
        web_url: String,
    },
    /// Project token
    Project {
        token: AccessToken,
        full_path: String,
        web_url: String,
    },
    /// User token
    User {
        token: PersonalAccessToken,
        full_path: String,
    },
}

impl Token {
    /// Convert token scopes ([`AccessTokenScope`] or [`PersonalAccessTokenScope`]) into a String
    #[expect(clippy::absolute_paths, reason = "Using a specific type")]
    pub fn scopes(&self) -> Result<String, core::fmt::Error> {
        let mut res = String::from("[");

        match *self {
            Self::Group { ref token, .. } | Self::Project { ref token, .. } => {
                for scope in &token.scopes {
                    write!(res, "{scope},")?;
                }
            }
            Self::User { ref token, .. } => {
                for scope in &token.scopes {
                    write!(res, "{scope},")?;
                }
            }
        }

        if res.ends_with(',') {
            res.pop();
        }

        res.push(']');
        Ok(res)
    }
}

/// Defines a [gitlab user](https://docs.gitlab.com/api/users/#list-users)
#[derive(Debug, Deserialize)]
pub struct User {
    /// User id
    pub id: usize,
    /// This field is not available if the query is made with a non-admin token
    #[serde(default)]
    pub is_admin: bool,
    /// User name (without spaces)
    pub username: String,
}

#[expect(clippy::missing_trait_methods, reason = "we don't need it")]
impl OffsetBasedPagination<Self> for User {}

/// Get the current gitlab user
#[instrument(skip_all, err)]
pub async fn get_current_user(
    http_client: &reqwest::Client,
    hostname: &str,
    token: &str,
) -> Result<User, Box<dyn Error + Send + Sync>> {
    let current_url = format!("https://{hostname}/api/v4/user");

    Ok(get_with_retry(http_client, &current_url, token)
        .await?
        .json::<User>()
        .await?)
}

/// Creates a string containing `group` full path
///
/// Because the gitlab API gives us `path_with_namespace` for [projects](Project) but not for [groups](Group)
#[instrument(skip_all, err)]
pub async fn get_group_full_path(
    http_client: &reqwest::Client,
    hostname: &str,
    token: &str,
    group: &Group,
    cache: &mut HashMap<usize, Group>,
) -> Result<String, Box<dyn Error + Send + Sync>> {
    debug!("group: {group:?}");

    // This variable will contain the String returned by this function
    let mut res = group.path.clone();

    // This variable will be overwritten in the while loop below
    let mut tmp_group = cache.entry(group.id).or_insert_with(|| group.clone());

    while let Some(parent_group_id) = tmp_group.parent_id {
        tmp_group = match cache.entry(parent_group_id) {
            // Found this group in the cache
            Occupied(entry) => entry.into_mut(),

            // If not, querying gitlab
            Vacant(entry) => {
                debug!("Getting group {parent_group_id} from gitlab");
                let group_url = format!("https://{hostname}/api/v4/groups/{parent_group_id}");
                let group_from_gitlab = get_with_retry(http_client, &group_url, token)
                    .await?
                    .json::<Group>()
                    .await?;

                // Storing the result in the cache
                entry.insert(group_from_gitlab)
            }
        };
        res = format!("{}/{res}", tmp_group.path);
    }

    Ok(res)
}

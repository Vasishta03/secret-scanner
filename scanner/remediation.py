from __future__ import annotations

from dataclasses import dataclass

_DOCS = "https://github.com/Vasishta03/secret-scanner/blob/main/README.md#detected-secret-types"


@dataclass
class Remediation:
    consequence: str
    blast_radius: str
    rotation_url: str


# secret_type -> (consequence if leaked, blast radius label, rotation action URL)
_DATA: dict[str, tuple[str, str, str]] = {
    "AWS Access Key ID": ("Combined with its secret key, an attacker can call any AWS API the underlying IAM identity is permitted to use, including launching compute, reading S3 buckets, and modifying IAM policies.", "Full cloud account compromise", "https://console.aws.amazon.com/iam/home#/security_credentials"),
    "AWS Secret Access Key": ("Combined with the access key ID, this authenticates as the IAM identity, allowing full programmatic control over every AWS service that identity can reach.", "Full cloud account compromise", "https://console.aws.amazon.com/iam/home#/security_credentials"),
    "GCP Service Account": ("This JSON key authenticates as the service account with all of its granted IAM roles, potentially exposing Compute Engine, Cloud Storage, BigQuery data, and billing controls.", "Full cloud project compromise", "https://console.cloud.google.com/iam-admin/serviceaccounts"),
    "RSA Private Key": ("Allows an attacker to impersonate the key owner for SSH logins, TLS termination, or code signing wherever the matching public key is trusted.", "Server access or identity impersonation", "https://docs.github.com/en/authentication/connecting-to-github-with-ssh/generating-a-new-ssh-key-and-adding-it-to-the-ssh-agent"),
    "EC Private Key": ("Allows an attacker to impersonate the key owner for SSH logins or TLS connections wherever the matching public key is trusted.", "Server access or identity impersonation", "https://docs.github.com/en/authentication/connecting-to-github-with-ssh/generating-a-new-ssh-key-and-adding-it-to-the-ssh-agent"),
    "PGP Private Key": ("Allows an attacker to decrypt messages encrypted to this key and to forge signatures that appear to come from its owner.", "Identity impersonation and data decryption", "https://docs.github.com/en/authentication/managing-commit-signature-verification/generating-a-new-gpg-key"),
    "OpenSSH Private Key": ("Grants direct SSH access to every server and account that trusts the matching public key.", "Server access", "https://docs.github.com/en/authentication/connecting-to-github-with-ssh/generating-a-new-ssh-key-and-adding-it-to-the-ssh-agent"),
    "PKCS8 Private Key": ("Allows impersonation of the key owner for TLS, signing, or authentication wherever the matching public key or certificate is trusted.", "Server access or identity impersonation", "https://docs.github.com/en/authentication/connecting-to-github-with-ssh/generating-a-new-ssh-key-and-adding-it-to-the-ssh-agent"),
    "PKCS8 Encrypted Key": ("If the encryption passphrase is also exposed or weak, this provides the same access as an unencrypted private key.", "Server access or identity impersonation", "https://docs.github.com/en/authentication/connecting-to-github-with-ssh/generating-a-new-ssh-key-and-adding-it-to-the-ssh-agent"),
    "DSA Private Key": ("Grants SSH access to any server or account that trusts the matching public key.", "Server access", "https://docs.github.com/en/authentication/connecting-to-github-with-ssh/generating-a-new-ssh-key-and-adding-it-to-the-ssh-agent"),
    "Azure Storage Key": ("Grants full read, write, and delete access to every blob, queue, table, and file share in the storage account, plus the ability to generate SAS tokens.", "Full Azure Storage account compromise", "https://learn.microsoft.com/en-us/azure/storage/common/storage-account-keys-manage"),

    "GitHub Personal Token": ("Grants API access to every repository, organization, and setting the token's scopes allow, including private source code and the ability to push commits.", "Source code and CI/CD compromise", "https://github.com/settings/tokens"),
    "GitHub OAuth Token": ("Acts on behalf of the authorizing user with whatever scopes were granted during the OAuth flow, including private repo access.", "Source code and account access", "https://github.com/settings/applications"),
    "GitHub App Token": ("Grants the GitHub App's installed permissions on every repository it has been installed into, often including code, issues, and CI/CD secrets.", "Source code and CI/CD compromise", "https://github.com/settings/installations"),
    "GitHub Refresh Token": ("Can be exchanged for new access tokens indefinitely, giving an attacker long-lived access to the authorizing user's account and repositories.", "Long-lived account and source code access", "https://github.com/settings/applications"),
    "GitLab Personal Token": ("Grants API access to every project and group the token's scopes allow, including private repository contents and CI/CD variables.", "Source code and CI/CD compromise", "https://gitlab.com/-/user_settings/personal_access_tokens"),
    "GitLab CI Token": ("Allows pulling and pushing container registries and packages, and can read protected CI/CD variables for the project.", "CI/CD pipeline compromise", "https://gitlab.com/-/user_settings/personal_access_tokens"),
    "Stripe Live Secret Key": ("Allows full access to the live Stripe account: charges, refunds, customer payment data, payouts, and account configuration.", "Payment processing and customer financial data", "https://dashboard.stripe.com/apikeys"),
    "Stripe Live Publishable": ("Lower risk than the secret key, but combined with other leaked information it can be used to create tokens or charges against the account in some configurations.", "Payment integration abuse", "https://dashboard.stripe.com/apikeys"),
    "Twilio Account SID": ("Identifies the Twilio account; combined with the matching auth token it allows sending SMS/calls and accessing call logs and recordings, billed to the account owner.", "Communications abuse and billing fraud", "https://console.twilio.com/us1/account/keys-credentials/api-keys"),
    "Twilio Auth Token": ("Combined with the account SID, allows sending SMS and making calls billed to the account, and reading call/message logs and recordings.", "Communications abuse and billing fraud", "https://console.twilio.com/us1/account/keys-credentials/api-keys"),
    "SendGrid API Key": ("Allows sending email as any verified sender on the account, harvesting contact lists, and reading email activity, often used for phishing campaigns.", "Email sending abuse and phishing", "https://app.sendgrid.com/settings/api_keys"),
    "Slack Bot Token": ("Allows the bot to read messages, post as itself, and access any workspace data its OAuth scopes permit.", "Workspace communication compromise", "https://api.slack.com/apps"),
    "Slack User Token": ("Acts as the authorizing user, allowing the attacker to read private channels, DMs, and post messages as that person.", "User account and workspace compromise", "https://api.slack.com/apps"),
    "Slack Webhook": ("Allows anyone with the URL to post arbitrary messages into the configured channel, useful for phishing or spam inside the organization.", "Channel spam and phishing", "https://api.slack.com/messaging/webhooks"),
    "Mailgun API Key": ("Allows sending email through every domain configured on the account and reading mailing lists and logs, commonly abused for phishing.", "Email sending abuse and phishing", "https://app.mailgun.com/app/account/security/api_keys"),
    "Anthropic API Key": ("Allows making Claude API calls billed to the account owner, potentially racking up large usage charges or exhausting rate limits.", "API usage and billing abuse", "https://console.anthropic.com/settings/keys"),
    "OpenAI API Key": ("Allows making OpenAI API calls billed to the account owner, including high-cost model usage, and may expose any fine-tuned models or files on the account.", "API usage and billing abuse", "https://platform.openai.com/api-keys"),
    "OpenAI Project Key": ("Scoped to a single OpenAI project, but still allows API usage billed to that project and access to its resources.", "API usage and billing abuse", "https://platform.openai.com/api-keys"),
    "HuggingFace Token": ("Allows downloading private models and datasets, and if the token has write access, pushing or deleting models under the user's account.", "Private model/dataset access", "https://huggingface.co/settings/tokens"),
    "Replicate API Token": ("Allows running models on Replicate billed to the account owner, and access to any private models the account owns.", "API usage and billing abuse", "https://replicate.com/account/api-tokens"),
    "Telegram Bot Token": ("Grants full control of the Telegram bot, including reading messages sent to it, sending messages to any chat it is in, and changing its profile.", "Bot account takeover", "https://core.telegram.org/bots#botfather"),
    "Discord Bot Token": ("Grants full control of the Discord bot account, including reading messages in every server it has joined and sending messages with its permissions.", "Bot account takeover", "https://discord.com/developers/applications"),
    "Discord Webhook": ("Allows anyone with the URL to post arbitrary messages, embeds, or files into the configured channel.", "Channel spam and phishing", "https://support.discord.com/hc/en-us/articles/228383668-Intro-to-Webhooks"),
    "NPM Access Token": ("Allows publishing new versions of any package the token has access to, a common supply-chain attack vector affecting every downstream consumer.", "Package registry supply-chain compromise", "https://www.npmjs.com/settings/~/tokens"),
    "PyPI API Token": ("Allows publishing new releases to PyPI for the scoped project(s), a supply-chain risk for every downstream consumer of the package.", "Package registry supply-chain compromise", "https://pypi.org/manage/account/token/"),
    "Shopify Access Token": ("Grants API access to the store's admin functions per the app's scopes, potentially including orders, customer data, and payment information.", "E-commerce store and customer data compromise", "https://admin.shopify.com/store/_/settings/apps/development"),
    "Shopify Shared Secret": ("Used to verify webhook signatures and OAuth callbacks; an attacker with this secret can forge requests that the store will treat as authentic.", "E-commerce store and customer data compromise", "https://admin.shopify.com/store/_/settings/apps/development"),
    "DigitalOcean Token": ("Allows full control of the DigitalOcean account via the API, including creating or destroying droplets, reading backups, and managing DNS and billing.", "Full cloud account compromise", "https://cloud.digitalocean.com/account/api/tokens"),
    "Dropbox Token": ("Grants access to the files and folders the token's scopes allow, potentially including the entire Dropbox account's contents.", "Cloud storage data exposure", "https://www.dropbox.com/developers/apps"),
    "Notion API Key": ("Allows reading and writing every page and database the integration has been shared with, which can include internal documentation and wikis.", "Internal documentation exposure", "https://www.notion.so/my-integrations"),
    "Linear API Key": ("Grants API access to the Linear workspace's issues, projects, and roadmaps, exposing internal product and engineering plans.", "Internal project management exposure", "https://linear.app/settings/api"),
    "Terraform Cloud Token": ("Allows triggering runs, reading state files (which often contain plaintext secrets and resource IDs), and modifying infrastructure configuration.", "Infrastructure-as-code and state file compromise", "https://app.terraform.io/app/settings/tokens"),
    "Vault Service Token": ("Allows reading every secret the token's policies grant access to, often a master key to an organization's other credentials.", "Secrets manager compromise (cascading)", "https://developer.hashicorp.com/vault/docs/commands/token/revoke"),
    "New Relic API Key": ("Allows querying application performance data, logs, and infrastructure metrics, which can leak internal hostnames, error details, and traffic patterns.", "Observability data exposure", "https://one.newrelic.com/api-keys"),
    "New Relic License Key": ("Allows ingesting data into the account's New Relic instance and, depending on key type, querying existing telemetry data.", "Observability data exposure", "https://one.newrelic.com/api-keys"),
    "Mapbox Token": ("If a secret-scoped token, allows managing styles, datasets, and uploads, and can be used to incur usage charges against the account.", "API usage and billing abuse", "https://account.mapbox.com/access-tokens/"),
    "Square Access Token": ("Grants access to the Square account's payments, orders, and customer data per the token's scopes.", "Payment processing and customer financial data", "https://developer.squareup.com/apps"),
    "Square OAuth Token": ("Acts on behalf of the merchant who authorized the app, with access to payments, orders, and customer records.", "Payment processing and customer financial data", "https://developer.squareup.com/apps"),
    "Twitter Bearer Token": ("Allows making API calls against the X (Twitter) API on behalf of the app, which can be used for spam, scraping, or rate-limit exhaustion.", "API usage abuse", "https://developer.twitter.com/en/portal/dashboard"),
    "Mailchimp API Key": ("Grants access to the account's audiences (mailing lists), campaigns, and subscriber data, and can be used to send email as the account.", "Email sending abuse and contact list exposure", "https://admin.mailchimp.com/account/api/"),

    "Supabase Service Key": ("Bypasses row-level security and grants full read/write access to the entire Postgres database behind the Supabase project.", "Full database compromise (bypasses access control)", "https://supabase.com/dashboard/project/_/settings/api"),
    "Supabase API Key": ("Acts as the project's anon or service key depending on type, potentially allowing access to tables exposed via the project's API.", "Database and API access", "https://supabase.com/dashboard/project/_/settings/api"),
    "Vercel Token": ("Allows managing deployments, environment variables (which often contain other secrets), and domains for every project the account owns.", "Deployment pipeline and secrets compromise", "https://vercel.com/account/tokens"),
    "Cloudflare Global Key": ("Grants full account-level access to every Cloudflare service: DNS records, SSL/TLS settings, Workers, firewall rules, and billing.", "Full Cloudflare account compromise", "https://dash.cloudflare.com/profile/api-tokens"),
    "Datadog API Key": ("Allows submitting metrics, logs, and traces to the account, and can be used to exhaust ingestion quotas or pollute dashboards.", "Observability data exposure and quota abuse", "https://app.datadoghq.com/organization-settings/api-keys"),
    "Datadog App Key": ("Combined with an API key, allows full read/write access to the Datadog account's dashboards, monitors, and configuration via the API.", "Observability data exposure", "https://app.datadoghq.com/organization-settings/application-keys"),
    "PlanetScale Token": ("Allows API access to the database's branches, deploy requests, and connection credentials per the token's scopes.", "Database access and schema control", "https://app.planetscale.com/"),
    "PlanetScale OAuth Token": ("Acts on behalf of the authorizing user, with access to their organizations, databases, and branches.", "Database access and schema control", "https://app.planetscale.com/"),
    "PlanetScale Password": ("Direct database credential; allows connecting to the database branch and reading/writing all data it contains.", "Full database compromise", "https://app.planetscale.com/"),
    "Postman API Key": ("Allows access to the user's Postman workspaces, collections, and environments, which often contain other API keys and credentials.", "Credential exposure (collections often store other secrets)", "https://web.postman.co/settings/me/api-keys"),
    "Grafana Service Token": ("Allows API access to the Grafana instance per the token's role, including reading dashboards and, for admin tokens, managing data sources and users.", "Observability platform compromise", "https://grafana.com/profile/api-keys"),
    "Grafana Cloud Token": ("Allows pushing or querying metrics, logs, or traces in the Grafana Cloud stack, and may expose infrastructure topology through dashboards.", "Observability data exposure", "https://grafana.com/profile/api-keys"),
    "Sentry Auth Token": ("Allows reading error events (which often contain stack traces, user data, and environment variables) and managing projects per the token's scopes.", "Error monitoring data exposure", "https://sentry.io/settings/account/api/auth-tokens/"),
    "Sentry DSN": ("Primarily used to submit events to a Sentry project; if it includes a private key, it could allow ingesting forged error events.", "Error monitoring data pollution", "https://sentry.io/settings/account/api/auth-tokens/"),
    "Doppler Token": ("Grants access to every secret stored in the Doppler project/config the token is scoped to, often the central store for an organization's other credentials.", "Secrets manager compromise (cascading)", "https://dashboard.doppler.com/workplace/access/tokens"),
    "Age Secret Key": ("Allows decrypting any file that was encrypted to the matching public key, exposing whatever secrets or backups were protected by it.", "Encrypted data decryption", "https://github.com/FiloSottile/age"),
    "Infisical Token": ("Grants access to every secret stored in the Infisical project/environment the token is scoped to, often the central store for an organization's other credentials.", "Secrets manager compromise (cascading)", "https://infisical.com/docs/documentation/platform/token"),
    "Finicity App Key": ("Allows accessing the Finicity (Mastercard Open Banking) API for the app, including connected bank account and transaction data for end users.", "Banking and financial data exposure", "https://developer.mastercard.com/finicity/"),
    "Flutterwave Secret Key": ("Allows initiating payments, refunds, and transfers, and reading transaction and customer data on the Flutterwave account.", "Payment processing and customer financial data", "https://dashboard.flutterwave.com/settings/apis"),
    "Coinbase Access Token": ("Allows access to the Coinbase account's wallets and transaction history, and depending on scopes, the ability to send funds.", "Cryptocurrency funds and account compromise", "https://www.coinbase.com/settings/api"),
    "Twitch Client Secret": ("Allows the application to obtain new OAuth tokens on behalf of users who have authorized it, and to manage the application's registration.", "OAuth application compromise", "https://dev.twitch.tv/console/apps"),

    "Generic API Key": ("An unidentified API key. If valid, it likely grants programmatic access to whatever service it belongs to, scoped however that service's keys are normally scoped.", "Unknown service API access", _DOCS),
    "Generic Secret": ("An unidentified secret or client secret. If valid, it can typically be used together with a client ID to authenticate as an application.", "Unknown application credential exposure", _DOCS),
    "Generic Password": ("A hardcoded password. If reused, it may grant access to the associated account, database, or admin panel, and possibly to other systems if the password is reused.", "Account or system access (and credential reuse risk)", _DOCS),
    "Bearer Token": ("An unidentified bearer token. If still valid, it grants whatever access the issuing service associates with that token, usually without any additional credential.", "Unknown API session access", _DOCS),
    "JWT Token": ("JWTs encode claims (often including user ID, role, and expiry) that a receiving service trusts; an attacker can replay it to impersonate the subject until it expires.", "Session/identity impersonation until expiry", _DOCS),
    "Database URL": ("Contains a username and password for a database, message broker, or search cluster, granting whatever access that account has, often full read/write.", "Database or message broker compromise", _DOCS),
    "Basic Auth in URL": ("Embeds a username and password directly in a URL, granting whatever access that account has on the target host or service.", "Account access on the target host", _DOCS),
    "Stripe Test Key": ("Test keys cannot move real money, but they can reveal the structure of the integration and, if mistaken for a live key, indicate the account exists.", "Low (test mode only)", "https://dashboard.stripe.com/test/apikeys"),
    "Firebase Config": ("The Firebase server key allows sending push notifications to all of the app's registered devices via FCM, which can be abused for spam or phishing.", "Push notification abuse", "https://console.firebase.google.com/"),
    "Google API Key": ("Depending on which Google APIs are enabled for this key, an attacker may be able to use Maps, Places, or other billed APIs against the project's quota.", "API usage and billing abuse", "https://console.cloud.google.com/apis/credentials"),
    "Slack App Token": ("App-level tokens are used to connect via Socket Mode and can be used to establish a WebSocket connection as the app across the workspaces it is installed in.", "Workspace communication compromise", "https://api.slack.com/apps"),
    "Private Key File Path": ("This itself is just a file path, but it points to where a private key is stored on disk, useful information for an attacker who already has some access.", "Information disclosure (key location)", _DOCS),

    "MongoDB Connection String": ("Contains a username and password for a MongoDB instance, granting full read/write access to every database and collection that user can reach.", "Full database compromise", "https://www.mongodb.com/docs/manual/tutorial/change-own-password-and-custom-data/"),
    "PostgreSQL Connection String": ("Contains a username and password for a PostgreSQL database, granting full read/write access to every schema that user can reach.", "Full database compromise", "https://www.postgresql.org/docs/current/sql-alterrole.html"),
    "MySQL Connection String": ("Contains a username and password for a MySQL/MariaDB database, granting full read/write access to every database that user can reach.", "Full database compromise", "https://dev.mysql.com/doc/refman/8.0/en/set-password.html"),
    "Redis Connection String": ("Contains a password for a Redis instance, granting access to every key in the database, including cached sessions, queues, and rate-limit counters.", "Cache/queue data compromise", "https://redis.io/docs/management/security/acl/"),
    "PEM Certificate": ("A public certificate by itself is not secret, but its presence often indicates a matching private key is stored nearby, and its subject/SAN fields can reveal internal hostnames.", "Information disclosure (low on its own)", _DOCS),
    "Docker Config Auth": ("The base64-encoded auth field decodes to a username:password (or token) for a container registry, granting pull/push access to private images.", "Container registry compromise (supply chain)", "https://docs.docker.com/engine/reference/commandline/login/"),
    "Kubernetes Service Account Token": ("Grants whatever RBAC permissions the service account has within the cluster, which can range from read-only pod access to full cluster admin.", "Cluster compromise (scope depends on RBAC)", "https://kubernetes.io/docs/reference/access-authn-authz/service-accounts-admin/#bound-service-account-token-volume"),
    "Firebase Admin SDK Key": ("The Admin SDK service account bypasses Firebase security rules entirely, granting full read/write access to Firestore, Realtime Database, Authentication, and Storage.", "Full Firebase project compromise (bypasses security rules)", "https://console.firebase.google.com/"),
    "Expo Access Token": ("Grants API access to the Expo/EAS account, including building and submitting app updates, which could be used to push malicious app updates.", "Mobile app build and update pipeline compromise", "https://expo.dev/settings/access-tokens"),
    "Fly.io API Token": ("Grants API access to manage the Fly.io organization's apps, including deploying new code, reading secrets set via flyctl, and accessing machines.", "Deployment pipeline and secrets compromise", "https://fly.io/user/personal_access_tokens"),
    "WireGuard Private Key": ("Allows establishing a VPN tunnel as this peer, granting whatever network access the WireGuard configuration permits, often a path into an internal network.", "VPN/internal network access", "https://www.wireguard.com/quickstart/"),
    "PagerDuty API Key": ("Allows reading and modifying incidents, schedules, and escalation policies, and could be used to silence alerts or access on-call contact information.", "Incident response and on-call data exposure", "https://support.pagerduty.com/docs/api-access-keys"),
    "Elastic Cloud API Key": ("Grants access to the Elasticsearch cluster per the key's privileges, potentially including reading or deleting indices containing logs and application data.", "Search/log cluster data compromise", "https://www.elastic.co/guide/en/cloud/current/ec-api-keys.html"),

    "Azure AD Client Secret": ("Allows the application registration to authenticate as itself and obtain access tokens for whatever Microsoft Graph or API permissions it has been granted, including Azure AD directory data.", "Azure AD application and directory compromise", "https://portal.azure.com/#view/Microsoft_AAD_RegisteredApps/ApplicationsListBlade"),
    "Cohere API Key": ("Allows making Cohere API calls billed to the account owner, potentially racking up large usage charges.", "API usage and billing abuse", "https://dashboard.cohere.com/api-keys"),
    "Groq API Key": ("Allows making Groq inference API calls billed to the account owner, potentially exhausting rate limits or quotas.", "API usage and billing abuse", "https://console.groq.com/keys"),
    "Pinecone API Key": ("Grants access to the Pinecone account's vector indexes, allowing reading, writing, or deleting embedded data, which may include sensitive document content.", "Vector database data exposure", "https://app.pinecone.io/"),
    "Atlassian API Token": ("Grants API access to Jira and Confluence as the associated user, including private issues, project data, and wiki content.", "Internal issue tracker and wiki exposure", "https://id.atlassian.com/manage-profile/security/api-tokens"),
    "PayPal Client Secret": ("Combined with the client ID, allows obtaining OAuth access tokens to act as the application, including initiating payments and accessing transaction data.", "Payment processing and customer financial data", "https://developer.paypal.com/dashboard/applications"),
    "Razorpay Key ID": ("Identifies the Razorpay account; combined with the key secret it allows creating orders, capturing payments, and issuing refunds.", "Payment processing and customer financial data", "https://dashboard.razorpay.com/app/keys"),
    "Postmark Server Token": ("Allows sending email through the Postmark server and reading message activity/bounce data, commonly abused for phishing.", "Email sending abuse and phishing", "https://account.postmarkapp.com/servers"),
    "Railway API Token": ("Grants API access to the Railway project, including environment variables (which often contain other secrets), deployments, and the ability to redeploy services.", "Deployment pipeline and secrets compromise", "https://railway.app/account/tokens"),
    "Cloudflare API Token": ("Grants access scoped to whatever permissions the token was created with, which can range from read-only DNS access to full zone or account management.", "Cloudflare zone/account compromise (scope-dependent)", "https://dash.cloudflare.com/profile/api-tokens"),

    "High Entropy String": ("A high-entropy string was detected that does not match any known credential format. It may be a secret, a hash, an encoded value, or random test data.", "Unknown - manual review recommended", _DOCS),
}

_DEFAULT = Remediation(
    "An attacker could use this credential to access the associated service or system.",
    "Unknown - review the matched line to determine which system this credential belongs to.",
    _DOCS,
)


def get_remediation(secret_type: str) -> Remediation:
    """Look up the consequence, blast radius, and rotation URL for a secret type.

    Falls back to a generic entry for custom or unrecognized pattern names
    (e.g. user-defined patterns from .leakscan.yaml).
    """
    data = _DATA.get(secret_type)
    if data is None:
        return _DEFAULT
    return Remediation(*data)

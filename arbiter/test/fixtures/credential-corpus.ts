/**
 * credential-corpus — where developer tools actually keep credentials, with a
 * realistic file body for each (docs/design/confidentiality/secret-discovery.md §2). The
 * catalog recall audit lays every entry out in a synthetic HOME and asks two
 * questions: does the launch-time walk register the file, and does the twin
 * the arbiter would render still contain the secret value?
 *
 * Paths are relative to HOME. `secret` is a value that appears in `content`
 * and must never survive into the twin. Sources: each tool's own docs for
 * where it writes its login state (named per entry).
 */
export interface CorpusEntry {
  /** The tool and what the file is. */
  tool: string;
  /** Path under HOME. */
  path: string;
  content: string;
  /** A value in `content` that must be masked. */
  secret: string;
}

const S = (tag: string): string => `CANARY${tag}x9f3Qz7LmK2pV8wR`;

export const CREDENTIAL_CORPUS: readonly CorpusEntry[] = [
  // ── cloud CLIs ──
  { tool: "aws: static keys", path: ".aws/credentials", content: `[default]\naws_access_key_id = AKIAEXAMPLE\naws_secret_access_key = ${S("aws")}\n`, secret: S("aws") },
  { tool: "aws: SSO token cache", path: ".aws/sso/cache/3f1c.json", content: `{"startUrl":"https://x.awsapps.com/start","region":"us-east-1","accessToken":"${S("awssso")}","expiresAt":"2026-09-26T00:00:00Z"}`, secret: S("awssso") },
  { tool: "aws: CLI assumed-role cache", path: ".aws/cli/cache/ab12.json", content: `{"Credentials":{"AccessKeyId":"ASIAEXAMPLE","SecretAccessKey":"${S("awscli")}","SessionToken":"tok"}}`, secret: S("awscli") },
  { tool: "gcloud: application default credentials", path: ".config/gcloud/application_default_credentials.json", content: `{"client_id":"x.apps.googleusercontent.com","client_secret":"cs","refresh_token":"${S("gcadc")}","type":"authorized_user"}`, secret: S("gcadc") },
  { tool: "gcloud: legacy per-account ADC", path: ".config/gcloud/legacy_credentials/me@example.com/adc.json", content: `{"refresh_token":"${S("gcleg")}","type":"authorized_user"}`, secret: S("gcleg") },
  { tool: "gcloud: access-token DB", path: ".config/gcloud/access_tokens.db", content: `SQLite format 3\u0000${S("gcdb")}`, secret: S("gcdb") },
  { tool: "gcp: service-account key in a project", path: "work/api/service-account.json", content: `{"type":"service_account","project_id":"p","private_key_id":"k1","private_key":"-----BEGIN PRIVATE KEY-----\\n${S("gsa")}\\n-----END PRIVATE KEY-----\\n","client_email":"sa@p.iam.gserviceaccount.com"}`, secret: S("gsa") },
  { tool: "azure: MSAL token cache", path: ".azure/msal_token_cache.json", content: `{"RefreshToken":{"x":{"credential_type":"RefreshToken","secret":"${S("azmsal")}"}}}`, secret: S("azmsal") },
  { tool: "azure: service principal entries", path: ".azure/service_principal_entries.json", content: `[{"client_id":"c","tenant":"t","client_secret":"${S("azsp")}"}]`, secret: S("azsp") },
  { tool: "azure: legacy access tokens", path: ".azure/accessTokens.json", content: `[{"accessToken":"${S("azat")}","refreshToken":"r"}]`, secret: S("azat") },
  { tool: "oci: API signing key", path: ".oci/oci_api_key.pem", content: `-----BEGIN PRIVATE KEY-----\n${S("oci")}\n-----END PRIVATE KEY-----\n`, secret: S("oci") },
  { tool: "digitalocean: doctl", path: ".config/doctl/config.yaml", content: `access-token: ${S("doctl")}\ncontext: default\n`, secret: S("doctl") },
  { tool: "alibaba: aliyun CLI", path: ".aliyun/config.json", content: `{"profiles":[{"name":"default","access_key_id":"LTAI","access_key_secret":"${S("aliyun")}"}]}`, secret: S("aliyun") },
  { tool: "boto2 / gsutil", path: ".boto", content: `[Credentials]\naws_access_key_id = AKIA\naws_secret_access_key = ${S("boto")}\n`, secret: S("boto") },
  { tool: "s3cmd", path: ".s3cfg", content: `[default]\naccess_key = AKIA\nsecret_key = ${S("s3cfg")}\n`, secret: S("s3cfg") },
  // ── containers and clusters ──
  { tool: "kubectl: kubeconfig", path: ".kube/config", content: `apiVersion: v1\nusers:\n- name: admin\n  user:\n    token: ${S("kube")}\n`, secret: S("kube") },
  { tool: "docker: registry auth", path: ".docker/config.json", content: `{"auths":{"ghcr.io":{"auth":"${S("docker")}"}}}`, secret: S("docker") },
  { tool: "podman / skopeo: registry auth", path: ".config/containers/auth.json", content: `{"auths":{"quay.io":{"auth":"${S("podman")}"}}}`, secret: S("podman") },
  { tool: "helm: registry auth", path: ".config/helm/registry/config.json", content: `{"auths":{"r.example.com":{"auth":"${S("helm")}"}}}`, secret: S("helm") },
  { tool: "vault: token", path: ".vault-token", content: `${S("vault")}\n`, secret: S("vault") },
  // ── source hosting and git ──
  { tool: "gh: hosts", path: ".config/gh/hosts.yml", content: `github.com:\n    oauth_token: ${S("gh")}\n    user: me\n`, secret: S("gh") },
  { tool: "git: credential store", path: ".git-credentials", content: `https://me:${S("gitcred")}@github.com\n`, secret: S("gitcred") },
  { tool: "git: XDG credential store", path: ".config/git/credentials", content: `https://me:${S("gitxdg")}@gitlab.com\n`, secret: S("gitxdg") },
  { tool: "glab: config", path: ".config/glab-cli/config.yml", content: `hosts:\n    gitlab.com:\n        token: ${S("glab")}\n`, secret: S("glab") },
  { tool: "hub: config", path: ".config/hub", content: `github.com:\n- user: me\n  oauth_token: ${S("hub")}\n`, secret: S("hub") },
  { tool: "netrc (heroku, curl)", path: ".netrc", content: `machine api.heroku.com\n  login me@example.com\n  password ${S("netrc")}\n`, secret: S("netrc") },
  // ── package registries ──
  { tool: "npm", path: ".npmrc", content: `//registry.npmjs.org/:_authToken=${S("npm")}\n`, secret: S("npm") },
  { tool: "yarn berry", path: ".yarnrc.yml", content: `npmAuthToken: ${S("yarn")}\n`, secret: S("yarn") },
  { tool: "pypi: twine", path: ".pypirc", content: `[pypi]\nusername = __token__\npassword = ${S("pypi")}\n`, secret: S("pypi") },
  { tool: "pip: index URL password", path: ".config/pip/pip.conf", content: `[global]\nindex-url = https://__token__:${S("pip")}@pypi.corp.example/simple\n`, secret: S("pip") },
  { tool: "pip: token as the user, continuation line", path: ".pip/pip.conf", content: `[global]\nextra-index-url =\n    https://pypi.org/simple\n    https://${S("piptok")}@pkgs.example/simple\n`, secret: S("piptok") },
  { tool: "cargo: registry token", path: ".cargo/credentials.toml", content: `[registry]\ntoken = "${S("cargo")}"\n`, secret: S("cargo") },
  { tool: "rubygems", path: ".gem/credentials", content: `---\n:rubygems_api_key: ${S("gem")}\n`, secret: S("gem") },
  { tool: "composer", path: ".config/composer/auth.json", content: `{"github-oauth":{"github.com":"${S("composer")}"}}`, secret: S("composer") },
  { tool: "maven: settings", path: ".m2/settings.xml", content: `<settings><servers><server><id>r</id><password>${S("maven")}</password></server></servers></settings>`, secret: S("maven") },
  { tool: "gradle: properties", path: ".gradle/gradle.properties", content: `ossrhPassword=${S("gradle")}\n`, secret: S("gradle") },
  { tool: "nuget: config", path: ".nuget/NuGet/NuGet.Config", content: `<configuration><packageSourceCredentials><f><add key="ClearTextPassword" value="${S("nuget")}" /></f></packageSourceCredentials></configuration>`, secret: S("nuget") },
  { tool: "terraform: cloud token", path: ".terraform.d/credentials.tfrc.json", content: `{"credentials":{"app.terraform.io":{"token":"${S("tf")}"}}}`, secret: S("tf") },
  { tool: "pulumi", path: ".pulumi/credentials.json", content: `{"current":"https://api.pulumi.com","accessTokens":{"https://api.pulumi.com":"${S("pulumi")}"}}`, secret: S("pulumi") },
  // ── databases ──
  { tool: "postgres", path: ".pgpass", content: `db.internal:5432:app:app:${S("pg")}\n`, secret: S("pg") },
  { tool: "mysql", path: ".my.cnf", content: `[client]\nuser = app\npassword = ${S("mysql")}\n`, secret: S("mysql") },
  { tool: "databricks", path: ".databrickscfg", content: `[DEFAULT]\nhost = https://x.cloud.databricks.com\ntoken = ${S("dbx")}\n`, secret: S("dbx") },
  { tool: "snowflake", path: ".snowflake/connections.toml", content: `[default]\naccount = "a"\npassword = "${S("snow")}"\n`, secret: S("snow") },
  // ── platforms and SaaS CLIs ──
  { tool: "vercel", path: ".local/share/com.vercel.cli/auth.json", content: `{"token":"${S("vercel")}"}`, secret: S("vercel") },
  { tool: "netlify", path: ".config/netlify/config.json", content: `{"users":{"u":{"auth":{"token":"${S("netlify")}"}}}}`, secret: S("netlify") },
  { tool: "cloudflare wrangler", path: ".config/.wrangler/config/default.toml", content: `oauth_token = "${S("wrangler")}"\nrefresh_token = "r"\n`, secret: S("wrangler") },
  { tool: "fly.io", path: ".fly/config.yml", content: `access_token: ${S("fly")}\n`, secret: S("fly") },
  { tool: "supabase", path: ".supabase/access-token", content: `${S("supabase")}`, secret: S("supabase") },
  { tool: "stripe CLI", path: ".config/stripe/config.toml", content: `[default]\ntest_mode_api_key = "${S("stripe")}"\n`, secret: S("stripe") },
  { tool: "firebase CLI", path: ".config/configstore/firebase-tools.json", content: `{"tokens":{"refresh_token":"${S("firebase")}"}}`, secret: S("firebase") },
  { tool: "ngrok", path: ".config/ngrok/ngrok.yml", content: `version: "2"\nauthtoken: ${S("ngrok")}\n`, secret: S("ngrok") },
  { tool: "rclone", path: ".config/rclone/rclone.conf", content: `[s3]\ntype = s3\nsecret_access_key = ${S("rclone")}\n`, secret: S("rclone") },
  { tool: "hugging face", path: ".cache/huggingface/token", content: `${S("hf")}`, secret: S("hf") },
  { tool: "hugging face (legacy)", path: ".huggingface/token", content: `${S("hfold")}`, secret: S("hfold") },
  { tool: "kaggle", path: ".kaggle/kaggle.json", content: `{"username":"me","key":"${S("kaggle")}"}`, secret: S("kaggle") },
  { tool: "github copilot", path: ".config/github-copilot/apps.json", content: `{"github.com:Iv1":{"user":"me","oauth_token":"${S("copilot")}"}}`, secret: S("copilot") },
  { tool: "1password CLI", path: ".config/op/config", content: `{"accounts":[{"shorthand":"me"}],"latest_signin":"me"}\n${S("op")}`, secret: S("op") },
  // 2026-10-19 (secret-discovery.md §2.6): a CLI's login file in its own
  // directory (`shape:tool-login-file`) ...
  { tool: "gemini CLI: OAuth login", path: ".gemini/oauth_creds.json", content: `{"access_token":"ya29.a0","refresh_token":"${S("gemini")}","token_type":"Bearer","expiry_date":1790000000000}`, secret: S("gemini") },
  { tool: "qwen code: OAuth login", path: ".qwen/oauth_creds.json", content: `{"access_token":"${S("qwen")}","refresh_token":"r","resource_url":"portal.qwen.ai"}`, secret: S("qwen") },
  { tool: "planetscale CLI", path: ".config/planetscale/access-token", content: `${S("pscale")}`, secret: S("pscale") },
  { tool: "vercel (legacy now CLI)", path: ".now/auth.json", content: `{"_":"This is your Now credentials file. DO NOT SHARE!","credentials":[{"provider":"sh","token":"${S("now")}"}]}`, secret: S("now") },
  // ... and, by the catalog's content tier, a tool's config in its own
  // dot-directory that holds a token under a credential-named key
  // (`content:secret-key`, read by the walk).
  { tool: "railway CLI", path: ".railway/config.json", content: `{"projects":{},"user":{"token":"${S("railway")}"}}`, secret: S("railway") },
  { tool: "turso CLI", path: ".config/turso/settings.json", content: `{"config":{"token":"${S("turso")}","username":"me"}}`, secret: S("turso") },
  { tool: "doppler CLI", path: ".doppler/.doppler.yaml", content: `scoped:\n    /:\n        token: ${S("doppler")}\n        api-host: https://api.doppler.com\n`, secret: S("doppler") },
  { tool: "twilio CLI", path: ".twilio-cli/config.json", content: `{"profiles":{"me":{"accountSid":"AC0","apiKey":"SK0","apiSecret":"${S("twilio")}"}},"activeProfile":"me"}`, secret: S("twilio") },
  // INI-family per-user configs read directly in HOME (secret-discovery.md
  // §2.9, `content:secret-key`), one with a short password.
  { tool: "postgres: per-user service file", path: ".pg_service.conf", content: "[prod]\nhost=db.internal\nport=5432\ndbname=app\nuser=app\npassword=Tr0ub4\n", secret: "Tr0ub4" },
  { tool: "unixODBC: user data sources", path: ".odbc.ini", content: `[warehouse]\nDriver=PostgreSQL Unicode\nServername=db.internal\nUserName=etl\nPassword=${S("odbc")}\n`, secret: S("odbc") },
  { tool: "wakatime", path: ".wakatime.cfg", content: `[settings]\napi_key = waka_${S("waka")}\n`, secret: S("waka") },
  // ── keys and keychains ──
  { tool: "ssh: private key", path: ".ssh/id_ed25519", content: `-----BEGIN OPENSSH PRIVATE KEY-----\n${S("ssh")}\n-----END OPENSSH PRIVATE KEY-----\n`, secret: S("ssh") },
  { tool: "ssh: config SetEnv token", path: ".ssh/config", content: `Host ci\n  HostName ci.example\n  SetEnv CI_TOKEN=${S("sshenv")}\n`, secret: S("sshenv") },
  { tool: "ssh: custom-named key", path: ".ssh/deploy_prod", content: `-----BEGIN OPENSSH PRIVATE KEY-----\n${S("sshc")}\n-----END OPENSSH PRIVATE KEY-----\n`, secret: S("sshc") },
  { tool: "gpg: private keys", path: ".gnupg/private-keys-v1.d/ABCD.key", content: `Created: 20260101\nKey: (private-key ${S("gpg")})\n`, secret: S("gpg") },
  { tool: "pass: password store", path: ".password-store/web/example.gpg", content: `\u0085\u0001${S("pass")}`, secret: S("pass") },
  { tool: "gnome keyring", path: ".local/share/keyrings/login.keyring", content: `GnomeKeyring\n${S("keyring")}`, secret: S("keyring") },
  { tool: "private key in a project (PEM)", path: "work/api/certs/server.key", content: `-----BEGIN RSA PRIVATE KEY-----\n${S("pem")}\n-----END RSA PRIVATE KEY-----\n`, secret: S("pem") },
  { tool: "PKCS#12 bundle in a project", path: "work/api/certs/client.p12", content: `0\u0082${S("p12")}`, secret: S("p12") },
  // ── project files ──
  { tool: "dotenv", path: "work/api/.env", content: `DATABASE_URL=postgres://app:${S("dotenv")}@db/app\n`, secret: S("dotenv") },
  { tool: "dotenv variant", path: "work/api/.env.local", content: `STRIPE_KEY=${S("envlocal")}\n`, secret: S("envlocal") },
  { tool: "dotenv under a name", path: "work/api/prod.env", content: `API_TOKEN=${S("prodenv")}\n`, secret: S("prodenv") },
  { tool: "secrets json", path: "work/api/secrets.json", content: `{"api_key":"${S("secjson")}"}`, secret: S("secjson") },
  { tool: "rails master key", path: "work/app/config/master.key", content: `${S("rails")}`, secret: S("rails") },
  { tool: "terraform state", path: "work/infra/terraform.tfstate", content: `{"resources":[{"instances":[{"attributes":{"password":"${S("tfstate")}"}}]}]}`, secret: S("tfstate") },
  { tool: "terraform vars", path: "work/infra/secrets.auto.tfvars", content: `db_password = "${S("tfvars")}"\n`, secret: S("tfvars") },
  { tool: "JetBrains HTTP Client: private environment", path: "work/api/http-client.private.env.json", content: `{"staging":{"user":"ops","password":"${S("httpenv")}"}}`, secret: S("httpenv") },
];

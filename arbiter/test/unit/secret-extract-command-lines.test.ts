/**
 * secret-extract, command lines in list items (2026-10-10, third review):
 * a table of real command lines, each with valueless switches before,
 * between and after its secret flags, in JSON, YAML (block and flow) and
 * TOML lists, both as one item (`sh -c "<line>"`) and as one item per word
 * (an MCP server's `args`).
 *
 * Before: inside one item a regex took the word after ANY flag as that
 * flag's value and went on after it, so a switch before a secret flag
 * swallowed the flag: `curl -s -u admin:pw`, `curl --silent --user a:pw`,
 * `tool --verbose --auth S`, `tool -q --pat S` stayed raw in the twin, and
 * `-H "Authorization: Bearer X"` inside one item was never read. Now the
 * item is read as shell words (`commandWords`) and every word is judged.
 *
 * Each row says exactly which values the twin masks (`masked`), and every
 * other value it names (`kept`) must stay as written: the table is what
 * docs/guarantees.md §3 and secret-discovery.md §2.5 promise. A property
 * test places the generic secret flags among random switches and shell
 * operators; the last test pins what stays unrecognized, which the same
 * docs list. The table, the property test and the copy test fail against
 * the extractor before this change.
 *
 * Fourth review (2026-10-10): any word whose basename was psql, mysql,
 * docker or podman made it "the program", so a path (`--datadir
 * /var/lib/mysql`), an image (`docker run mcp/mysql`) or a flag's value
 * (`--db-type mysql`) turned off `--password VALUE` (psql's and mysql's
 * prompt) and `-u user:password` (docker's user and group): the password
 * stayed raw. Now those exceptions hold only when the program is the
 * command itself, in command position (the list's `command`, a command's
 * first word past `NAME=` and wrappers such as `sudo -u postgres`, `env`,
 * `timeout 30`, or after `;`, `&&`, `|`, `$(`). The rows below the
 * `-- fourth review --` line are the review's forms; they and the property
 * test's program words fail against the extractor before this change. A
 * `$`-led value is masked unless something resolves it (`${…}` anywhere,
 * `$NAME` where a shell expands it): the last-but-one test.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import yaml from "js-yaml";
import { extractSecretSpans, renderStructuredTwin, type SecretSpan } from "../../policy/secret-extract.js";
import { stateAxes } from "../axes.js";

stateAxes("secrets"); // pure extraction; the twin is the confidentiality axis's

/** A keyed secret: list rules only add to a file whose keys gave one. */
const KEYED = "keyedT0kenValue";
const tok = (s: SecretSpan) => `$MDU:nomodel_Read[abcd].${s.key}`;
// A GitHub token, built at run time so no source line is token-shaped.
const GHP = ["ghp", "Zq4mX9pL2vN7wK3aZ3kQ9mX2pL7vN4w8Rt0Y"].join("_");

interface Row {
  tool: string;
  /** The command line as a shell would read it. */
  line: string;
  /** Exactly the values the twin masks (beside the keyed one). */
  masked: string[];
  /** Words that must stay as written. */
  kept: string[];
  /** Only as one line (it holds a shell operator). */
  lineOnly?: boolean;
  /** What the `argv` form masks instead: there the list's command is `run`,
   *  so the program named in its first item is no command, and psql's
   *  `--password` and docker's `-u` take their values. */
  argv?: { masked: string[]; kept: string[] };
}

const ROWS: Row[] = [
  // curl: -u/--user/-U take user:password (the password is masked); -H/--header a header; -b a cookie.
  { tool: "curl", line: "curl -s -u admin:ZqCurlA1 --fail https://api.example.com/v1/user", masked: ["ZqCurlA1"], kept: ["-s", "admin:", "--fail", "https://api.example.com/v1/user"] },
  { tool: "curl", line: "curl --silent --show-error --user admin:ZqCurlA2 --retry 3 https://api.example.com/v1/user", masked: ["ZqCurlA2"], kept: ["--silent", "--show-error", "admin:", "--retry", "3"] },
  { tool: "curl", line: "curl -s --user=deploy:ZqCurlA3 -X POST https://api.example.com/v1/deploy", masked: ["ZqCurlA3"], kept: ["--user=deploy:", "-X", "POST"] },
  { tool: "curl", line: "curl -fsSL -udeploy:ZqCurlA4 -o out.json https://api.example.com/v1/x", masked: ["ZqCurlA4"], kept: ["-fsSL", "-udeploy:", "-o", "out.json"] },
  { tool: "curl", line: "curl -su admin:ZqCurlA5 -k https://api.example.com/v1/x", masked: ["ZqCurlA5"], kept: ["-su", "admin:", "-k"] },
  { tool: "curl", line: 'curl -sS -H "Authorization: Bearer ZqCurlB1" -H "Content-Type: application/json" -X POST -d @body.json https://api.example.com/v1/items', masked: ["ZqCurlB1"], kept: ["-sS", "Authorization: Bearer ", "Content-Type: application/json", "-d", "@body.json"] },
  { tool: "curl", line: "curl --compressed -H 'X-API-Key: ZqCurlB2' --retry 3 https://api.example.com/v1/items", masked: ["ZqCurlB2"], kept: ["--compressed", "X-API-Key: ", "--retry"] },
  { tool: "curl", line: "curl -s -H X-Api-Key:ZqCurlB3 --location https://api.example.com", masked: ["ZqCurlB3"], kept: ["X-Api-Key:", "--location"] },
  { tool: "curl", line: "curl -s --header 'PRIVATE-TOKEN: ZqCurlB4' --globoff https://gitlab.example.com/api/v4/projects", masked: ["ZqCurlB4"], kept: ["PRIVATE-TOKEN: ", "--globoff"] },
  { tool: "curl", line: 'curl -fsSL -H"Authorization: token ZqCurlB5" https://api.example.com', masked: ["ZqCurlB5"], kept: ["Authorization: token "] },
  { tool: "curl", line: "curl -s -H Authorization:\\ Bearer\\ ZqCurlB6 -v https://api.example.com", masked: ["ZqCurlB6"], kept: ["Authorization: Bearer ", "-v"] },
  { tool: "curl", line: "curl --fail -H 'Authorization: Basic ZGVwbG95OlpxQ3VybEI3' -sS https://api.example.com", masked: ["ZGVwbG95OlpxQ3VybEI3"], kept: ["--fail", "Authorization: Basic ", "-sS"] },
  { tool: "curl", line: "curl -k --oauth2-bearer ZqCurlC1 --location https://api.example.com", masked: ["ZqCurlC1"], kept: ["-k", "--oauth2-bearer", "--location"] },
  { tool: "curl", line: "curl -s -U proxyuser:ZqCurlC2 -x http://proxy.internal:3128 https://example.com", masked: ["ZqCurlC2"], kept: ["proxyuser:", "-x", "http://proxy.internal:3128"] },
  { tool: "curl", line: "curl -s -b session=ZqCurlC3 -L https://example.com/app", masked: ["session=ZqCurlC3"], kept: ["-b", "-L"] },
  { tool: "curl", line: "curl -s -X POST -d 'grant_type=client_credentials&client_id=app&client_secret=ZqCurlC4' --fail https://auth.example.com/token", masked: ["ZqCurlC4"], kept: ["grant_type=client_credentials&client_id=app&client_secret=", "--fail"] },
  { tool: "curl", line: "curl -s https://deploy:ZqCurlC5@files.example.com/release.tar.gz -O", masked: ["ZqCurlC5"], kept: ["https://deploy:", "@files.example.com/release.tar.gz", "-O"] },
  // wget: --password, --http-password, --proxy-password; --header=; --ask-password is a switch.
  { tool: "wget", line: "wget -q --user=deploy --password=ZqWgetA1 -O release.tar.gz https://files.example.com/release.tar.gz", masked: ["ZqWgetA1"], kept: ["-q", "--user=deploy", "--password=", "-O", "release.tar.gz"] },
  { tool: "wget", line: "wget -nv --http-user=deploy --http-password ZqWgetA2 --tries=3 https://files.example.com/x", masked: ["ZqWgetA2"], kept: ["-nv", "--http-user=deploy", "--tries=3"] },
  { tool: "wget", line: 'wget --header="Authorization: Bearer ZqWgetA3" --no-verbose -O - https://api.example.com/v1/me', masked: ["ZqWgetA3"], kept: ["--header=Authorization: Bearer ", "--no-verbose", "-O", "-"] },
  { tool: "wget", line: "wget --proxy-user=px --proxy-password=ZqWgetA4 -e use_proxy=yes https://example.com", masked: ["ZqWgetA4"], kept: ["--proxy-user=px", "use_proxy=yes"] },
  { tool: "wget", line: "wget --ask-password --user=deploy --continue https://files.example.com/x", masked: [], kept: ["--ask-password", "--user=deploy", "--continue", "https://files.example.com/x"] },
  // httpie: -a/--auth user:password (the password), a token alone (whole); header and data items.
  { tool: "httpie", line: "http -a admin:ZqHttpA1 --check-status GET https://api.example.com/v1/user", masked: ["ZqHttpA1"], kept: ["admin:", "--check-status", "GET"] },
  { tool: "httpie", line: "http --auth admin:ZqHttpA2 --follow POST https://api.example.com/v1/items name=widget", masked: ["ZqHttpA2"], kept: ["admin:", "--follow", "name=widget"] },
  { tool: "httpie", line: "http -A bearer -a ZqHttpA3 --print=b GET https://api.example.com/v1/me", masked: ["ZqHttpA3"], kept: ["-A", "bearer", "--print=b"] },
  { tool: "httpie", line: 'https --verify=no GET api.example.com/v1/me Authorization:"Bearer ZqHttpA4" X-Request-Id:abc123', masked: ["ZqHttpA4"], kept: ["--verify=no", "Authorization:Bearer ", "X-Request-Id:abc123"] },
  { tool: "httpie", line: "http --ignore-stdin POST https://api.example.com/v1/login username=admin password=ZqHttpA5 api_key==ZqHttpA6", masked: ["ZqHttpA5", "ZqHttpA6"], kept: ["--ignore-stdin", "username=admin", "password=", "api_key=="] },
  // psql: a URL's password, PGPASSWORD=, a conninfo string; --password is a switch.
  { tool: "psql", line: 'psql "postgresql://app:ZqPsqlA1@db.internal:5432/prod" --no-psqlrc -c "select 1"', masked: ["ZqPsqlA1"], kept: ["postgresql://app:", "@db.internal:5432/prod", "--no-psqlrc", "select 1"] },
  { tool: "psql", line: "PGPASSWORD=ZqPsqlA2 psql -h db.internal -U app -d prod --no-psqlrc", masked: ["ZqPsqlA2"], kept: ["PGPASSWORD=", "psql", "db.internal", "-U", "app", "prod", "--no-psqlrc"] },
  { tool: "psql", line: 'psql -X "host=db.internal port=5432 user=app password=ZqPsqlA3 dbname=prod sslmode=require" -At', masked: ["ZqPsqlA3"], kept: ["host=db.internal port=5432 user=app password=", " dbname=prod sslmode=require", "-At"] },
  { tool: "psql", line: "psql -h db.internal -U app --password prod", masked: [], kept: ["-h", "db.internal", "app", "--password", "prod"], argv: { masked: ["prod"], kept: ["-h", "db.internal", "app", "--password"] } },
  // mysql: -p glued only, --password= ; -p alone and --password alone ask.
  { tool: "mysql", line: 'mysql -h db.internal -u root -pZqMysqlA1 --batch -e "show databases"', masked: ["ZqMysqlA1"], kept: ["root", "-p", "--batch", "show databases"] },
  { tool: "mysql", line: "mysql --host=db.internal --user=root --password=ZqMysqlA2 --silent prod", masked: ["ZqMysqlA2"], kept: ["--user=root", "--password=", "--silent", "prod"] },
  { tool: "mysql", line: "mysqldump -uroot -pZqMysqlA3 --single-transaction --routines prod", masked: ["ZqMysqlA3"], kept: ["-uroot", "--single-transaction", "--routines", "prod"] },
  { tool: "mysql", line: 'MYSQL_PWD=ZqMysqlA4 mysql -u root -N -e "select 1"', masked: ["ZqMysqlA4"], kept: ["MYSQL_PWD=", "root", "-N", "select 1"] },
  { tool: "mysql", line: "mysql -u root -p --skip-column-names prod", masked: [], kept: ["root", "-p", "--skip-column-names", "prod"] },
  { tool: "mysql", line: "mysql -u root --password --skip-column-names prod", masked: [], kept: ["--password", "--skip-column-names", "prod"] },
  // docker login: -p after `login`; -u is the user; docker run's -p is a port and -u a user and group.
  { tool: "docker login", line: "docker login -u deploy -p ZqDockA1 registry.example.com", masked: ["ZqDockA1"], kept: ["-u", "deploy", "-p", "registry.example.com"] },
  { tool: "docker login", line: "docker --debug login --username deploy --password=ZqDockA2 registry.example.com", masked: ["ZqDockA2"], kept: ["--debug", "--username", "deploy", "registry.example.com"] },
  { tool: "docker login", line: "docker login -u deploy -pZqDockA3 ghcr.io", masked: ["ZqDockA3"], kept: ["deploy", "ghcr.io"] },
  { tool: "docker login", line: "podman login --tls-verify=false -u deploy -p ZqDockA4 --verbose quay.io", masked: ["ZqDockA4"], kept: ["--tls-verify=false", "deploy", "--verbose", "quay.io"] },
  { tool: "docker login", line: "docker run -d -p 8080:80 -u 1000:1000 --rm -e LOG_LEVEL=debug -u app:staff nginx:1.27", masked: [], kept: ["8080:80", "1000:1000", "LOG_LEVEL=debug", "app:staff", "nginx:1.27"], argv: { masked: ["staff"], kept: ["8080:80", "1000:1000", "LOG_LEVEL=debug", "app:", "nginx:1.27"] } },
  { tool: "docker login", line: "docker run --rm -e API_KEY=ZqDockA5 -e LOG_LEVEL=info ghcr.io/acme/tool:1.2 --verbose", masked: ["ZqDockA5"], kept: ["API_KEY=", "LOG_LEVEL=info", "ghcr.io/acme/tool:1.2", "--verbose"] },
  // gh: GH_TOKEN=, a header, `secret set --body`/`-b`; `auth login -p` is a protocol; --body elsewhere is text.
  { tool: "gh", line: 'GH_TOKEN=ZqGhA1 gh api -H "Accept: application/vnd.github+json" --paginate /repos/acme/app/releases', masked: ["ZqGhA1"], kept: ["Accept: application/vnd.github+json", "--paginate", "/repos/acme/app/releases"] },
  { tool: "gh", line: 'gh api -H "Authorization: token ZqGhA2" --paginate /user/repos', masked: ["ZqGhA2"], kept: ["Authorization: token ", "--paginate", "/user/repos"] },
  { tool: "gh", line: "gh secret set DEPLOY_KEY --body ZqGhA3 --repo acme/app", masked: ["ZqGhA3"], kept: ["DEPLOY_KEY", "--body", "--repo", "acme/app"] },
  { tool: "gh", line: "gh secret set API_TOKEN -b ZqGhA4 -R acme/app", masked: ["ZqGhA4"], kept: ["API_TOKEN", "-b", "-R", "acme/app"] },
  { tool: "gh", line: "gh auth login -p https -h github.com --with-token", masked: [], kept: ["-p", "https", "github.com", "--with-token"] },
  { tool: "gh", line: 'gh issue create --title Bug --body "steps to reproduce" --label bug', masked: [], kept: ["--title", "Bug", "steps to reproduce", "--label"] },
  // npm: an _authToken setting (config set, =, a --//…:_authToken= flag), NPM_TOKEN=, a registry URL's password.
  { tool: "npm", line: "npm config set //registry.npmjs.org/:_authToken ZqNpmA1 --location=user", masked: ["ZqNpmA1"], kept: ["config", "set", "//registry.npmjs.org/:_authToken", "--location=user"] },
  { tool: "npm", line: "npm config set //npm.pkg.github.com/:_authToken=ZqNpmA2 --location=project", masked: ["ZqNpmA2"], kept: ["//npm.pkg.github.com/:_authToken=", "--location=project"] },
  { tool: "npm", line: "NPM_TOKEN=ZqNpmA3 npm publish --access public --dry-run", masked: ["ZqNpmA3"], kept: ["NPM_TOKEN=", "publish", "--access", "public", "--dry-run"] },
  { tool: "npm", line: "npm publish --//registry.npmjs.org/:_authToken=ZqNpmA4 --tag beta", masked: ["ZqNpmA4"], kept: ["--//registry.npmjs.org/:_authToken=", "--tag", "beta"] },
  { tool: "npm", line: "npm install --registry=https://ci:ZqNpmA5@npm.example.com/ --no-audit --verbose", masked: ["ZqNpmA5"], kept: ["--registry=https://ci:", "@npm.example.com/", "--no-audit", "--verbose"] },
  { tool: "npm", line: "npm login --auth-type=legacy --registry https://registry.npmjs.org/", masked: [], kept: ["--auth-type=legacy", "--registry", "https://registry.npmjs.org/"] },
  // git: credentials in URLs; an extraHeader through -c; a setting by its name.
  { tool: "git", line: "git clone --depth 1 https://oauth2:ZqGitA1@gitlab.example.com/acme/app.git", masked: ["ZqGitA1"], kept: ["--depth", "https://oauth2:", "@gitlab.example.com/acme/app.git"] },
  { tool: "git", line: 'git -c http.extraHeader="Authorization: Bearer ZqGitA2" clone --quiet https://github.com/acme/app.git', masked: ["ZqGitA2"], kept: ["http.extraHeader=Authorization: Bearer ", "--quiet", "https://github.com/acme/app.git"] },
  { tool: "git", line: "git remote set-url origin https://x-access-token:ZqGitA3@github.com/acme/app.git", masked: ["ZqGitA3"], kept: ["set-url", "origin", "https://x-access-token:"] },
  { tool: "git", line: "git push --force-with-lease https://deploy:ZqGitA4@git.example.com/acme/app.git HEAD:main", masked: ["ZqGitA4"], kept: ["--force-with-lease", "HEAD:main"] },
  { tool: "git", line: `git clone --quiet https://${GHP}@github.com/acme/app.git`, masked: [GHP], kept: ["--quiet", "@github.com/acme/app.git"] },
  { tool: "git", line: "git config --global credential.helper store", masked: [], kept: ["--global", "credential.helper", "store"] },
  { tool: "git", line: "git config --global user.password ZqGitA5", masked: ["ZqGitA5"], kept: ["--global", "user.password"] },
  // The review's own forms, and a secret flag's value given glued, after `=`, or dash-led.
  { tool: "other", line: "tool --verbose --auth ZqToolA1 --dry-run", masked: ["ZqToolA1"], kept: ["--verbose", "--auth", "--dry-run"] },
  { tool: "other", line: "tool -q --pat ZqToolA2 -v", masked: ["ZqToolA2"], kept: ["-q", "--pat", "-v"] },
  { tool: "other", line: "tool --skip-auth -u a:ZqToolA3 --verbose -u b:ZqToolA4", masked: ["ZqToolA3", "ZqToolA4"], kept: ["--skip-auth", "a:", "--verbose", "b:"] },
  { tool: "other", line: "tool --api-key -Xk9mQ2vL8pR4wT6 --log-level=debug", masked: ["-Xk9mQ2vL8pR4wT6"], kept: ["--api-key", "--log-level=debug"] },
  { tool: "other", line: "tool -password ZqToolA5 -token=ZqToolA6 -v", masked: ["ZqToolA5", "ZqToolA6"], kept: ["-password", "-token=", "-v"] },
  { tool: "other", line: "sshpass -p ZqToolA7 ssh -o StrictHostKeyChecking=no deploy@host.internal", masked: ["ZqToolA7"], kept: ["-p", "-o", "StrictHostKeyChecking=no", "deploy@host.internal"] },
  { tool: "other", line: "redis-cli -h cache.internal -p 6379 -a ZqToolA8 --no-auth-warning ping", masked: ["ZqToolA8"], kept: ["-p", "6379", "--no-auth-warning", "ping"] },
  // A shell operator starts a new command: docker's `-u x:y` is a user and group, curl's after `&&` is a password.
  { tool: "other", line: "docker run -u app:grp img && curl -s -u frank:ZqToolA9 https://h.example", masked: ["ZqToolA9"], kept: ["app:grp", "frank:"], lineOnly: true },
  { tool: "other", line: "tool --token ZqToolB1; tool --token <file.txt --verbose", masked: ["ZqToolB1"], kept: ["file.txt", "--verbose"], lineOnly: true },
  // A command substitution is a command of its own: `--token $(…)` takes no value, the command inside is read.
  { tool: "other", line: "tool --token $(cat ~/.token) --home $HOME --verbose", masked: [], kept: ["--token", "$(cat", "~/.token)", "$HOME"], lineOnly: true },
  { tool: "other", line: "TOKEN=$(curl -s -u admin:ZqToolB3 https://h.example/t) tool --verbose", masked: ["ZqToolB3"], kept: ["TOKEN=$(curl", "admin:", "--verbose"], lineOnly: true },
  // A command line two quotes deep inside the line (the line, `bash -c "…"`, `'…'`).
  { tool: "other", line: `sh -c "bash -c 'curl -s -u admin:ZqToolB2 https://h.example'"`, masked: ["ZqToolB2"], kept: ["bash -c 'curl -s -u admin:"] },
  // -- fourth review --: a word that only NAMES psql, mysql, docker or podman (a path, an image,
  // a flag's value, a subcommand, a wrapper's option value) is no command: --password and -u take their values.
  { tool: "program", line: "backup-tool --datadir /var/lib/mysql --user root --password ZqProgA1", masked: ["ZqProgA1"], kept: ["--datadir", "/var/lib/mysql", "--user", "root", "--password"] },
  { tool: "program", line: "tool --db-type mysql --host db --password ZqProgA2", masked: ["ZqProgA2"], kept: ["--db-type", "mysql", "--host", "db", "--password"] },
  { tool: "program", line: "tool --client psql --password ZqProgA3", masked: ["ZqProgA3"], kept: ["--client", "psql", "--password"] },
  { tool: "program", line: "docker run -i --rm mcp/mysql --password ZqProgA4", masked: ["ZqProgA4"], kept: ["run", "-i", "--rm", "mcp/mysql", "--password"] },
  { tool: "program", line: "npx -y mysql --password ZqProgA5", masked: ["ZqProgA5"], kept: ["-y", "mysql", "--password"] },
  { tool: "program", line: "goose mysql --password ZqProgA6 status", masked: ["ZqProgA6"], kept: ["goose", "mysql", "--password", "status"] },
  { tool: "program", line: "tool --runtime docker --user admin:ZqProgA7", masked: ["ZqProgA7"], kept: ["--runtime", "docker", "--user", "admin:"] },
  { tool: "program", line: "tool --docker-bin /usr/bin/docker --user admin:ZqProgA8", masked: ["ZqProgA8"], kept: ["--docker-bin", "/usr/bin/docker", "admin:"] },
  { tool: "program", line: "tool --engine podman -u admin:ZqProgA9", masked: ["ZqProgA9"], kept: ["--engine", "podman", "-u", "admin:"] },
  { tool: "program", line: "tool --db-type mysql -password ZqProgB1", masked: ["ZqProgB1"], kept: ["--db-type", "mysql", "-password"] },
  { tool: "program", line: "sudo -u mysql backup-tool --password ZqProgB2", masked: ["ZqProgB2"], kept: ["-u", "mysql", "backup-tool", "--password"] },
  { tool: "program", line: "docker run --rm img curl -s -u admin:ZqProgB3 https://h.example", masked: ["ZqProgB3"], kept: ["img", "curl", "-s", "admin:"] },
  // After `>`, `)` or a closing backquote comes a file or the rest of a word, never a command.
  { tool: "program", line: "tool >/var/log/mysql --password ZqProgB4", masked: ["ZqProgB4"], kept: ["/var/log/mysql", "--password"], lineOnly: true },
  { tool: "program", line: "tool --dir $(pwd)/mysql --password ZqProgB5", masked: ["ZqProgB5"], kept: ["--dir", "/mysql", "--password"], lineOnly: true },
  { tool: "program", line: "tool --dir `pwd`/psql --password ZqProgB6", masked: ["ZqProgB6"], kept: ["--dir", "/psql", "--password"], lineOnly: true },
  // The exceptions hold where the program IS the command: first, past NAME= and wrappers, or after an operator.
  { tool: "program", line: "sudo -u postgres psql -h db.internal --password prod", masked: [], kept: ["postgres", "psql", "--password", "prod"], argv: { masked: ["prod"], kept: ["postgres", "psql", "--password"] } },
  { tool: "program", line: "env PGHOST=db.internal timeout 30 psql --password prod", masked: [], kept: ["PGHOST=db.internal", "30", "psql", "--password", "prod"], argv: { masked: ["prod"], kept: ["PGHOST=db.internal", "psql", "--password"] } },
  { tool: "program", line: "nice -n 10 docker run -u app:staff img", masked: [], kept: ["docker", "run", "app:staff", "img"], argv: { masked: ["staff"], kept: ["docker", "run", "app:", "img"] } },
  { tool: "program", line: "cd /var/lib/mysql && mysql -u root --password prod", masked: [], kept: ["/var/lib/mysql", "mysql", "--password", "prod"], lineOnly: true },
  { tool: "program", line: "(cd /srv; psql --password prod) | tee out.txt", masked: [], kept: ["/srv", "psql", "--password", "prod", "out.txt"], lineOnly: true },
];

/** The words of a command line, as the shell reads it (for the one-item-per-word form). */
function words(line: string): string[] {
  const out: string[] = [];
  let w: string | null = null;
  for (let i = 0; i < line.length; i++) {
    const c = line[i]!;
    if (c === " ") { if (w !== null) out.push(w); w = null; continue; }
    w ??= "";
    if (c === "'") { const e = line.indexOf("'", i + 1); w += line.slice(i + 1, e); i = e; }
    else if (c === '"') { let j = i + 1; for (; line[j] !== '"'; j++) { if (line[j] === "\\") j++; w += line[j]; } i = j; }
    else if (c === "\\") { w += line[++i]; }
    else w += c;
  }
  if (w !== null) out.push(w);
  return out;
}

type Form = "line" | "argv" | "mcp";

/** Can `items` be written as YAML plain (unquoted) scalars, `block` (`-
 *  item` lines) or flow (`[a, b]`), and read back as the same strings? Not
 *  in flow when an item holds a quote or a backslash: its placeholder is
 *  then the whole item (secret-extract-lists.test.ts pins that rule). Not
 *  in a block for `name:value` with a secret-looking name
 *  (`Authorization:Bearer X`, `https://x-access-token:S@host`): YAML's
 *  keyed line reader (unchanged since 2026-09-24) takes that line for a
 *  key and masks its whole value, more than the list rules do. */
function yamlPlain(items: string[], block: boolean): boolean {
  if (items.some((a) => a === "" || /[\n\r]/.test(a) || (!block && /["'\\]/.test(a)))) return false;
  const keyed = (a: string) => /pass|secret|token|key|auth|cred|pwd/i.test(/^([A-Za-z0-9_.:/-]+):\s*\S/.exec(a)?.[1] ?? "");
  if (block && items.some(keyed)) return false;
  const text = block ? `l:\n${items.map((a) => `  - ${a}\n`).join("")}` : `l: [${items.join(", ")}]\n`;
  try {
    const l = (yaml.load(text) as { l: unknown[] }).l;
    return Array.isArray(l) && l.length === items.length && l.every((v, i) => v === items[i]);
  } catch {
    return false;
  }
}

/** The row as files: each format (JSON, YAML block and flow, quoted and,
 *  where every item reads back as the same string, plain; TOML) and each
 *  form on its own, so no form's placeholder masks another's copy:
 *  `line`, the line as one item after `sh -c`; `argv`, its words as the
 *  items of a list; `mcp`, an MCP server's shape, the program as `command`
 *  and the other words as `args` (a row that starts with a program). Not
 *  `argv` or `mcp` for a `lineOnly` row. `items` reads the list back. */
function files(row: Row): Array<{ format: string; form: Form; path: string; content: string; items: (twin: string) => string[] }> {
  const q = (s: string) => JSON.stringify(s);
  const out: Array<{ format: string; form: Form; path: string; content: string; items: (twin: string) => string[] }> = [];
  const argv = words(row.line);
  const forms: Form[] = row.lineOnly ? ["line"] : argv[0]!.includes("=") ? ["line", "argv"] : ["line", "argv", "mcp"];
  for (const form of forms) {
    const list = form === "line" ? ["-c", row.line] : form === "argv" ? argv : argv.slice(1);
    const command = form === "line" ? "sh" : form === "argv" ? "run" : argv[0]!;
    out.push(
      {
        format: "json", form, path: "/w/mcp.json", content: JSON.stringify({ token: KEYED, srv: { command, args: list } }, null, 2),
        items: (t) => (JSON.parse(t) as { srv: { args: string[] } }).srv.args,
      },
      {
        format: "yaml block", form, path: "/w/config.yaml", content: `token: ${KEYED}\nsrv:\n  command: ${q(command)}\n  args:\n${list.map((a) => `    - ${q(a)}\n`).join("")}`,
        items: (t) => (yaml.load(t) as { srv: { args: string[] } }).srv.args,
      },
      {
        format: "yaml flow", form, path: "/w/config.yaml", content: `token: ${KEYED}\nsrv:\n  command: ${q(command)}\n  args: [${list.map(q).join(", ")}]\n`,
        items: (t) => (yaml.load(t) as { srv: { args: string[] } }).srv.args,
      },
      {
        // TOML basic strings are JSON strings here (ASCII, `\"` and `\\`).
        format: "toml", form, path: "/w/config.toml", content: `token = ${q(KEYED)}\n\n[srv]\ncommand = ${q(command)}\nargs = [${list.map(q).join(", ")}]\n`,
        items: (t) => JSON.parse(/\nargs = (\[.*\])\n/.exec(t)![1]!) as string[],
      },
    );
    if (yamlPlain(list, true)) {
      out.push({
        format: "yaml plain", form, path: "/w/config.yaml", content: `token: ${KEYED}\nsrv:\n  command: ${q(command)}\n  args:\n${list.map((a) => `    - ${a}\n`).join("")}`,
        items: (t) => (yaml.load(t) as { srv: { args: string[] } }).srv.args,
      });
    }
    // Two placeholders in one plain flow item become one (the documented merge): not here.
    const secrets = [...row.masked, ...(row.argv?.masked ?? [])];
    if (yamlPlain(list, false) && list.every((a) => secrets.filter((m) => a.includes(m)).length <= 1)) {
      out.push({
        format: "yaml flow plain", form, path: "/w/config.yaml", content: `token: ${KEYED}\nsrv:\n  command: ${q(command)}\n  args: [${list.join(", ")}]\n`,
        items: (t) => (yaml.load(t) as { srv: { args: string[] } }).srv.args,
      });
    }
  }
  return out;
}

test("a table of real command lines (curl, wget, httpie, psql, mysql, docker login, gh, npm, git, and words that only name a program): switches before, between and after a secret flag hide nothing; exactly the secrets are masked, in JSON, YAML (block, flow, plain) and TOML, as one item and as one item per word", () => {
  let cases = 0;
  let plain = 0;
  let expected = 0;
  for (const row0 of ROWS) {
    expected += 4 * (row0.lineOnly ? 1 : words(row0.line)[0]!.includes("=") ? 2 : 3);
    for (const f of files(row0)) {
      const row = f.form === "argv" && row0.argv !== undefined ? { ...row0, ...row0.argv } : row0;
      if (f.format.includes("plain")) plain++;
      const where = `${row.tool} ${f.format} ${f.form}: ${row.line}`;
      const x = extractSecretSpans(f.path, f.content);
      assert.ok(x.shape !== null, `${where}: a structured twin`);
      const text = renderStructuredTwin(f.content, x.spans, tok);
      // 1. No raw secret anywhere in the twin.
      for (const s of row.masked) assert.ok(!text.includes(s), `CONFIDENTIALITY VIOLATION (${where}): ${s} is raw in the twin:\n${text}`);
      // 2. Exactly these values are masked, each as a value of its own, and nothing else.
      const values = x.spans.flatMap((s) => [s.value, ...(s.parts ?? []).map((p) => p.value)]).filter((v) => v !== KEYED);
      const want = new Set(row.masked);
      for (const v of values) assert.ok(want.has(v), `${where}: masked ${JSON.stringify(v)}, which is no secret of the row`);
      for (const s of row.masked) assert.ok(values.includes(s), `${where}: ${s} is masked as a value of its own`);
      // 3. The twin still parses, one item per item, and every ordinary word is as written.
      const items = f.items(text);
      const original = f.items(f.content);
      assert.equal(items.length, original.length, `${where}: the list keeps its items`);
      const read = f.form === "line" ? words(items[1]!).join(" ") : [f.form === "mcp" ? words(row.line)[0] : "", ...items].join(" ");
      for (const k of row.kept) assert.ok(read.includes(k), `${where}: ${JSON.stringify(k)} stays as written: ${read}`);
      cases++;
    }
  }
  assert.equal(cases - plain, expected, "every row in JSON, both quoted YAML forms and TOML");
  assert.ok(plain > 150, `${plain} plain YAML cases`);
  // Every review form that leaked is also written as YAML plain, block and flow, in each of its forms.
  for (const row of ROWS.filter((r) => r.tool === "program" && !r.lineOnly && r.masked.length > 0)) {
    for (const form of ["line", "argv", "mcp"] as const) {
      for (const format of ["yaml plain", "yaml flow plain"]) {
        assert.ok(files(row).some((f) => f.form === form && f.format === format), `${row.line}: ${format} ${form}`);
      }
    }
  }
  assert.ok(cases > 900, `${cases} cases`);
});

test("random command lines: a secret after any of the generic secret flags is masked wherever switches, operators, other flags and words that only name a program stand around it, as one item and as one item per word", () => {
  // Words that name psql, mysql, docker or podman without being the command
  // (a flag's value, a path, an image, a file after `>`, the rest of a word
  // after `$(…)`): before the fourth review each turned `--password S` or
  // `-u admin:S` after it into a prompt or a user and group.
  const SWITCHES = ["-s", "-v", "--verbose", "-q", "--silent", "-fsSL", "--fail", "-k", "-L", "--skip-auth", "--exclude-pat", "--ask-password", "-X", "POST",
    "-o", "out.txt", "--", "-", "-1", "--retry", "3", "&&", ";", "|", "x", "https://h.example/p", "-c", "--no-auth", "-e", "LOG=1",
    "--db-type mysql", "--datadir /var/lib/mysql", "--client psql", "--image mcp/mysql", "--runtime docker", "--engine podman",
    "--docker-bin /usr/bin/docker", "--log >/var/log/mysql", "--dir $(pwd)/psql"];
  const PROGRAMS = ["curl", "wget", "tool", "git", "npm", "gh", "env", "/usr/bin/curl", "sudo"];
  const FORMS: Array<(s: string) => string> = [
    (s) => `-u admin:${s}`, (s) => `--user admin:${s}`, (s) => `--user=admin:${s}`, (s) => `-uadmin:${s}`, (s) => `-su admin:${s}`, (s) => `--proxy-user px:${s}`,
    (s) => `--auth ${s}`, (s) => `--pat ${s}`, (s) => `--token ${s}`, (s) => `--token=${s}`, (s) => `--api-key ${s}`, (s) => `--secret "${s}"`,
    (s) => `-H "Authorization: Bearer ${s}"`, (s) => `--header 'X-API-Key: ${s}'`, (s) => `-H X-Auth-Token:${s}`, (s) => `API_KEY=${s}`,
    (s) => `https://u:${s}@h.example/x`, (s) => `-password ${s}`, (s) => `--client-secret=${s}`, (s) => `--password ${s}`,
  ];
  let seed = 20261010;
  const rand = (n: number): number => { seed ^= seed << 13; seed >>>= 0; seed ^= seed >>> 17; seed ^= seed << 5; seed >>>= 0; return seed % n; };
  let placed = 0;
  let named = 0;
  for (let it = 0; it < 3000; it++) {
    const parts = [PROGRAMS[rand(PROGRAMS.length)]!];
    const secrets: string[] = [];
    for (let k = 0, n = 1 + rand(7); k < n; k++) {
      if (rand(2) === 0) parts.push(SWITCHES[rand(SWITCHES.length)]!);
      else { const s = `Zr${it}w${k}q`; secrets.push(s); parts.push(FORMS[rand(FORMS.length)]!(s)); }
    }
    const line = parts.join(" ");
    if (/mysql|psql|docker|podman/.test(line) && secrets.length > 0) named++;
    // `>` and `$(…)` are operators only in a line, so those switches go to the one-item form.
    for (const args of /[>$]/.test(line) ? [["-c", line]] : [["-c", line], words(line)]) {
      const c = JSON.stringify({ token: KEYED, args });
      const text = renderStructuredTwin(c, extractSecretSpans("/w/r.json", c).spans, tok);
      for (const s of secrets) assert.ok(!text.includes(s), `CONFIDENTIALITY VIOLATION: ${s} is raw in ${JSON.stringify(args)}:\n${text}`);
      placed += secrets.length;
    }
  }
  assert.ok(placed > 5000, `${placed} secrets placed`);
  assert.ok(named > 800, `${named} lines with a word that names a program`);
});

test("a value that is only punctuation (`--token $`, `-u a:*`) is no secret: it would replace the same punctuation all over the twin", () => {
  const c = JSON.stringify({ token: KEYED, note: "costs $5 * 2", args: ["--token", "$", "-u", "a:*", "-c", "tool --password '-' --home $HOME"] });
  const x = extractSecretSpans("/w/p.json", c);
  assert.deepEqual(x.spans.map((s) => s.value), [KEYED]);
  assert.equal((JSON.parse(renderStructuredTwin(c, x.spans, tok)) as { note: string }).note, "costs $5 * 2");
});

test("a copy of a command line's secret elsewhere in the file is masked too, with that secret's own placeholder", () => {
  const c = JSON.stringify({ token: KEYED, note: "ZqCopyA1", args: ["-c", "curl -s -u admin:ZqCopyA1 -H 'Authorization: Bearer ZqCopyA2' https://h.example"], other: "ZqCopyA2" });
  const x = extractSecretSpans("/w/c.json", c);
  const text = renderStructuredTwin(c, x.spans, tok);
  for (const s of ["ZqCopyA1", "ZqCopyA2"]) assert.ok(!text.includes(s), `CONFIDENTIALITY VIOLATION: ${s}:\n${text}`);
  const p = JSON.parse(text) as { note: string; other: string; args: string[] };
  assert.equal(p.note, "$MDU:nomodel_Read[abcd].args.1.password");
  assert.equal(p.other, "$MDU:nomodel_Read[abcd].args.1");
  assert.equal(p.args[1], "curl -s -u admin:$MDU:nomodel_Read[abcd].args.1.password -H 'Authorization: Bearer $MDU:nomodel_Read[abcd].args.1' https://h.example");
});

test("reading a command line stays linear: no adversarial 256 KB item blocks the arbiter for seconds", () => {
  // A wall-clock bound, the cost that matters on the arbiter's event loop,
  // set where a load spike cannot reach it and a quadratic always does:
  // the quadratic URL regex the first review found took 9.4 s for ONE
  // 256 KB item (each content here holds two); a loaded CI runner took
  // 1.2 s for "-H " (MR !1222, job 15574) that takes ~0.1 s on a quiet
  // host, and a growth ratio flaked under load (a GC pause in one run).
  const K = 1024;
  const items = [
    "-s ".repeat(85 * K),
    "-u ".repeat(85 * K),
    "--token ".repeat(32 * K),
    "-H ".repeat(85 * K),
    "Authorization: ".repeat(17 * K),
    '"'.repeat(256 * K),
    "'".repeat(256 * K),
    "\\".repeat(256 * K),
    '"a b" '.repeat(43 * K),
    `sh -c "${"bash -c 'x ".repeat(23 * K)}"`,
    "a=".repeat(128 * K),
    "a=1&".repeat(64 * K),
    `${"x".repeat(256 * K)}=`,
    `-${"s".repeat(256 * K)}`,
    `--${"a".repeat(256 * K)}`,
    "config set ".repeat(23 * K),
    // Fourth review: wrapper chains, assignments, literal `$`s, backquotes.
    "sudo -u x env A=1 timeout 3 ".repeat(9 * K),
    "A=1 ".repeat(64 * K),
    "'$a' ".repeat(51 * K),
    "`x".repeat(128 * K),
    `--password '${"$".repeat(256 * K)}'`,
  ];
  for (const item of items) {
    const content = JSON.stringify({ token: KEYED, args: ["-c", item, item] });
    let best = Infinity;
    for (let r = 0; r < 2; r++) {
      const t0 = performance.now();
      extractSecretSpans("/w/a.json", content);
      best = Math.min(best, performance.now() - t0);
    }
    assert.ok(best < 5000, `${JSON.stringify(item.slice(0, 24))}…: ${Math.round(best)} ms`);
  }
});

/** The values a JSON file's `srv` list masks (beside the keyed one), the
 *  list given with or without a `command`. */
function maskedValues(args: string[], command?: string): string[] {
  const c = JSON.stringify({ token: KEYED, srv: command === undefined ? { args } : { command, args } });
  const x = extractSecretSpans("/w/v.json", c);
  const text = renderStructuredTwin(c, x.spans, tok);
  const values = x.spans.flatMap((s) => [s.value, ...(s.parts ?? []).map((p) => p.value)]).filter((v) => v !== KEYED);
  for (const v of values) assert.ok(!text.includes(v), `CONFIDENTIALITY VIOLATION: ${v} is raw:\n${text}`);
  return values;
}

test("command position (fourth review): psql's --password and docker's -u keep their exceptions only for the command word, found past NAME=, wrappers and their options, and operators that start a command", () => {
  // The program IS the command: `prod` is psql's database, `app:staff` docker's user and group.
  const KEPT = [
    "psql --password prod", "PGHOST=db PGUSER=app psql --password prod", "/usr/lib/postgresql/16/bin/psql --password prod",
    "sudo -u postgres psql --password prod", "sudo -iu postgres psql --password prod", "sudo -E --user=postgres -- psql --password prod",
    "sudo -upostgres PGHOST=db psql --password prod", "doas -u postgres psql --password prod",
    "env -i PGHOST=db psql --password prod", "env - psql --password prod", "env -u HOME --chdir /srv psql --password prod",
    "nice -n 5 psql --password prod", "nice -10 psql --password prod", "nohup psql --password prod",
    "timeout -s KILL 30 psql --password prod", "timeout --kill-after=5 30s psql --password prod", "exec -a pg psql --password prod",
    "command -p psql --password prod", "xargs -0 -n 1 -I {} psql --password prod", "time -p psql --password prod",
    "stdbuf -oL -e L psql --password prod", "ionice -c 3 psql --password prod", "setsid -f psql --password prod",
    "sudo -u postgres env PGHOST=db nice -n 5 timeout 30 psql --password prod",
    "docker run -u app:staff img", "podman run --rm -u app:staff img", "sudo docker run -u app:staff img",
  ];
  for (const line of KEPT) {
    const [command, ...args] = words(line);
    assert.deepEqual(maskedValues(["-c", line], "sh"), [], `line: ${line}`);
    assert.deepEqual(maskedValues(args, command), [], `command + args: ${line}`);
  }
  // A shell operator that starts a command makes the word after it the command word.
  for (const line of ["cd /var/lib/mysql && mysql --password prod", "make dump | psql --password prod", "true; psql --password prod",
    "X=$(psql --password prod)", "X=`psql --password prod`", "(psql --password prod)", "if psql --password prod; then echo ok; fi",
    "tool & psql --password prod", "tool || psql --password prod"]) {
    assert.deepEqual(maskedValues(["-c", line], "sh"), [], `line: ${line}`);
  }
  // The program is NOT the command word: the value is masked.
  const MASKED: Array<[string, string]> = [
    ["tool --db-type mysql --password ZqPosA1", "ZqPosA1"],
    ["tool /var/lib/mysql --password ZqPosA2", "ZqPosA2"],
    ["sudo -u mysql tool --password ZqPosA3", "ZqPosA3"],
    ["sudo -h mysql --password ZqPosA4", "ZqPosA4"], // `-h`: help or a host, an option Mandu does not know
    ["sudo --host mysql tool --password ZqPosA5", "ZqPosA5"],
    ["env -C /var/lib/mysql tool --password ZqPosA6", "ZqPosA6"],
    ["timeout mysql --password ZqPosA7", "ZqPosA7"], // timeout's duration
    ["xargs -I mysql tool --password ZqPosA8", "ZqPosA8"],
    ["command -v mysql --password ZqPosA9", "ZqPosA9"],
    ["nice -n 5 tool --client psql --password ZqPosB1", "ZqPosB1"],
    ["docker exec db psql --password ZqPosB2", "ZqPosB2"], // docker is the command; psql only a word after it
    ["sudo -u docker tool -u admin:ZqPosB3", "ZqPosB3"],
    ["docker run --rm img curl -u admin:ZqPosB4", "ZqPosB4"],
    ["tool --runtime docker run -u admin:ZqPosB5", "ZqPosB5"],
  ];
  for (const [line, secret] of MASKED) {
    const [command, ...args] = words(line);
    assert.ok(maskedValues(["-c", line], "sh").includes(secret), `line: ${line}`);
    assert.ok(maskedValues(args, command).includes(secret), `command + args: ${line}`);
    assert.ok(maskedValues(words(line)).includes(secret), `args with no command: ${line}`);
  }
  // After `>`, `<`, `>&`, `)` or a closing backquote comes no command word.
  for (const [line, secret] of [
    ["tool >/var/log/mysql --password ZqPosC1", "ZqPosC1"], ["tool </var/lib/mysql --password ZqPosC2", "ZqPosC2"],
    ["tool 2>&1 mysql --password ZqPosC3", "ZqPosC3"], ["tool $(pwd)/psql --password ZqPosC4", "ZqPosC4"],
    ["tool `pwd`/psql --password ZqPosC5", "ZqPosC5"], ["tool (x) mysql --password ZqPosC6", "ZqPosC6"],
  ] as const) {
    assert.ok(maskedValues(["-c", line], "sh").includes(secret), `line: ${line}`);
  }
  // A list with no `command` has no command word: its first item may be an argument (Kubernetes `args`).
  assert.deepEqual(maskedValues(["mysql", "--password", "ZqPosD1"]), ["ZqPosD1"]);
  assert.deepEqual(maskedValues(["docker", "run", "-u", "app:ZqPosD2"]), ["ZqPosD2"]);
  // A `command` of several words is read as a command's first words.
  assert.deepEqual(maskedValues(["--password", "prod"], "sudo -u postgres psql"), []);
  assert.deepEqual(maskedValues(["psql", "--password", "prod"], "sudo -u postgres"), []);
  assert.deepEqual(maskedValues(["mysql", "tool", "--password", "ZqPosD3"], "sudo -u"), ["ZqPosD3"]);
});

test("a `$`-led value is masked unless something resolves it: `${…}` anywhere, `$NAME` only where a shell expands it (fourth review)", () => {
  // An item reaches the program as written; an MCP client expands `${…}` only.
  assert.deepEqual(maskedValues(["--password", "$ecretPass99"], "tool"), ["$ecretPass99"]);
  assert.deepEqual(maskedValues(["--password=$ecretPass98", "-u", "admin:$ecretPw97"], "tool"), ["$ecretPass98", "$ecretPw97"]);
  assert.deepEqual(maskedValues(["https://u:$ecretPw96@h.example/x"], "tool"), ["$ecretPw96"]);
  assert.deepEqual(maskedValues(["--password", "${DB_PASS}", "--token=${input:tok}", "-u", "admin:${env:PW}", "https://u:${PW}@h.example/x"], "tool"), []);
  // In a command line the shell expands `$NAME` outside single quotes, unless escaped.
  assert.deepEqual(maskedValues(["-c", "tool --password '$ecretPass95' --verbose"], "sh"), ["$ecretPass95"]);
  assert.deepEqual(maskedValues(["-c", "tool --password \\$ecretPass94"], "sh"), ["$ecretPass94"]);
  assert.deepEqual(maskedValues(["-c", 'tool --password "\\$ecretPass93"'], "sh"), ["$ecretPass93"]);
  assert.deepEqual(maskedValues(["-c", "curl -u 'admin:$ecretPw92' https://h.example"], "sh"), ["$ecretPw92"]);
  assert.deepEqual(maskedValues(["-c", 'tool --password "$DB_PASS" --token $API_TOKEN -u "admin:${PW}" API_KEY=$KEY'], "sh"), []);
  // The keyed value was masked already.
  const c = JSON.stringify({ password: "$ecretPass91" });
  assert.deepEqual(extractSecretSpans("/w/k.json", c).spans.map((s) => s.value), ["$ecretPass91"]);
});

test("what stays unrecognized (docs/guarantees.md §3 lists it): such a secret stays raw in the twin", () => {
  const raw = (line: string, secret: string) => {
    const c = JSON.stringify({ token: KEYED, args: ["-c", line] });
    const text = renderStructuredTwin(c, extractSecretSpans("/w/u.json", c).spans, tok);
    return text.includes(secret);
  };
  // A secret given as a plain argument, or on stdin, has no flag or name to recognize it by.
  assert.ok(raw("cargo login ZqGapA1", "ZqGapA1"));
  assert.ok(raw("echo ZqGapA2 | docker login -u deploy --password-stdin ghcr.io", "ZqGapA2"));
  assert.ok(raw("poetry config http-basic.acme deploy ZqGapA3", "ZqGapA3"));
  // A value that starts with `-` and does not look random is read as the next flag.
  assert.ok(raw("tool --password -hunter2", "-hunter2"));
  // A JSON body, and a URL's query value.
  assert.ok(raw(`curl -d '{"password": "ZqGapA4"}' https://h.example`, "ZqGapA4"));
  assert.ok(raw("curl https://h.example/x?access_token=ZqGapA5", "ZqGapA5"));
  // A word-like token written as a URL's user with no password (a known format is caught: the table's ghp_ row).
  assert.ok(raw("git clone https://ZqGapA6@github.com/acme/app.git", "ZqGapA6"));
  // When docker is the command, `-u x:y` later in it is a user and group, even after the image.
  assert.ok(raw("docker run img tool -u admin:ZqGapA7", "ZqGapA7"));
  // A flag Mandu does not know takes a secret (curl's client certificate password),
  // and a header whose name does not say secret.
  assert.ok(raw("curl -E client.pem:ZqGapA8 https://h.example", "ZqGapA8"));
  assert.ok(raw("curl -H 'X-Custom: ZqGapB1' https://h.example", "ZqGapB1"));
  // A command line nested in more than two levels of quotes inside the line.
  assert.ok(raw(`sh -c "bash -c 'zsh -c \\"curl -u a:ZqGapA9\\"'"`, "ZqGapA9"));
});

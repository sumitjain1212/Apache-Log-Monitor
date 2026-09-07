# Apache-Log-Monitor
# Apache Log Monitor

A lightweight PHP-based web interface for monitoring Apache HTTPD access and error logs across multiple servers.

The application provides a centralized dashboard for:

* Discovering configured Apache hosts
* Listing Apache access logs
* Listing Apache error logs
* Displaying log file sizes
* Live tailing access and error logs
* Configurable refresh intervals
* Filtering live log output
* HTTP response-code highlighting
* Access-log statistics
* Top client IPs
* Top user agents
* HTTP response-code distribution
* Top URLs returning `400` errors
* Top URLs returning `401` errors
* Top URLs returning `403` errors
* Top URLs returning `500` errors
* Recent `404` requests
* Most popular URLs

---

## Features

### 🖥 Host Discovery

Hosts are discovered from a configurable Apache master configuration file.

The application extracts unique host entries and displays them in the Hosts panel.

### 📁 Access and Error Logs

After selecting a host, the application discovers:

```text
*_access_log
*_error_log
```

The log list displays:

* Log filename
* Log type
* Log size

Example:

```text
www_access_log
ACCESS • 1.2G

www_error_log
ERROR • 245M
```

### 📡 Live Log Tail

Select a log to start live monitoring.

Available refresh intervals:

```text
3 seconds
5 seconds
10 seconds
30 seconds
```

The number of displayed lines can be configured.

The dashboard also supports:

* Pause / Resume
* Clear output
* Scroll to bottom
* Text filtering
* Automatic scrolling
* HTTP status-code highlighting

### 📊 Access Log Statistics

Statistics can be generated for access logs.

The analysis includes:

* Total log entries
* First log entry
* Top 10 user agents
* Top 10 client IPs
* HTTP response-code distribution
* Top 10 URLs with HTTP 500
* Top 10 URLs with HTTP 400
* Top 10 URLs with HTTP 401
* Top 10 URLs with HTTP 403
* Last 10 HTTP 404 requests
* Top 10 popular URLs

Statistics are intended for Apache access logs.

Error-log files are available for live tailing but statistics are disabled for them.

---

## Architecture

```text
                   ┌──────────────────────┐
                   │   Web Browser        │
                   │                      │
                   │ Apache Log Monitor   │
                   └──────────┬───────────┘
                              │
                              │ HTTP / AJAX
                              ▼
                   ┌──────────────────────┐
                   │      PHP App         │
                   │ live_http_url.php    │
                   └──────────┬───────────┘
                              │
                              │ SSH
                              ▼
          ┌───────────────────────────────────────┐
          │           Apache Servers              │
          │                                       │
          │  Server 1     Server 2     Server N  │
          │      │            │            │      │
          │      ▼            ▼            ▼      │
          │ access_log    access_log    access_log│
          │ error_log     error_log     error_log │
          └───────────────────────────────────────┘
```

---

## Requirements

### Application Server

* Linux
* Apache HTTPD
* PHP 7.4+ recommended
* OpenSSH client
* SSH access to monitored servers

### Monitored Servers

* Linux
* Apache HTTPD
* Read access to Apache log files
* SSH connectivity from the application server

### PHP Extensions

The application primarily uses standard PHP functionality.

Recommended PHP extensions:

* `json`
* `openssl`
* `curl`

---

## Installation

### 1. Clone the repository

```bash
git clone https://github.com/<YOUR-USERNAME>/apache-log-monitor.git

cd apache-log-monitor
```

### 2. Configure the application

Do not place environment-specific configuration directly into the public source code.

Create your local configuration from the example:

```bash
cp config.example.php config.php
```

Edit:

```bash
vi config.php
```

Configure:

```php
$MASTER_CONF
$SSH_USER
$SSH_KEY
$CONN_TIMEOUT
$MONI_SCRIPT
$LOG_BASE
```

Example:

```php
$MASTER_CONF  = '/path/to/apache_master.conf';
$SSH_USER     = 'monitoruser';
$SSH_KEY      = '/path/to/.ssh/id_rsa';
$CONN_TIMEOUT = 5;
$MONI_SCRIPT  = '/path/to/moni.sh';
$LOG_BASE     = '/path/to/apache/logs';
```

---

## SSH Configuration

The application connects to monitored servers using SSH.

Passwordless SSH authentication is recommended.

Example:

```bash
ssh-keygen -t ed25519
```

Copy the public key to each monitored server:

```bash
ssh-copy-id monitoruser@server.example.com
```

Verify:

```bash
ssh monitoruser@server.example.com
```

The SSH account should have the minimum permissions required to:

* Read Apache logs
* Execute required monitoring commands
* Read the Apache configuration used for host discovery

Avoid using `root` unless absolutely necessary.

---

## Apache Log Permissions

The SSH user must be able to read the configured Apache log directory.

For example:

```bash
ls -lh /path/to/apache/logs/
```

Verify:

```bash
ssh monitoruser@server.example.com \
  'tail -20 /path/to/apache/logs/example_access_log'
```

---

## Configuration

The following configuration values are environment-specific and must be customized before deployment:

| Variable       | Description                                         |
| -------------- | --------------------------------------------------- |
| `MASTER_CONF`  | Apache master configuration used for host discovery |
| `SSH_USER`     | SSH account used to connect to monitored servers    |
| `SSH_KEY`      | SSH private-key path                                |
| `CONN_TIMEOUT` | SSH connection timeout                              |
| `MONI_SCRIPT`  | Optional statistics script                          |
| `LOG_BASE`     | Apache log base directory                           |

The original application contains organization-specific filesystem paths and usernames, so these values should never be committed unchanged to a public repository.

---

## API Endpoints

The PHP application exposes several AJAX actions.

### Load Hosts

```text
?action=hosts
```

Returns the available hosts.

Example:

```json
{
  "hosts": [
    "server01",
    "server02"
  ]
}
```

### List Logs

```text
?action=logs&host=server01
```

Returns access and error logs.

Example:

```json
{
  "logs": [
    {
      "path": "/path/to/example_access_log",
      "name": "example_access_log",
      "size": "1.2G",
      "type": "access"
    },
    {
      "path": "/path/to/example_error_log",
      "name": "example_error_log",
      "size": "250M",
      "type": "error"
    }
  ],
  "error": ""
}
```

### Tail Log

```text
?action=tail&host=server01&log=/path/to/example_access_log&lines=50
```

Returns the latest log lines.

The application limits the requested number of lines to prevent excessively large responses.

### Statistics

```text
?action=stats&host=server01&log=/path/to/example_access_log
```

Runs access-log analysis and returns structured statistics.

---

## Security

This application executes commands on remote servers through SSH.

Before exposing it outside a trusted network, review the following:

### Authentication

Protect the application with authentication.

Recommended options:

* Apache Basic Authentication
* SSO/OIDC
* Reverse-proxy authentication
* VPN-only access

### Authorization

Do not allow arbitrary users to execute arbitrary SSH commands.

The application should restrict:

* Host names
* Log paths
* SSH destinations
* Available commands

### SSH

Use a dedicated non-root SSH account.

Recommended:

```text
monitoruser
```

instead of:

```text
root
```

### Private Keys

Never commit:

```text
*.pem
*.key
id_rsa
id_ed25519
```

to Git.

Store private keys outside the repository.

### Sensitive Configuration

Never commit:

```text
passwords
API tokens
private keys
internal hostnames
internal filesystem paths
company-specific configuration
credentials
```

Use environment-specific configuration instead.

---

## `.gitignore`

Recommended `.gitignore`:

```gitignore
# Environment configuration
config.php
.env
.env.*
!.env.example

# SSH keys
*.pem
*.key
id_rsa
id_rsa.pub
id_ed25519
id_ed25519.pub

# Logs
*.log
logs/

# Temporary files
*.tmp
*.swp
*.swo
*~

# OS files
.DS_Store
Thumbs.db

# IDE
.idea/
.vscode/

# Runtime files
cache/
tmp/
```

---

## Example Configuration

Create:

```text
config.example.php
```

Example:

```php
<?php

$MASTER_CONF  = '/path/to/apache_master.conf';

$SSH_USER     = 'monitoruser';

$SSH_KEY      = '/path/to/ssh/private/key';

$CONN_TIMEOUT = 5;

$MONI_SCRIPT  = '/path/to/moni.sh';

$LOG_BASE     = '/path/to/apache/logs';
```

Users should copy this file to:

```text
config.php
```

and customize it for their environment.

---

## Project Structure

```text
apache-log-monitor/
│
├── live_http_url.php
├── moni.sh
├── config.example.php
├── servers.example.txt
│
├── docs/
│   ├── INSTALL.md
│   ├── CONFIGURATION.md
│   └── SECURITY.md
│
├── screenshots/
│   └── dashboard.png
│
├── .gitignore
├── LICENSE
└── README.md
```

---

## Troubleshooting

### No hosts are displayed

Check:

```text
MASTER_CONF
```

and verify that the PHP process can read it.

Test:

```bash
awk '{print $1}' /path/to/apache_master.conf
```

### No logs are displayed

Verify the SSH connection:

```bash
ssh monitoruser@server01
```

Then verify:

```bash
ls -lh /path/to/apache/logs/server01/common/
```

### Live tail does not work

Test manually:

```bash
ssh monitoruser@server01 \
  'tail -50 /path/to/example_access_log'
```

### Permission denied

Verify that the SSH account has read access to the Apache logs.

### Statistics are slow

Statistics operate on potentially large log files. The current analysis processes up to the latest 600,000 entries for several calculations.

---

## Performance

For large Apache logs:

* Use appropriate refresh intervals.
* Avoid unnecessarily large tail sizes.
* Use log rotation.
* Consider pre-aggregated statistics for very large environments.
* Avoid running multiple statistics jobs simultaneously.

---

## Security Recommendations Before Public Deployment

This project is primarily intended to run inside a trusted infrastructure/network.

If you intend to expose it to the public Internet, implement authentication and authorization before deployment.

At minimum:

```text
Internet
   │
   ▼
HTTPS
   │
   ▼
Authentication
   │
   ▼
Apache Log Monitor
   │
   ▼
Restricted SSH account
   │
   ▼
Apache servers
```

Do not expose an unauthenticated version of this application to the Internet.

---

## Roadmap

Potential future improvements:

* [ ] Authentication / SSO
* [ ] Role-based access control
* [ ] HTTPS-only deployment
* [ ] WebSocket-based live tail
* [ ] Server health indicators
* [ ] Log rotation awareness
* [ ] Log download
* [ ] Search across logs
* [ ] Advanced filtering
* [ ] Date/time filtering
* [ ] HTTP status dashboard
* [ ] Response-time analysis
* [ ] JSON structured logging support
* [ ] Docker deployment
* [ ] Kubernetes deployment
* [ ] Configurable log locations
* [ ] Audit logging
* [ ] Rate limiting

---

## Contributing

Contributions are welcome.

1. Fork the repository.
2. Create a feature branch.

```bash
git checkout -b feature/my-feature
```

3. Make your changes.
4. Test the application.
5. Commit your changes.

```bash
git add .
git commit -m "Add my feature"
```

6. Push the branch.

```bash
git push origin feature/my-feature
```

7. Open a Pull Request.

---

## License

This project is licensed under the MIT License.

See [LICENSE](LICENSE) for details.

---

## Disclaimer

This software is provided "as is", without warranty of any kind.

The administrator deploying this application is responsible for:

* Securing the application
* Protecting SSH credentials
* Restricting access to Apache logs
* Configuring appropriate authentication
* Reviewing command execution permissions
* Protecting sensitive infrastructure information

Use this software only on systems and infrastructure for which you have authorization.

````

### 2. What you MUST remove before pushing to a public repository

Your current PHP file has several things I would **not** publish unchanged.

For example, the source currently contains an internal filesystem path, a specific SSH username, and internal monitoring-script/log locations.

Change this:

```php
$MASTER_CONF  = '/auto/eifsjcweb3/web/common/apache/bin/apache_master.conf';
$SSH_USER     = 'eifadmin';
$SSH_KEY      = '';
$MONI_SCRIPT  = '/auto/wwwin-migration/wwwin-migration/metrics/moni.sh';
$LOG_BASE     = '/opt/eif/web/httpd/default/logs';
````

to something like:

```php
require_once __DIR__ . '/config.php';
```

Then create **local-only** `config.php`:

```php
<?php

$MASTER_CONF  = '/your/environment/apache_master.conf';
$SSH_USER     = 'monitoruser';
$SSH_KEY      = '/home/monitoruser/.ssh/id_ed25519';
$CONN_TIMEOUT = 5;
$MONI_SCRIPT  = '/your/environment/moni.sh';
$LOG_BASE     = '/your/environment/apache/logs';
```

And commit only:

```text
config.example.php
```

not:

```text
config.php
```

---

## 3. Important security issue in the current code

There is another thing I would fix **before making this public**.

Your SSH command currently uses:

```php
StrictHostKeyChecking=no
```

The current implementation explicitly disables SSH host-key verification.

For an internal controlled environment this may have been convenient, but for a public project I would change the default to proper host-key verification.

Also, the application accepts a `log` path from the HTTP request, even though it does apply a character whitelist.

For a public project, I would make the server select a log from the list returned by `action=logs` rather than allowing an arbitrary filesystem path supplied by the browser.

**I strongly recommend making these changes before publishing.**

---

# 4. Git repository information you should add

Your repository should have these files:

```text
README.md
LICENSE
.gitignore
config.example.php
live_http_url.php
moni.sh
```

I would also add:

```text
SECURITY.md
CONTRIBUTING.md
CHANGELOG.md
```

### LICENSE

If you want others to freely use, modify and redistribute it, **MIT License** is a simple choice.

### SECURITY.md

Tell users how to report security vulnerabilities privately rather than opening a public GitHub issue.

### CHANGELOG.md

Start with:

```markdown
# Changelog

## [1.0.0] - 2026-09-07

### Added

- Apache host discovery
- Access log discovery
- Error log discovery
- Log file size display
- Live access log tail
- Live error log tail
- Configurable tail refresh interval
- Log filtering
- Access log statistics
- HTTP response code analysis
```

---

# 5. GitHub repository description

For the GitHub **About** section, I'd use:

> **Lightweight PHP web dashboard for monitoring Apache HTTPD access and error logs across multiple Linux servers with live tailing and access-log statistics.**

Suggested topics:

```text
apache
apache-httpd
apache-logs
log-monitor
log-monitoring
php
linux
ssh
devops
sysadmin
httpd
server-monitoring
web-monitoring
```

---

# 6. Repository name

Good options:

```text
apache-log-monitor
```

or:

```text
apache-log-dashboard
```

or:

```text
php-apache-log-monitor
```

**My choice: `apache-log-monitor`**.

---

# 7. Before your first `git push`

Run a secret scan/search first:

```bash
grep -RniE \
'password|passwd|secret|token|api[_-]?key|private[_-]?key|BEGIN .*PRIVATE KEY|eifadmin|/auto/|/opt/eif/' \
. \
--exclude-dir=.git
```

Also check:

```bash
git status
```

Then:

```bash
git diff --cached
```

Make sure there are **no internal hostnames, usernames, paths, credentials, keys, or company-specific configuration**.

Then:

```bash
git init
git add README.md LICENSE .gitignore config.example.php live_http_url.php moni.sh
git commit -m "Initial public release"
git branch -M main
git remote add origin <YOUR-GITHUB-REPOSITORY>
git push -u origin main
```

One more recommendation: **don't publish the current file exactly as it is**. I would first refactor the configuration, remove the internal environment references, improve SSH host-key handling, and add authentication/authorization guidance. The current UI and functionality are already a good basis for a public `apache-log-monitor` project.

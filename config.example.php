<?php
/**
 * Apache Log Monitor - local configuration
 *
 * Copy this file to config.php and adjust the values for your environment.
 * DO NOT commit config.php to a public repository.
 */

// Local Apache configuration used to discover monitored hosts.
$MASTER_CONF = '/path/to/apache_master.conf';

// SSH account used to read logs on monitored hosts.
$SSH_USER = 'monitoruser';

// Optional SSH private key. Leave empty to use the web server user's SSH agent/default key.
$SSH_KEY = '/path/to/ssh/private/key';

// SSH connection timeout in seconds.
$CONN_TIMEOUT = 5;

// Base directory containing:
//   <host>/common/*_access_log
//   <host>/common/*_error_log
$LOG_BASE = '/path/to/apache/logs';

// Recommended: keep host-key verification enabled.
$SSH_STRICT_HOST_KEY_CHECKING = true;

// Optional known_hosts file. Leave empty to use the SSH client's default.
$SSH_KNOWN_HOSTS = '';

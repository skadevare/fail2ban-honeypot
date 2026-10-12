<?php
/**
 * Honeypot ban trigger.
 *
 * Include this from any trap page (e.g. /admin/index.php). It writes the
 * visitor's IP to a log file that fail2ban watches (jail "php-honeypot"),
 * which bans the IP for 24 hours, then answers with a plain 404.
 *
 * PHP never talks to fail2ban directly, so the web server user needs no
 * root/sudo rights. It only needs write access to HONEYPOT_LOG.
 */

declare(strict_types=1);

// ---------------------------------------------------------------- config ---

// Log file watched by fail2ban. Must match "logpath" in the jail.
const HONEYPOT_LOG = '/var/log/php-honeypot/ban.log';

// How to find the client IP:
//   'auto'   - use the proxy header ONLY when the request comes from one of
//              HONEYPOT_TRUSTED_PROXIES, otherwise use REMOTE_ADDR.
//              Safe both behind Cloudflare and when exposed directly.
//   'direct' - always use REMOTE_ADDR and ignore proxy headers.
const HONEYPOT_MODE = 'auto';

// Header holding the client IP when behind a trusted proxy (as named in
// $_SERVER). Cloudflare also sends 'HTTP_CF_CONNECTING_IP', which holds a
// single IP and can be used here instead.
const HONEYPOT_IP_HEADER = 'HTTP_X_FORWARDED_FOR';

// Proxies whose headers we believe. Default: Cloudflare's published ranges
// (https://www.cloudflare.com/ips/). Replace with your own proxy/load
// balancer if the site moves behind something else.
const HONEYPOT_TRUSTED_PROXIES = [
    // Cloudflare IPv4
    '173.245.48.0/20', '103.21.244.0/22', '103.22.200.0/22', '103.31.4.0/22',
    '141.101.64.0/18', '108.162.192.0/18', '190.93.240.0/20', '188.114.96.0/20',
    '197.234.240.0/22', '198.41.128.0/17', '162.158.0.0/15', '104.16.0.0/13',
    '104.24.0.0/14', '172.64.0.0/13', '131.0.72.0/22',
    // Cloudflare IPv6
    '2400:cb00::/32', '2606:4700::/32', '2803:f800::/32', '2405:b500::/32',
    '2405:8100::/32', '2a06:98c0::/29', '2c0f:f248::/32',
];

// ------------------------------------------------------------- functions ---

/** True if $ip is inside the CIDR range $cidr (IPv4 or IPv6). */
function honeypot_ip_in_cidr(string $ip, string $cidr): bool
{
    [$subnet, $bits] = array_pad(explode('/', $cidr, 2), 2, null);
    $ipBin = @inet_pton($ip);
    $subnetBin = @inet_pton((string) $subnet);
    if ($ipBin === false || $subnetBin === false || strlen($ipBin) !== strlen($subnetBin)) {
        return false;
    }

    $maxBits = strlen($ipBin) * 8;
    $bits = $bits === null ? $maxBits : (int) $bits;
    if ($bits < 0 || $bits > $maxBits) {
        return false;
    }

    $fullBytes = intdiv($bits, 8);
    if (strncmp($ipBin, $subnetBin, $fullBytes) !== 0) {
        return false;
    }
    $remBits = $bits % 8;
    if ($remBits === 0) {
        return true;
    }
    $mask = (0xFF << (8 - $remBits)) & 0xFF;
    return (ord($ipBin[$fullBytes]) & $mask) === (ord($subnetBin[$fullBytes]) & $mask);
}

function honeypot_is_trusted_proxy(string $ip): bool
{
    foreach (HONEYPOT_TRUSTED_PROXIES as $cidr) {
        if (honeypot_ip_in_cidr($ip, $cidr)) {
            return true;
        }
    }
    return false;
}

/**
 * Returns the real client IP, or null if it cannot be determined safely.
 * Never returns a trusted proxy's address (banning Cloudflare would be bad).
 */
function honeypot_client_ip(array $server): ?string
{
    $remote = $server['REMOTE_ADDR'] ?? '';
    if (filter_var($remote, FILTER_VALIDATE_IP) === false) {
        return null;
    }

    if (HONEYPOT_MODE === 'direct' || !honeypot_is_trusted_proxy($remote)) {
        // Not behind (our) proxy: headers can be forged, so ignore them.
        return $remote;
    }

    // From a trusted proxy. X-Forwarded-For is "client, proxy1, proxy2" and
    // each proxy appends to it, so anything left of the proxy's entry may be
    // forged by the client. Walk from the right and take the first address
    // that is not one of our trusted proxies.
    $header = (string) ($server[HONEYPOT_IP_HEADER] ?? '');
    foreach (array_reverse(explode(',', $header)) as $candidate) {
        $candidate = trim($candidate);
        if (filter_var($candidate, FILTER_VALIDATE_IP) === false) {
            return null;
        }
        if (!honeypot_is_trusted_proxy($candidate)) {
            return $candidate;
        }
    }
    return null;
}

/** Appends a ban request for $ip to the fail2ban-watched log. */
function honeypot_log_ban(string $ip, string $uri): bool
{
    // Keep the line single-line and printable; the IP comes first so nothing
    // attacker-controlled can sit in front of it in the fail2ban regex.
    $uri = substr(preg_replace('/[^\x21-\x7E]/', '?', $uri), 0, 256);
    $line = sprintf("%d php-honeypot ban ip=%s uri=%s\n", time(), $ip, $uri);
    return @file_put_contents(HONEYPOT_LOG, $line, FILE_APPEND | LOCK_EX) !== false;
}

function honeypot_trigger(): void
{
    $ip = honeypot_client_ip($_SERVER);
    if ($ip === null) {
        error_log('php-honeypot: could not determine client IP, not banning');
    } elseif (!honeypot_log_ban($ip, (string) ($_SERVER['REQUEST_URI'] ?? ''))) {
        error_log('php-honeypot: cannot write to ' . HONEYPOT_LOG);
    }

    // Look like a page that simply does not exist.
    http_response_code(404);
    header('Content-Type: text/html; charset=utf-8');
    header('Cache-Control: no-store');
    echo "<!DOCTYPE html>\n<html><head><title>404 Not Found</title></head>"
        . "<body><h1>Not Found</h1><p>The requested URL was not found on this server.</p></body></html>\n";
    exit;
}

// ------------------------------------------------------------------- run ---

if (!defined('HONEYPOT_NO_AUTORUN')) {
    honeypot_trigger();
}

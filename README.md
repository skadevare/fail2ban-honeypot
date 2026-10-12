# fail2ban-honeypot

A trap page (e.g. `/admin/`) that bans any visitor for 24 hours using fail2ban.

How it works: `ban_script.php` writes the visitor's IP to
`/var/log/php-honeypot/ban.log` and returns a normal-looking 404. fail2ban
watches that log (`maxretry = 1`) and bans the IP. PHP needs no root or sudo,
only write access to the log.

## Client IP detection

`HONEYPOT_MODE = 'auto'` (default):

- If the request comes from a Cloudflare IP, the client IP is taken from
  `X-Forwarded-For` (the rightmost entry that isn't a Cloudflare address, so a
  forged header from the client is ignored).
- If the request comes from any other IP, `REMOTE_ADDR` is used and headers
  are ignored. Nobody can bypass the ban, or frame another IP, by connecting
  to the origin directly with a fake header.

If the site moves off Cloudflare, it keeps working with no changes. If it moves
behind a different proxy, put that proxy's ranges in `HONEYPOT_TRUSTED_PROXIES`.
Cloudflare's ranges change occasionally; check https://www.cloudflare.com/ips/.

## Install (Debian/Ubuntu)

```sh
# 1. Script, outside the web root
sudo mkdir -p /var/www/includes
sudo cp ban_script.php /var/www/includes/

# 2. Trap page(s). Adjust the require path in index.php if needed.
sudo mkdir -p /var/www/html/admin
sudo cp admin/index.php /var/www/html/admin/

# 3. Log file writable by the web server user
sudo mkdir -p /var/log/php-honeypot
sudo touch /var/log/php-honeypot/ban.log
sudo chown -R www-data:www-data /var/log/php-honeypot

# 4. fail2ban config (fill in Cloudflare zone ID + token first)
sudo apt install fail2ban curl
sudo cp fail2ban/filter.d/php-honeypot.conf /etc/fail2ban/filter.d/
sudo cp fail2ban/jail.d/php-honeypot.conf   /etc/fail2ban/jail.d/
sudo chmod 640 /etc/fail2ban/jail.d/php-honeypot.conf   # contains API token
sudo systemctl restart fail2ban
```

If PHP-FPM runs with `open_basedir`, add `/var/log/php-honeypot` to it.

Optionally add log rotation for `/var/log/php-honeypot/ban.log`
(`create 0640 www-data www-data`).

## Enforcing the ban: important behind Cloudflare

Behind Cloudflare, every request reaches the server from a Cloudflare IP,
so an iptables/nftables ban on the client IP blocks nothing. The jail therefore
uses fail2ban's `cloudflare-token` action, which creates an IP block rule in
Cloudflare through the API:

- Create a token at Cloudflare → My Profile → API Tokens, with permission
  **Zone → Firewall Services → Edit** for your zone.
- Put the zone ID (on the domain's Overview page) and token in `jail.d/php-honeypot.conf`.

When the server is exposed directly, switch the jail to `action = %(action_)s`
(local firewall ban). The PHP side needs no change.

## Testing

```sh
# Check the filter matches the log
sudo fail2ban-regex /var/log/php-honeypot/ban.log /etc/fail2ban/filter.d/php-honeypot.conf

# Visit /admin/ from a throwaway IP, then:
sudo fail2ban-client status php-honeypot

# Unban
sudo fail2ban-client set php-honeypot unbanip 203.0.113.7
```

Add your own IP(s) to `ignoreip` in the jail so you don't lock yourself out.

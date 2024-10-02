# Dirty COW CVE-2016-5195


* ## Identification
    - Dirty COW (Copy-On-Write) is a local **privilege escalation** vulnerability in the **Linux kernel's** memory subsystem copy-on-write mechanism.
    - Affects Linux-based systems, including Android devices, using kernels versions from 2.6.22 to 4.8 inclusive.
    - Exploits a race condition to gain write access to read-only memory mappings.
    - Allows unauthorized modification and privilege escalation to root access.


* ## Cataloging
    - Discovered by Phil Oester in 2016, designated [CVE-2016-5195](https://cve.mitre.org/cgi-bin/cvename.cgi?name=cve-2016-5195) through capturing HTTP logs;
    - [Patched by Linus Torvalds](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=19be0eaffa3ac7d8eb6784ad9bdbc7d67ed8e619) in October 2016; 
    - Severity rated as **High** with a [CVSS v3](https://nvd.nist.gov/vuln/detail/cve-2016-5195) score of 7.0.
    - No known bug-bounty awarded;


* ## Exploit
    - Unprivileged local users exploit a race condition to gain write access to read-only memory mappings.
    - Attackers can modify on-disk binaries (e.g. `/usr/bin/passwd`) without proper permissions, escalating privileges to root access.
    <!-- - Public exploit scripts, including [proof-of-concept code](https://github.com/dirtycow/dirtycow.github.io/wiki/PoCs) in C; *automated attacks possible.* -->
    - Many variations of the exploit were created as [proofs of concept](https://github.com/dirtycow/dirtycow.github.io/wiki/PoCs), allowing *automated attacks*.
    - Exploit leaves no traces in system logs; detection is difficult.
    <!-- *Encontrei nada sobre Metasploit para Dirty COW* -->


* ## Attacks
    <!-- - Malware incorporated Dirty COW to silently escalate privileges on infected Linux machines.
    - Local users exploited the flaw in shared hosting environments to compromise entire servers.
    - Android devices were vulnerable, risking unauthorized access to user data and system files.
    - Gaining root access grants an attacker full control of system: install malware, modify files, and change system settings. -->

    - Multiple [proofs of concept](https://github.com/dirtycow/dirtycow.github.io/wiki/PoCs) were developed for exploiting the vulnerability, including [dirtyc0w.c](https://github.com/dirtycow/dirtycow.github.io/blob/master/dirtyc0w.c)
    - Successful attacks are rare, as the vulnerability was patched before stable exploits were developed for major devices, but has been used by attackers ever since.
    - The exploit is used in [ZNIU](https://www.trendmicro.com/en_us/research/17/i/zniu-first-android-malware-exploit-dirty-cow-vulnerability.html), a malware family for Android, hidden in more than 1200 apps and affecting more than 5000 users.
    - A Russian attack named Xurum used Dirty COW as an auxiliary vulnerability, for privilege escalation on Linux servers.

<!-- 

* ## Exploit
    a
    (
        - An unprivileged local user could use this flaw to gain write access to otherwise read-only memory mappings and thus increase their privileges on the system.
        - This flaw allows an attacker with a local system account to modify on-disk binaries, bypassing the standard permission mechanisms that would prevent modification without an appropriate permission set.
    ) 

-->

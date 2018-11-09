# Saddam-new
Saddam-new is a simple reflection and amplification DoS attack tool based on [Saddam](https://github.com/OffensivePython/Saddam).

```bash
 _____       _   _
|   __|___ _| |_| |___ _____ ___ ___ ___ _ _ _
|__   | .'| . | . | .'|     |___|   | -_| | | |
|_____|__,|___|___|__,|_|_|_|   |_|_|___|_____|

usage: saddam_new.py [-h] [--benchmark] [-a DOMAIN|IP] [-d FILE:FILE|DOMAIN]
                     [-n FILE] [-c FILE] [-s FILE] [-p FILE] [-t N]

Example: python saddam_new.py -n ./ntplist.txt -t 10 -a target.com

Options:
  -h, --help            Show Help Message And Exit
  --benchmark           Calculate Amplification Factor
  -a DOMAIN|IP, --aim DOMAIN|IP
                        Aim To Attack
  -d FILE:FILE|DOMAIN, --dns FILE:FILE|DOMAIN
                        DNS Amplification List Fileand Domains to Resolve
                        (e.g: dns.txt:[evildomain.com|domains_file.txt]
  -n FILE, --ntp FILE   NTP Amplification List File
  -c FILE, --cldap FILE
                        CLDAP Amplification List File
  -s FILE, --snmp FILE  SNMP Amplification List File
  -p FILE, --ssdp FILE  SSDP Amplification List File
  -t N, --threads N     Threads Number (default=1)
```

### Compared with Saddam, there are several changes:

1. Support for CLDAP protocol.
2. After benchmark, you can save the still available IPs to a new txt file.
3. Command line options changed.
4. Some other changes in code.

### In addition, you need to pay attention to the following points:

1. `Pinject.py` has been placed in the same directory, so you don't need to download it anymore.
2. You need to have root privileges to run this tool. Of course, Saddam is also.
3. After testing, the tool seems to be used only in the case of a wired network connection. When using a wireless connection, the data packet will be corrected (forced to add a IP header), and I don't understand how to solve it at present. Do you have a solution?

**Thanks to Saddam and @OffensivePython.**

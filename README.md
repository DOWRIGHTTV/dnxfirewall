<h5><strong>NOTICE: The license has changed from the CMD version (GPLv3). The 'FULL' version (current branch) is licensed under AGPLv3.</strong></h5>

<h1 align="center">
	<br>
	<img src="https://github.com/DOWRIGHTTV/dnxfirewall/blob/dnxfirewall/dnx_frontend/static/assets/images/dnxlogo_v2.png" alt="dnxfirewall logo">
	<br>
</h1>

<h3 align="center">
	Command Line Version | coded/tested live on twitch.tv.
	<br>
	<a href="https://www.twitch.tv/dowright" target="_blank">
		<img src="https://github.com/ProHackTech/DNX-FWALL-CMD/blob/master/Readme_Social/twitch.png" alt="DOWRIGHTTV" />
	</a>
</h3>

<h2>Overview</h2>

DNX Firewall is an optimized/high performance collection of applications or services to convert a standard linux system
into a zone based next generation firewall. All software is designed to run in conjunction with eachother, but with a modular 
design certain aspects can be completely removed with little effort. The primary security modules have DIRECT/INLINE control 
over all connections, streams, messages, that goes through the system. That being said, depending on the protocol, offloading
to lower level control is present to maintain the highest possible throughput with full inspection enabled. There is an IPTable
custom chain to allow for the administrator to hook into the packet flow without the ability to accidentally override dnx security
modules. A low level "architecture, system design" video will be created at some point to show how this is possible with pure python.

<h2>Included Features</h2>

- DNS Proxy
   - category based blocking (general, TLD, substring matching)
   - user added whitelist/blacklist or custom general category creation
   - native DNS over TLS conversion with optional UDP fallback
   - local dns server
   - software failover
   - 2 level record caching
- IP Proxy (transparent) Bi directional
   - reprutation based host filtering
   - geolocation filter
   - lan restriction (disables internet access to the LAN for all IPs not whitelisted)

- IPS/IDS (WAN/inbound)
   - Denial of service detection/prevention
   - Portscan detection/prevention

- Lightweight DHCP Server (custom)
   - ip reservations
   - security alert integration

- General Services
   - Log handling
   - Database management
   - Syslog client (UDP, TCP, TLS) IMPORTANT: currently in a beta/unstable state.
this service will not be enabled by default and will require the service enabled to start on system start.
    
- Additional Features
   - IPv6 disabled
   - prebuilt iptable rules
   - DNS over HTTPs blocks (dns bypass prevention)
   - DNS over TCP blocks (dns bypass prevention)
   - DNS over TLS blocks (dns bypass prevention)
   - all inbound connections to wan DROPPED by default
   - IPTABLES custom chain for admin hook into packet flow

<h2>Before Running</h2>

<strong>NEW: sqlite3 is now the default database in use (to simplify deployments). The environment variable "SQL_VERSION" located in dnx_configure/dnx_constants.py can be flipped to use postgresql. WARNING: switching the database used after initial configuration may cause problems. </strong>

- [+] Edit data/config.json and data/dhcp_server.json to reflect your system [interfaces].

- [+] Move all systemd service files into the systems systemd folder.

- [+] Configure system interfaces. LAN needs to be Default Gateway of local network.

- [+] Compile python-netfilterqueue for your current architecture/distro (link below).
        
        - ensure name is netfilter.so and placed in the dnxfirewall/netfilter folder
	
- [+] Compile dnx_iptools/binary_search.pyx for your current architecture/distro.

- [+] Run/ follow, in order, the corresponding deployment scripts [for the selected database] to automate system setup. look at comments in script files 
for more direction.

<h2>Non DNX code dependencies/sources!</h2>

https://github.com/kti/python-netfilterqueue | cython <-> python extension for binding to linux kernel [netfilter] | THIS IS AWESOME!

https://www.ip2location.com/free/visitor-blocker | geolocation ip filtering datasets

https://gitlab.com/ZeroDot1/CoinBlockerLists | cryptominer host set

https://squidblacklist.org | malicious and advertisement host sets

<bold>OPTIONAL:</bold> https://github.com/tlocke/pg8000 | pure python postgresql adapter

<h2>General Showcase Demo (outdated)</h2>

This video is extremely outdated, but still shows general functionality and some of the high level security implementations. 
an updated video will be created soon which will show the newly added modules: syslog client, standard logging, ips/ids, 
updated dns proxy functionality, updated ip proxy functionality, more.

<h3 align="center">
	<a href="http://www.youtube.com/watch?feature=player_embedded&v=6NvRXlNjpOc" target="_blank">
		<img src="http://img.youtube.com/vi/6NvRXlNjpOc/0.jpg" alt="DNX Firewall Demo" width="480" height="360" border="10" />
	</a>
</h3>

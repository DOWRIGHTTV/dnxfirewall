<h5><strong>NOTICE: The license has changed from the CMD version (GPLv3). The 'FULL' version (current branch) is licensed under AGPLv3.</strong></h5>

<h1 align="center">
	<br>
	<img src="https://github.com/DOWRIGHTTV/dnxfirewall/blob/dnxfirewall/dnx_frontend/static/assets/images/dnxlogo_v2.png" alt="dnxfirewall logo">
	<br>
</h1>

<br>
<h2>Overview</h2>

  DNX Firewall is an optimized/high performance collection of applications and services to convert a standard linux system
into a zone based next generation firewall. All software is designed to run in conjunction with eachother, but with a modular 
design certain aspects can be completely removed with little effort. The primary security modules have DIRECT/INLINE control 
over all connections, streams, and messages that goes through the system. That being said, depending on the protocol, offloading
to lower level control is present to maintain the highest possible throughput with full inspection enabled. custom iptable chains
are used to allow for the administrator to hook into the packet flow without worrying about accidentally overriding dnx security
modules control.

A low level "architecture, system design" video will be created at some point to show how this is possible with pure python.

<br>
<h2>Included Features</h2>

<strong>NEW: sqlite3 is now the default database in use (to simplify deployments). postgresql is still present on the backend and will be able to be enabled during system deployment in a future release.</strong>

<strong>NEW: Auto deployment utility (auto loader) is now live. This should be used to deploy the system on any compatible distro. See compatible distro list for more details. </strong>

- DNS proxy
   - category based blocking (general, TLD, substring matching)
   - user added whitelist/blacklist or custom general category creation
   - native DNS over TLS conversion with optional UDP fallback
   - local dns server (authoritative via packet manipulation)
   - automatic software failover
   - 2 level record caching

- IP proxy (transparent) bi-directional
   - reputation based host filtering
   - geolocation filter (country blocking)
   - lan restriction (disables internet access to the LAN for all IPs not whitelisted) | Parental Control

- IPS/IDS (WAN/inbound)
   - denial of service detection/prevention
   - portscan detection/prevention

- Lightweight DHCP server (native software)
   - ip reservations
   - interface level control (enable/disable)
   - security alert integration

- General Services
   - log handling
   - database management
   - syslog client (UDP, TCP, TLS) IMPORTANT: currently in a beta/unstable state. this service will not be enabled by default.
    
- Additional Features
   - IPv6 disabled
   - prebuilt iptable rules (all inbound connections to wan DROPPED by default)
   - DNS over HTTPs restricted (dns bypass prevention)
   - DNS over TCP restricted (dns bypass prevention)
   - DNS over TLS restricted (dns bypass prevention)
   - IPTABLES custom chain for admin hook into packet flow

<br>
<h2>To deploy (using auto loader)</h2>

1. select linux distro on compatible distro list (see below)

2. install linux on physical hardware or a VM
	
	2a. (3) interfaces are required (WAN, LAN, DMZ)
	
	2b. create "dnx" user during install or once complete
	
	2c. install and make python3.8 default (if applicable)

3. upgrade and update system

4. install git
	
5. clone https://github.com/dowrighttv/dnxfirewall.git to "dnx" user home directory (/home/dnx)
        
6. log in as "dnx" user run command: sudo python3 dnxfirewall/dnx_configure/dnx_autoloader.py
	
7. follow prompts to associate physical interfaces to dnxfirewall zones
	
8. once utility is complete, restart system and navigate to https://dnx.firewall from LAN or DMZ interface.
	
<br>
<h2>Compatible linux distros with dnxfirewall auto loader </h2>
	
  - Ubuntu server 20.04 LTS (stable)
	
  - Debian based distros (untested, but likely stable)
	
  - Non Debian based distros (not supported)

<br>
<h2>Additional info</h2>

<h4 align="center">coded and tested live on twitch.tv.</h4>
<p align="center"><a href="https://www.twitch.tv/dowright" target="_blank">
	<img src="https://github.com/ProHackTech/DNX-FWALL-CMD/blob/master/Readme_Social/twitch.png" alt="DOWRIGHTTV"/>
</a></p>

<br>
<h4>External code sources</h4>

https://github.com/kti/python-netfilterqueue | cython <-> python C extension for binding to linux kernel [netfilter]

https://www.ip2location.com/free/visitor-blocker | geolocation filtering datasets (ip address assignments by country)

https://gitlab.com/ZeroDot1/CoinBlockerLists | cryptominer host dataset

https://squidblacklist.org | malicious and advertisement host datasets

<bold>psql only:</bold> https://github.com/tlocke/pg8000 | pure python postgresql adapter

<br>
<h4>Showcase demo</h4>	
  This video is extremely outdated, but still shows general functionality and some of the high level security implementations. 
An updated video will be created soon(ish), which will show the newly added modules: syslog client, standard logging, ips/ids, 
updated dns proxy functionality, updated ip proxy functionality, more.

<h3 align="center">
	<a href="http://www.youtube.com/watch?feature=player_embedded&v=6NvRXlNjpOc" target="_blank">
		<img src="http://img.youtube.com/vi/6NvRXlNjpOc/0.jpg" alt="DNX Firewall Demo" width="480" height="360" border="10" />
	</a>
</h3>

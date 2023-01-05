<h5><strong>NOTICE: The license has changed from the CMD version (GPLv3). The 'FULL' version (current branch) is licensed under AGPLv3.</strong></h5>

<h1>
	<br>
	<img src="https://raw.githubusercontent.com/DOWRIGHTTV/dnxfirewall/dnxfirewall/dnx_webui/static/assets/images/dnxlogo_v2.png" alt="dnxfirewall logo">
	<br>
</h1>

<br>
<h2>Overview</h2>
<span>
  DNXFIREWALL is an optimized/high performance collection of applications and services to convert a standard linux system
  into a zone based next generation firewall. The primary security modules have DIRECT/INLINE control over all connections, streams, 
  and messages that goes through the system.

<pre>
                -------------------------------------------------------
                | (outbound)                                          |
                |                                                     V
                |                               --------------> [dns proxy (*1)] --------
                |                               | (outbound)                            |
                |      (bi-directional)         |                                       V
TCP/IP --> [cfirewall] -------------------> [ip proxy] ------------------------> ((*packet verdict*)) --> TCP/IP 
stack          |  |                             |                                       ^    ^            stack
               |  |                             | (inbound)                             |    |
               |  |                             --------------> [ids/ips (*2)] ----------    |
               |  |                                                   ^                      |
               |  | (inbound)                                         |                      |
               |  -----------------------------------------------------                      |
               |                                                                             |
               -------------------------------------------------------------------------------
</pre>

- (*1) the dns proxy is specifically designed to inspect dns payload going between internal networks or from the lan to internet.

- (*2) the ids/ips is specifically designed (for now at least) to only inspect traffic from the internet to the lan networks. 
  - this decision is based on the fact that 99.99% (generalization) of threats in this space will source from the internet.

</span>
A low level "architecture, system design" video will be created at some point to show how this is possible with pure python.

<br>
<h2>Included Features</h2>

- Custom packet handler
  - implemented in C
  - stateful or stateless packet inspection
  - complex packet decisions (defer packet action to security modules)

- DNS proxy (outbound or cross lan networks)
   - category based blocking (general, TLD, substring matching)
   - user added whitelist/blacklist or custom general category creation

- DNS server (recently detached from dns proxy, but shares process resources)
  - native DNS over TLS conversion with optional UDP fallback
  - local dns server (authoritative via packet manipulation)
  - automatic software failover
  - 2 levels of record caching

- IP proxy (transparent) bi-directional
   - reputation based host filtering (detection implemented in C)
   - geolocation filter (country blocking, detection implemented in C)

- IPS/IDS (inbound)
   - denial of service detection/prevention
   - portscan detection/prevention

- Lightweight DHCP server (native software)
   - ip reservations
   - interface level control (enable/disable)
   - security alert integration

- General Services
   - log handling
   - database management
   - syslog client (UDP, TCP, TLS) IMPORTANT: currently unusable state due to many internal breaking api changes. this service will not be enabled by default.
    
- Additional Features
   - IPv6 disabled
   - DNS proxy bypass prevention
     - DNS over HTTPs restricted
     - DNS over TCP restricted
     - DNS over TLS restricted
   - Modern webui for administration
   - custom shell utility for system level maintenance
     - includes built in system (dnxfirewall) updater for 1 click updates

<br>
<h2>To deploy (using autoloader)</h2>

1. select linux distro on compatible distro list (see below)

2. install linux on physical hardware or a VM
	
	2a. (3) interfaces are required (WAN, LAN, DMZ)
	
	2b. create "dnx" user during os install or once complete
	
	2c. install and make python3.8 default (if applicable)

3. upgrade and update system

4. install git
	
5. clone https://github.com/dowrighttv/dnxfirewall.git to "dnx" user home directory (/home/dnx)
        
6. log in as "dnx" user and run command: sudo python3 dnxfirewall/dnx_run.py cli autoloader
	
7. follow the prompts to associate the physical interfaces with dnxfirewall builtin zones
	
8. once the utility is complete, restart the system and navigate to the specified url

<br>
<h2>Compatible linux distros with dnxfirewall autoloader</h2>

- Debian based distros
  - Linux kernel >= 2.6.31
  - Python 3.8+
  - netplan	(ubuntu interface/network manager)

<br>

<h4>External Contributors</h4>
afallenhope - web design, ux, and templating -> https://github.com/afallenhope

<h4>External code sources</h4>

https://www.ip2location.com/free/visitor-blocker | geolocation filtering datasets (ip address assignments by country)

https://gitlab.com/ZeroDot1/CoinBlockerLists | cryptominer host dataset

<bold>psql only:</bold> https://github.com/tlocke/pg8000 | pure python postgresql adapter


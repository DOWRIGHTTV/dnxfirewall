<h1 align="center">
	<br>
	<img src="https://github.com/ProHackTech/DNX-FWALL-CMD/blob/master/DNX_Logo.png" alt="DNX Firewall Logo">
	<br>
</h1>

<h3 align="center">
	Command Line Version
	<br>
	<a href="https://www.twitch.tv/dowright" target="_blank">
		<img src="https://github.com/ProHackTech/DNX-FWALL-CMD/blob/master/Readme_Social/twitch.png" alt="DOWRIGHTTV" />
	</a>
</h3>

<h4>Bought to you by: DOWRIGHT</h4>

<h2>Before Running</h2>

- [+] Edit data/config.json to reflect your system

- [+] Change environment variable in dnx_run.sh

- [+] Use dnx_run.sh to start the system

<h2>Optional</h2>

- To enable full logging (log all request instead of only blocked), change Logging Enabled to 1 in data/config.json

- To enable full enterprise logging, ensure full logging (above) is enabled and set || self.ent_full = False > True || in dns_proxy_dev.py

<h2>Instructional Demo</h2>

- NOTE: The front end is not included in public/foss version of firewall, but the funcionality of the system is the same.
Edit json files accordingly to implement specific system controls, eg whitelist, blacklist, dns records, etc.

<h3 align="center">
	<a href="http://www.youtube.com/watch?feature=player_embedded&v=6NvRXlNjpOc" target="_blank">
		<img src="http://img.youtube.com/vi/6NvRXlNjpOc/0.jpg" alt="DNX Firewall Demo" width="480" height="360" border="10" />
	</a>
</h3>


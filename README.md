# DNX-FWALL-CMD
Command line version of DNX Firewall.

#Before running# 

1. Edit data/config.json to reflect your system.
2. Change environment variable in dnx_run.sh
3. Use dnx_run.sh to start the system.

#OPTIONAL#
To enable full logging (log all request instead of only blocked)
change Logging Enabled to 1 in data/config.json.

To enable full enterprise logging, ensure full logging (above) is
enabled and set || self.ent_full = False > True || in dns_proxy_dev.py.


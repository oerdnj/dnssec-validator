#
# Regular cron jobs for the dnssec-validator package
#
0 4	* * *	root	[ -x /usr/bin/dnssec-validator_maintenance ] && /usr/bin/dnssec-validator_maintenance

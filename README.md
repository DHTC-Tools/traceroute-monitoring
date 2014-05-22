traceroute-monitoring
=====================

Nagios plugin to monitor perfSONAR traceroutes by getting the perfSONAR toolkit's [reverse traceroute page](http://iut2-net1.iu.edu/toolkit/gui/reverse_traceroute.cgi?target=uct2-net2.mwt2.org&function=traceroute) and parsing it in order to retrieve the reverse traceroutes to and from perfSONAR nodes.

Run as `./validate-traceroute.py [-v <verbosity>] [-s] host1 host2` with verbosity being a number from 1 to 4 (4 being the most verbose), the -s flag being set if you want to overwrite a stored route, and host1 and host2 being perfSONAR hosts that are in the `valid_hosts` list. The order of the two hosts does not matter, as the trace is done in both directions (host1 to host2 and vice versa).

The traceroute history is stored in the file set by `history_file_name` (presently set to /var/nagios/rw/valid_traces).

#!/usr/bin/python

import sys, urllib2, re, os, getopt, socket

EXIT_OK = 0
EXIT_WARNING = 1
EXIT_CRITICAL = 2
EXIT_UNKNOWN = 3

TIMEOUT = 6

usage = "Usage: %s [-v <verbosity>] [-s] host1 host2\n\t-s Sets the retrieved trace as the new standard (skips validity checking)" % sys.argv[0]
valid_hosts = [
	"iut2-net1.iu.edu",
	"iut2-net5.iu.edu",
	"iut2-net7.iu.edu",
	"uct2-net2.mwt2.org",
	"mwt2-ps02.campuscluster.illinois.edu",
	"lhcperfmon.bnl.gov",
	"psum01.aglt2.org",
	"psum05.aglt2.org",
	"psmsu01.aglt2.org",
	"perfsonar-ps2.cern.ch"
]
usage += "\nValid hosts:\n"
for h in valid_hosts:
	usage += "\t" + h + "\n" 
trace_url = "http://%s/toolkit/gui/reverse_traceroute.cgi?target=%s&function=traceroute"
history_file_name = "/var/nagios/rw/valid_traces"
#history_file_name = "valid_traces"
verbosity = 1
set_new_valid = False

socket.setdefaulttimeout(TIMEOUT)

def retrieve_traceroute(hosts):
	if verbosity >= 2:
		print "Retrieving trace from %s to %s..." % tuple(hosts)
	
	receieved = None
	try:
		receieved = urllib2.urlopen(trace_url % tuple(hosts))
	except urllib2.URLError, e:
		# Catch timeout errors
		if isinstance(e.reason, socket.timeout):
			print "Error: Time out from %s to %s" % (hosts[0], hosts[1])
			sys.exit(EXIT_WARNING)
		else:
			print "URL Error from %s to %s" % (hosts[0], hosts[1])
			sys.exit(EXIT_WARNING)
	except socket.timeout, e:
		# Catch timeout errors
		print "Error: Timed out from %s to %s" % (hosts[0], hosts[1])
		sys.exit(EXIT_UNKNOWN)

 	if receieved:
		trace = receieved.read()
	else:
		print "Error getting page from %s to %s" % (hosts[0], hosts[1])
		sys.exit(EXIT_UNKNOWN)

	# Split the trace at the <pre> tag and take everything after it
	try:
		return trace.split("<pre>")[1].strip()
	except IndexError:
		print "Error in page format (<pre> tag split failed) from %s to %s" % (hosts[0], hosts[1])
		sys.exit(EXIT_UNKNOWN)

def parse_hops(trace):
	# Parse the IPs of each hop
	IPs = []
	# This complicated regex gets the IPs from the traceroute lines
	# Or it gets the '* * *' of failed hops (in group 2)
	re_ips = re.compile(r"^\s*\d+(?:[^\(]*\(([^\)]*)|\s+(\*\s\*\s\*))")
	for line in trace.split("\n"):
		result = re_ips.match(line.strip())
		if result:
			IPs.append(result.group(2) or result.group(1))

	return IPs

def get_history(hosts):
	try:
		if os.path.exists(history_file_name):
			history_file = open(history_file_name, "r")
		else:
			history_file = open(history_file_name, "w+")
	except:
		print "Unable to open history file: " + history_file_name
		sys.exit(EXIT_UNKNOWN);

	lines = history_file.readlines()
	history_file.close()

	# We need to retrieve the two traces
	found = False
	curHost = None
	traces = { hosts[0]: [], hosts[1]: []}
	for line in lines:
		line = line.rstrip()
		if found and not curHost:
			if line.find("From " + hosts[0]) >= 0:
				curHost = hosts[0]
				continue
			elif line.find("From " + hosts[1]) >= 0:
				curHost = hosts[1]
				continue
			elif line.find("End") >= 0 and line.find(hosts[0]) >= 0 and line.find(hosts[1]) >= 0:
				found = False
				break
		if found and curHost:
			if line.find("End " + curHost) >= 0:
				curHost = None
				continue
			traces[curHost].append(line)
			continue
		if line.find("Start") >= 0 and line.find(hosts[0]) >= 0 and line.find(hosts[1]) >= 0:
			found = True
			continue

	return traces

def check_history(hosts, traces, history):
	# Return True if the current trace and the historical ones are the same
	# False if they're not
	for key in traces:
		if len(traces[key]) != len(history[key]):
			# Different lengths is bad
			return False
		for i in range(len(traces[key])):
			if traces[key][i] != history[key][i]:
				# Not matching hops is bad
				return False

	return True

def save_history(hosts, traces):
	lines_to_write = []
	lines_to_write.append("Start %s <-> %s\n" % tuple(hosts))
	for key in traces:
		lines_to_write.append("From %s\n" % key)
		for hop in traces[key]:
			lines_to_write.append(hop + "\n")
		lines_to_write.append("End %s\n" % key)
	lines_to_write.append("End %s <-> %s\n\n" % tuple(hosts))

	history_file = open(history_file_name, "r")
	lines = history_file.readlines()
	history_file.close()

	# Figure out what history we need to replace
	start_index = 0
	end_index = 0
	for i in range(len(lines)):
		line = lines[i]
		if line.find("Start") >= 0 and line.find(hosts[0]) >= 0 and line.find(hosts[1]) >= 0:
			start_index = i
		elif line.find("End") >= 0 and line.find(hosts[0]) >= 0 and line.find(hosts[1]) >= 0:
			end_index = i + 1
			break

	lines[start_index:end_index] = lines_to_write


	history_file = open(history_file_name, "w+")
	for line in lines:
		history_file.write(line)
	history_file.close()

def main(hosts):
	host1, host2 = hosts

	# Make sure we are testing valid hosts
	if host1 not in valid_hosts or host2 not in valid_hosts:
		if host1 not in valid_hosts:
			print "Invalid host: " + host1
		if host2 not in valid_hosts:
			print "Invalid host: " + host2
		print usage
		return EXIT_UNKNOWN
	if host1 == host2:
		print "The two hosts can't be the same"
		return EXIT_UNKNOWN

	# Get the traceroutes, then switch them around and get it the other direction
	traces = {}
	traces[host1] = parse_hops(retrieve_traceroute(hosts))
	hosts[0], hosts[1] = hosts[1], hosts[0]
	traces[host2] = parse_hops(retrieve_traceroute(hosts))

	if verbosity >= 3:
		print traces

	if set_new_valid:
		print "Setting new valid trace"
		save_history(hosts, traces)
		return EXIT_OK

	history = get_history(hosts)
	match = check_history(hosts, traces, history)
	if not match:
		if len(history[host1]) == 0 and len(history[host2]) == 0:
			print "No history found for this trace, adding it"
			save_history(hosts, traces)
			return EXIT_OK
		else: 
			print "(%s <-> %s): Current trace does NOT match stored trace" % tuple(hosts)
                        
                        if verbosity >= 1:
                                # Print the trace comparison
                                print "Expected ... Current"
                                for host in hosts:
                                        print "From: " + host
                                        for i in range(max(len(history[host]), len(traces[host]))):
                                                if i < len(history[host]):
                                                        print history[host][i] + " ... ",
                                                else: print "[N/A] ... ",
                                                if i < len(traces[host]):
                                                        print traces[host][i]
                                                else: print "[N/A]"
                                                
                        return EXIT_CRITICAL
	else:
		print "(%s <-> %s): Current trace matches stored trace, no problem found" % tuple(hosts)
		return EXIT_OK

if __name__ == "__main__":

	# Get arguments
	try:
		opts, args = getopt.getopt(sys.argv[1:], "v:hs", [])
	except getopt.GetoptError:
		print usage
		sys.exit(EXIT_UNKNOWN)

	for opt, arg in opts:
		if opt  == "-h":
			print usage
			sys.exit(EXIT_OK)
		elif opt == "-v":
			try:
				int(arg)
			except ValueError:
				print "Invalid verbosity value (must be number from [0-3])"
				print usage
				sys.exit(EXIT_UNKNOWN)
			if int(arg) > 3:
				print "Invalid verbosity value (must be from [0-3])"
				print usage
				sys.exit(EXIT_UNKNOWN)
			verbosity = int(arg)
		elif opt == "-s":
			set_new_valid = True

	# End getting arguments

	# The non-flag arguments are stored in args (in this case it's the two hosts)
	if len(args) != 2:
		print "You must specify two hosts"
		print usage
		sys.exit(EXIT_UNKNOWN)

	sys.exit(main(args))

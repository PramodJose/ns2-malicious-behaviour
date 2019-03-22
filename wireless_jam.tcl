set val(chan)			Channel/WirelessChannel
set val(prop)			Propagation/TwoRayGround
set val(netif)			Phy/WirelessPhy
set val(mac)			Mac/802_11
set val(ifq)			Queue/DropTail/PriQueue
set val(ifqlen)			1048576						;# 1 MB queue length (2^20 bytes)
set val(ll)				LL
set val(ant)			Antenna/OmniAntenna
set val(rp)				DSDV

if {$argc != 6} {
	puts "Usage:-\nns $argv0 <node-count> <mal-node-percentage \[0.0-0.9\]> <attack-type\[c/p/r\]> <out-thrput-file> <out-trace-file> <ID>"
	exit 1
} elseif {![string is double [lindex $argv 1]]} {
	puts "The percentage of malicious nodes should be a float"
	exit 1
}

set mal_percntg [lindex $argv 1]
if {$mal_percntg < 0.0 || $mal_percntg > 0.9} {
	puts "Invalid malicious node percentage. Please enter a decimal number between 0.1 and 0.9."
	exit 1
}

set val(maxx)			175
set val(maxy)			175
set val(nn)				[lindex $argv 0]
set val(mal_nn)			[expr {int([lindex $argv 1] * $val(nn))}]
set val(ben_nn)			[expr {$val(nn) - $val(mal_nn)}]
set val(attack-type)	[lindex $argv 2]
set val(sim_time)		20.0
set val(buff_time)		0.01
set val(scene)			"scen_$argv0"
set val(conn)			"conn_$argv0"
set val(events)			"events_$argv0"
set val(mal_time)		0.0
set val(poll_delta)		$val(sim_time)
set val(thrput_file)	[lindex $argv 3]
set val(trace_file)		[lindex $argv 4]
set val(ID)				[lindex $argv 5]

# if {$val(mal_nn) >= $val(nn) } {
# 	puts "The malicious nodes are greater or equal to\
# 	 the total number of nodes. This is an invalid configuration."
# 	exit 1
# }

set ns_ [new Simulator]
set topo [new Topography]
$topo load_flatgrid $val(maxx) $val(maxy)
create-god $val(nn)

set chan_1 [new $val(chan)]

$ns_ node-config	-adhocRouting $val(rp) \
					-llType $val(ll) \
					-macType $val(mac) \
					-ifqType $val(ifq) \
					-ifqLen $val(ifqlen) \
					-antType $val(ant) \
					-propType $val(prop) \
					-channel $chan_1 \
					-phyType $val(netif) \
					-topoInstance $topo \
					-agentTrace ON \
					-routerTrace OFF \
					-macTrace OFF \
					-movementTrace OFF \
					-toraDebug OFF \
					-mobileIP OFF			
		
					
# set namtrace_fh [open "$argv0.nam" w]
# $ns_ namtrace-all-wireless $namtrace_fh $val(maxx) $val(maxy)
set trace_fh [open "$val(trace_file)$val(ID)" w]
$ns_ trace-all $trace_fh
set plot_fh [open "$val(thrput_file)$val(ID)" w]

proc finish {} {
	global ns_ trace_fh argv0 val plot_fh ;#namtrace_fh
	$ns_ flush-trace
	# close $namtrace_fh
	close $trace_fh
	close $plot_fh
	# exec nam "$argv0.nam" &
	# exec xgraph $val(plot_file) > /dev/null 2> /dev/null &
	exit 0
}

source $val(scene)
source $val(conn)
source $val(events)

proc plot_graph {} {
	global l_sink_ ns_ plot_fh val legit_conn
	set now [$ns_ now]

	set total_bytes_ 0
	for {set i_main 0} {$i_main < $legit_conn} {incr i_main} {
		set total_bytes_ [expr {$total_bytes_ + [$l_sink_($i_main) set bytes_]}]
		$l_sink_($i_main) set bytes_ 0
	}

	puts $plot_fh "[expr {$total_bytes_ / $val(sim_time)}]"
	# puts $plot_fh "$now [expr {$total_bytes_ / $legit_conn}]" ;# avg bytes received by a legit node
	# puts "[expr {$total_bytes_ / $val(sim_time)}]" ;# throughput

	$ns_ at [expr {$now + $val(poll_delta)}] "plot_graph"
}

$ns_ at [expr {$val(sim_time) + $val(buff_time)}] "finish"
$ns_ at $val(poll_delta) "plot_graph"
$ns_ run

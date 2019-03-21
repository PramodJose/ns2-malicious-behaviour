# The benign nodes are allowed to start at the 0th second. Only the
# start times of the malicious nodes are altered.
for {set i_events 0} {$i_events < $legit_conn} {incr i_events} {
	$ns_ at 0.0 "$l_cbr_($i_events) start"
}

# implementing attacks...
if {$val(attack-type) == "c"} { 				;# constant jamming
	for {set i_events 0} {$i_events < $mal_conn} {incr i_events} {
		$ns_ at $val(mal_time) "$m_cbr_($i_events) start"
	}
} elseif {$val(attack-type) == "p"} {			;# periodic jamming
	for {set i_events $val(ben_nn)} {$i_events < $val(nn)} {incr i_events} {

		set mal_periods($i_events) [expr {2 + int(rand()*4)}] 	;#	The malicious time interval can be between [2, 5]
		set mal_node_status($i_events) 0 						;#	 Initially, all malicious nodes are off..
		
		$ns_ at $val(mal_time) "toggle_periodic_mal_cbr $i_events"	;#	..but now, we will turn them on
	}
} elseif {$val(attack-type) == "r"} {			;# random jamming
	for {set i_events $val(ben_nn)} {$i_events < $val(nn)} {incr i_events} {
		set mal_node_status($i_events) 0 							;#	 Initially, all malicious nodes are off..
		$ns_ at $val(mal_time) "toggle_random_mal_cbr $i_events"	;#	..but now, we will turn them on
	}	
} else {										;# invalid argument
	puts "Invalid attack type. Valid attack types are:-\n\tc - constant\n\tp - periodic\n\tr - random"
	exit 0
}


# Periodic jamming - Procedure to toggle malicious CBRs.
proc toggle_periodic_mal_cbr {id} {
	global ns_ val mal_node_status mal_periods m_cbr_
	set now [$ns_ now]
	set next_time [expr {$now + $mal_periods($id)}]

	# Toggling status of the malicious node using bitwise XOR
	set mal_node_status($id) [expr {$mal_node_status($id) ^ 1}]
	# Number of outgoing connections per malicious node.
	set conns_per_mal_node [expr {$val(nn) - 1}]

	set first_conn [expr {($id - $val(ben_nn)) * $conns_per_mal_node}]
	set last_conn [expr {$first_conn + $conns_per_mal_node}]

	for {set i_events $first_conn} {$i_events < $last_conn} {incr i_events} {
		if {$mal_node_status($id) == 1} {
			$m_cbr_($i_events) start
		} else {
			$m_cbr_($i_events) stop
		}
	}

	if {$next_time <= $val(sim_time)} {
		$ns_ at $next_time "toggle_periodic_mal_cbr $id"
	}
}

# Random jamming - Procedure to toggle malicious CBRs.
proc toggle_random_mal_cbr {id} {
	global ns_ val mal_node_status m_cbr_
	set now [$ns_ now]

	# The time instant when the malicious node would be toggled can be between [2, 5]
	set next_time [expr {$now + (2 + int(rand()*4))}]

	# Toggling status of the malicious node using bitwise XOR
	set mal_node_status($id) [expr {$mal_node_status($id) ^ 1}]

	# Number of outgoing connections per malicious node.
	set conns_per_mal_node [expr {$val(nn) - 1}]

	set first_conn [expr {($id - $val(ben_nn)) * $conns_per_mal_node}]
	set last_conn [expr {$first_conn + $conns_per_mal_node}]

	for {set i_events $first_conn} {$i_events < $last_conn} {incr i_events} {
		if {$mal_node_status($id) == 1} {
			$m_cbr_($i_events) start
		} else {
			$m_cbr_($i_events) stop
		}
	}

	if {$next_time <= $val(sim_time)} {
		$ns_ at $next_time "toggle_random_mal_cbr $id"
	}
}

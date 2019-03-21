# setting up legitimate connections. Each benign node connects only with other benign nodes.
# A random number is generated (either a 0 or 1); depending on which a connection is set up
# between a pair of legitimate nodes.
set legit_conn 0

for {set i_conn 0} {$i_conn < $val(ben_nn)} {incr i_conn} {			;# each benign node..
	for {set j_conn 0} {$j_conn < $val(ben_nn)} {incr j_conn} {		;# connects to benign nodes only
		if {$i_conn != $j_conn} {									;# but, does not connect with itself!
			set rand_num [expr {int(rand()*2)}]

			if {$rand_num == 1} {
				set l_udp_($legit_conn) [new Agent/UDP]
				$ns_ attach-agent $node_($i_conn) $l_udp_($legit_conn)

				set l_cbr_($legit_conn) [new Application/Traffic/CBR]
				$l_cbr_($legit_conn) set rate_ 2e5
				$l_cbr_($legit_conn) attach-agent $l_udp_($legit_conn)

				set l_sink_($legit_conn) [new Agent/LossMonitor]
				$ns_ attach-agent $node_($j_conn) $l_sink_($legit_conn)

				$ns_ connect $l_udp_($legit_conn) $l_sink_($legit_conn)
				incr legit_conn
			}
		}
	}
}

# setting up malicious nodes. A malicious node connects to all nodes (except itself).
# Therefore, at the end of the nested loops below, the mal_conn variable will contain the value:
# malicious nodes * (total nodes - 1)
# This property will become important while implementing periodic and random jamming.
set mal_conn 0

# Please NOTE: If you change the condition of the inner loop (e.g., make the malicious nodes connect
# to only the benign nodes), then you would have to update the initial value of the variable
# "conns_per_mal_node" in the events file (events_jammer_try2.tcl; in procedures
# toggle_periodic_mal_cbr and toggle_random_mal_cbr).
for {set i_conn $val(ben_nn)} {$i_conn < $val(nn)} {incr i_conn} {	;# each malicious node..
	for {set j_conn 0} {$j_conn < $val(nn)} {incr j_conn} {			;# ..connects to all other nodes
		if {$i_conn != $j_conn} {									;# but, does not connect with itself!
			set m_udp_($mal_conn) [new Agent/UDP]
			$ns_ attach-agent $node_($i_conn) $m_udp_($mal_conn)

			set m_cbr_($mal_conn) [new Application/Traffic/CBR]
			$m_cbr_($mal_conn) set packetSize_ 8192
			$m_cbr_($mal_conn) set rate_ 5e+6
			$m_cbr_($mal_conn) attach-agent $m_udp_($mal_conn)

			set null_($mal_conn) [new Agent/Null]
			$ns_ attach-agent $node_($j_conn) $null_($mal_conn)

			$ns_ connect $m_udp_($mal_conn) $null_($mal_conn)
			incr mal_conn
		}
	}
}

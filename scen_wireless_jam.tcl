for {set i_scen 0} {$i_scen < $val(nn)} {incr i_scen} {
	set node_($i_scen) [$ns_ node]

	$node_($i_scen) set X_ [expr {int( rand() * $val(maxx) )}]
	$node_($i_scen) set Y_ [expr {int( rand() * $val(maxy) )}]
	$node_($i_scen) set Z_ 0.0
	
	$node_($i_scen) random-motion 0
	$ns_ initial_node_pos $node_($i_scen) 20
	
	# malicious nodes are created at the last. Colour them red.
	if {$i_scen >= $val(ben_nn)} {
		$node_($i_scen) color Red
		$ns_ at 0.0 "$node_($i_scen) color Red"
	}
}

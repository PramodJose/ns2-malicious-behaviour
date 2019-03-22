from os import system, remove
from time import time
from multiprocessing import Pool
from datetime import timedelta

tcl_script = "wireless_jam.tcl"
attacks = ["c", "p", "r"]                   # types of attacks: constant (c), periodic (p), random (r)
out_file_names = ["thrput_", "delay_"]      # output file name prefixes of a single run
node_count = 10
run_count = 50


def calc_delay(trace_file, nodes, mal_percentage):
    avg_delay = 0
    sent_time = dict()  # of the form sent_time[pkt_id] = time
    pckts_recvd = 0
    ben_nodes = int(nodes * (1 - mal_percentage))

    try:
        with open(trace_file, "r") as in_fh:
            for line in in_fh:
                split_line = line.split()

                if len(split_line) < 20 or split_line[3] != "AGT":
                    continue
                sender_id = int(split_line[13][1:].split(":")[0])
                if sender_id >= ben_nodes:
                    continue
                pkt_id = int(split_line[5])
                time = float(split_line[1])

                if line.startswith("s "):
                    sent_time[pkt_id] = time
                elif line.startswith("r "):
                    pckts_recvd += 1
                    avg_delay += time - sent_time.pop(pkt_id)

    except KeyError:
        print("Mismatch in packet IDs in the trace file: " + trace_file)
        print("Exiting...")
        exit(1)

    avg_delay /= pckts_recvd
    remove(trace_file)
    return avg_delay


def simulation_instance(command):
    system(command)

    split_cmd = command.split()
    thr_file = split_cmd[5] + split_cmd[7]
    trace_file = split_cmd[6] + split_cmd[7]

    in_fh = open(thr_file, "r")
    throughput = float(in_fh.readline())
    in_fh.close()
    remove(thr_file)

    delay = calc_delay(trace_file, int(split_cmd[2]), float(split_cmd[3]))
    return throughput, delay


if __name__ == "__main__":
    start_time = time()

    for attack_id in range(len(attacks)):
        print("Working on attack " + attacks[attack_id])
        out_thr_fh = open(out_file_names[0] + attacks[attack_id], "w")
        out_del_fh = open(out_file_names[1] + attacks[attack_id], "w")

        for percentg in range(0, 6):    # percentage of malicious nodes
            mal_node_percentage = percentg / 10
            print("Percentage: " + str(mal_node_percentage))
            throughput = 0
            delay = 0
            commands = []

            for i in range(run_count):
                command = "ns " + tcl_script + " " + str(node_count) + " " + str(mal_node_percentage) + " " + attacks[attack_id] + " " \
                          + out_file_names[0] + " " + out_file_names[1] + " " + str(i) + " > /dev/null 2>&1"
                commands.append(command)

            p = Pool()
            result_list = p.map(simulation_instance, commands)
            p.close()
            p.join()

            for i in range(run_count):
                throughput += result_list[i][0]
                delay += result_list[i][1]

            avg_throughput = throughput / run_count
            avg_delay = delay / run_count
            out_thr_fh.write(str(mal_node_percentage) + " " + str(avg_throughput) + "\n")
            out_del_fh.write(str(mal_node_percentage) + " " + str(avg_delay) + "\n")

        out_del_fh.close()
        out_thr_fh.close()
        print(f"\nThroughput graph :\t{out_file_names[0] + attacks[attack_id]}")
        print(f"Avg delay graph : \t{out_file_names[1] + attacks[attack_id]}")
        print("\n===============================================================\n")

    print(f"Execution time :\t{timedelta(seconds=time() - start_time)}")

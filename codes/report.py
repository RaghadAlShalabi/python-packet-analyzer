class ReportGenerator:

    def generate_report(
        self,
        total_packets,
        total_bytes,
        protocol_count,
        connections,
        ip_counter,
        port_tracker,
        icmp_counter,
        mode,
        top_ip,
        max_packets
    ):

        try:

            file = open("report.txt", "w")

            file.write("         NETWORK TRAFFIC ANALYSIS REPORT\n")
            file.write("====================================================\n\n")

            # General Statistics
            file.write("1. GENERAL STATISTICS\n")
            file.write("----------------------------------------------------\n")

            file.write("Total Packets Captured : " + str(total_packets) + "\n")
            file.write("Total Bytes Transferred: " + str(total_bytes) + "\n")
            file.write("Capture Mode           : " + mode + "\n\n")

            # Protocol Statistics
            file.write("2. PROTOCOL STATISTICS\n")
            file.write("----------------------------------------------------\n")

            if len(protocol_count) == 0:

                file.write("No protocols detected\n")

            else:

                for p in protocol_count:
                    file.write(p + " : " + str(protocol_count[p]) + " packets\n")

            file.write("\n")

            # Top Talker Analysis
            file.write("3. TOP TALKER ANALYSIS\n")
            file.write("----------------------------------------------------\n")

            if top_ip != "":

                file.write("Most Active IP Address : " + top_ip + "\n")
                file.write("Packets Sent           : " + str(max_packets) + "\n")

                if total_packets > 0:

                    percentage = (max_packets / total_packets) * 100

                    file.write("Traffic Percentage     : ")
                    file.write(str(round(percentage, 2)) + "%\n")

                else:
                    file.write("Traffic Percentage     : 0%\n")

            else:

                file.write("No IP addresses detected\n")

            file.write("\n")

            # Connection Summary
            file.write("4. CONNECTION SUMMARY\n")
            file.write("----------------------------------------------------\n")

            if len(connections) == 0:

                file.write("No connections found\n")

            else:

                counter = 0

                for conn in connections:

                    file.write(
                        conn +
                        "  --->  " +
                        str(connections[conn]) +
                        " times\n"
                    )

                    counter += 1

                    if counter == 30:
                        break

            file.write("\n")

            # Suspicious Activity
            file.write("5. SUSPICIOUS ACTIVITY DETECTION\n")
            file.write("----------------------------------------------------\n")

            suspicious_found = False

            # Possible DoS
            for ip in ip_counter:

                if ip_counter[ip] >= 300:

                    file.write(
                        "[WARNING] Possible DoS Activity from IP: "
                        + ip +
                        "\n"
                    )

                    suspicious_found = True

            # Possible Port Scan
            for ip in port_tracker:

                if len(port_tracker[ip]) >= 40:

                    file.write(
                        "[WARNING] Possible Port Scanning from IP: "
                        + ip +
                        "\n"
                    )

                    suspicious_found = True

            # ICMP Flood
            for ip in icmp_counter:

                if icmp_counter[ip] >= 50:

                    file.write(
                        "[WARNING] High ICMP Traffic Detected from IP: "
                        + ip +
                        "\n"
                    )

                    suspicious_found = True

            if suspicious_found == False:
                file.write("No obvious suspicious activity detected\n")

            file.write("\n")

            # Final Analysis
            file.write("6. FINAL ANALYSIS\n")
            file.write("----------------------------------------------------\n")

            file.write(
                "This report summarizes the analyzed network traffic "
                "and provides monitoring information about "
                "protocol usage, active hosts, connections, and "
                "potential suspicious behavior.\n\n"
            )

            file.write(
                "The analysis can help identify unusual traffic "
                "patterns such as excessive packet generation, "
                "port scanning attempts, or abnormal ICMP activity.\n"
            )

            file.write("\n")

            # End of Report
            file.write("====================================================\n")
            file.write("                 END OF REPORT\n")
            file.write("====================================================\n")

            file.close()

            print("\nReport saved successfully to report.txt")

        except Exception as e:

            print("Error writing report")
            print(e)
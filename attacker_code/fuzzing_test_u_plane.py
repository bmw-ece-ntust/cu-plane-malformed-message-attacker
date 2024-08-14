from scapy.all import *
from datetime import datetime
import sys

class Fuzzer:
    def __init__(self, pcap_file, output_dir):
        self.pcap_file = pcap_file
        self.output_dir = output_dir
        self.modified_packets = []

    def read_pcap(self):
        try:
            return rdpcap(self.pcap_file)
        except FileNotFoundError:
            print(f"Error: File not found - {self.pcap_file}")
            sys.exit(1)

    def write_pcap(self, packets, field_name):
        try:
            output_filename = f"{self.output_dir}/{field_name}.pcap"
            wrpcap(output_filename, packets)
            print(f"Modified packets written to {output_filename}")
        except PermissionError:
            print(f"Error: Permission denied - {output_filename}")
            sys.exit(1)

    def fuzz_o_ran_fh_u_packet(self, packet, fields_to_fuzz):
        if "o_ran_fh_u" in packet:
            rand_number_of_sections = RandNum(0, 10)
            # Modify the MAC addr
            packet[Ether].dst = "00:11:22:33:44:66" #OAIDU
            #packet[Ether].src = "00:E0:0C:00:AE:06" #MetaRU
            packet[Ether].src = "00:aa:ff:bb:ff:cc" #Lite-OnRU
            #packet[Ether].dst = "00:11:22:33:44:33" #TYDU
            #packet[Ether].dst = "00:11:22:33:44:66" #OAIDU
            packet[Dot1Q].vlan = 4

            # Modify the specified fields based on user input
            for field in fields_to_fuzz:
                if field == "ecpriPcid.du_port_id":
                    packet["o_ran_fh_u"].ecpriPcid.du_port_id = RandNum(0, 15)
                elif field == "ecpriPcid.bandsector_id":
                    packet["o_ran_fh_u"].ecpriPcid.bandsector_id = RandNum(0, 63)
                elif field == "ecpriPcid.cc_id":
                    packet["o_ran_fh_u"].ecpriPcid.cc_id = RandNum(0, 15)
                elif field == "ecpriPcid.ru_port_id":
                    packet["o_ran_fh_u"].ecpriPcid.ru_port_id = RandNum(4, 15)
                elif field == "ecpriPcid":
                    # If "ecpriPcid" is specified without a subfield, modify all subfields
                    packet["o_ran_fh_u"].ecpriPcid.du_port_id = RandNum(0, 3)
                    packet["o_ran_fh_u"].ecpriPcid.bandsector_id = RandNum(0, 63)
                    packet["o_ran_fh_u"].ecpriPcid.cc_id = RandNum(0, 15)
                    packet["o_ran_fh_u"].ecpriPcid.ru_port_id = RandNum(0, 15)
                elif field == "ecpriSeqid.sequence_id":   
                    packet["o_ran_fh_u"].ecpriSeqid.sequence_id = RandNum(0, 255)
                elif field == "ecpriSeqid.e_bit": 
                    packet["o_ran_fh_u"].ecpriSeqid.e_bit = RandNum(0, 1)
                elif field == "ecpriSeqid.subsequence_id": 
                    packet["o_ran_fh_u"].ecpriSeqid.subsequence_id = RandNum(0, 127)
                elif field == "ecpriSeqid":
                    packet["o_ran_fh_u"].ecpriSeqid.sequence_id = RandNum(0, 255)
                    packet["o_ran_fh_u"].ecpriSeqid.e_bit = RandNum(0, 1)
                    packet["o_ran_fh_u"].ecpriSeqid.subsequence_id = RandNum(0, 127) 
                # Modify the u_plane fields
                elif field == "u_plane.dataDirection":
                    packet["o_ran_fh_u"].u_plane.dataDirection = RandNum(0, 1)
                elif field == "u_plane.payloadVersion":
                    packet["o_ran_fh_u"].u_plane.payloadVersion = RandNum(0, 7)
                elif field == "u_plane.filterIndex":
                    packet["o_ran_fh_u"].u_plane.filterIndex = RandNum(0, 8)
                elif field == "u_plane.frameId":
                    packet["o_ran_fh_u"].u_plane.frameId = RandByte()
                elif field == "u_plane.subframeId":
                    packet["o_ran_fh_u"].u_plane.subframeId = RandNum(0, 15)
                elif field == "u_plane.slotID":
                    packet["o_ran_fh_u"].u_plane.slotID = RandNum(0, 63)
                elif field == "u_plane.startSymbolId":
                    packet["o_ran_fh_u"].u_plane.startSymbolId = RandNum(0, 63)
                elif field == "u_plane":
                    packet["o_ran_fh_u"].u_plane.dataDirection = RandNum(0, 1)
                    packet["o_ran_fh_u"].u_plane.payloadVersion = RandNum(0, 7)
                    packet["o_ran_fh_u"].u_plane.filterIndex = RandNum(0, 15)
                    packet["o_ran_fh_u"].u_plane.frameId = RandByte()
                    packet["o_ran_fh_u"].u_plane.subframeId = RandNum(0, 15)
                    packet["o_ran_fh_u"].u_plane.slotID = RandNum(0, 63)
                    packet["o_ran_fh_u"].u_plane.startSymbolId = RandNum(0, 63)
                elif field == "section_u.sectionId":
                    for section_layer in packet["o_ran_fh_u"].section:
                        section_layer.sectionId = RandNum(0, 4095)
                elif field == "section_u.rb":
                    for section_layer in packet["o_ran_fh_u"].section:
                        section_layer.rb = RandNum(0, 1)
                elif field == "section_u.symInc":
                    for section_layer in packet["o_ran_fh_u"].section:
                        section_layer.symInc = RandNum(0, 1)
                elif field == "section_u.startPrbu":
                    for section_layer in packet["o_ran_fh_u"].section:
                            section_layer.startPrbu = RandNum(0, 1023)
                elif field == "section_u.numPrbu":
                    for section_layer in packet["o_ran_fh_u"].section:
                           section_layer.numPrbu = RandByte()
                elif field == "PRB.reserved":
                    for section_layer in packet["o_ran_fh_u"].section:
                        if section_layer.haslayer("prb"):  # Check if prb layer exists
                            for prb_layer in section_layer.prb:
                                prb_layer.reserved = RandNum(0,15)
                elif field == "PRB.exponent":
                    for section_layer in packet["o_ran_fh_u"].section:
                        if section_layer.haslayer("prb"):  # Check if prb layer exists
                            for prb_layer in section_layer.prb:
                                prb_layer.exponent = RandNum(0,15)
                elif field == "PRB.iq_user_data":
                    for section_layer in packet["o_ran_fh_u"].section:
                        if section_layer.haslayer("prb"):  # Check if prb layer exists
                            for prb_layer in section_layer.prb:
                                prb_layer.iq_user_data = RandNum(0, 2**192-1) 
                else:
                    print(f"Error: {field} is not a valid field for fuzzing or does not exist in the packet.")
        # Return the fuzzed packet
        return packet

    def fuzz_and_send_packets(self, fields_to_fuzz, iterations=1):
        packets = self.read_pcap()
        for i in range(iterations):           
            iteration_packets_sent = 0

            for packet_num, packet in enumerate(packets, start=1):
                fuzzed_packet = self.fuzz_o_ran_fh_u_packet(packet, fields_to_fuzz)
                # sendp(fuzzed_packet, iface=conf.iface, verbose=False)
                sendp(fuzzed_packet, iface="enp3s0f1", verbose=False)
                #sendpfast(fuzzed_packet, iface="enp3s0f1", mbps=5)
                self.modified_packets.append(fuzzed_packet)
                iteration_packets_sent += 1

            # print(f"Iteration {i + 1}. Packets sent: {iteration_packets_sent}")
            print(f"Iteration {i + 1}.")

        print(f"Total packets sent: {len(self.modified_packets)}")
        self.write_pcap(self.modified_packets, fields_to_fuzz)



def main():
    #load_layer("oran_fh")
    load_layer("heidi_oran_u_OAI")
    pcap_file = ""
    output_dir = ""
    
    print("Finish loading the oran_fh protocol!\nStart fuzzing...")

    fuzzer = Fuzzer(pcap_file, output_dir)

    print("Enter the fields to fuzz in the following format:")
    print("Example 1: ecpriPcid.du_port_id\nExample 2: ecpriPcid (to fuzz all subfields)")

    fields_to_fuzz = input("Fields to fuzz: ").split(',')

    fuzzer.fuzz_and_send_packets(fields_to_fuzz)

if __name__ == "__main__":
    main()

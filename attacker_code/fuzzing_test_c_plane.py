from scapy.all import *
from datetime import datetime
import sys

class Fuzzer:
    def __init__(self, pcap_file, output_dir):
        self.pcap_file = pcap_file
        self.output_dir = output_dir
        self.modified_packets = []

    def fuzz_o_ran_fh_c_packet(self, packet, fields_to_fuzz):
        # Modify the existing packet's o_ran_fh_c layer
        if "o_ran_fh_c" in packet:
            rand_number_of_sections = RandNum(0, 10)
            # Modify the MAC addr
            packet[Ether].dst = "00:11:22:33:44:66" #OAIDU
            #packet[Ether].src = "00:E0:0C:00:AE:06" #MetaRU
            packet[Ether].src = "00:aa:ff:bb:ff:cc" #Lite-OnRU
            #packet[Ether].dst = "00:11:22:33:44:33" #TYDU
            #packet[Ether].src = "00:11:22:33:44:66" #OAIDU
            packet[Dot1Q].vlan = 4

            # Modify the specified fields based on user input
            for field in fields_to_fuzz:
                if field == "ecpriRtcid.du_port_id":
                    packet["o_ran_fh_c"].ecpriRtcid.du_port_id = RandNum(0, 3)
                elif field == "ecpriRtcid.bandsector_id":
                    packet["o_ran_fh_c"].ecpriRtcid.bandsector_id = RandNum(0, 63)
                elif field == "ecpriRtcid.cc_id":
                    packet["o_ran_fh_c"].ecpriRtcid.cc_id = RandNum(0, 15)
                elif field == "ecpriRtcid.ru_port_id":
                    packet["o_ran_fh_c"].ecpriRtcid.ru_port_id = RandNum(0, 15)
                elif field == "ecpriRtcid":
                    # If "ecpriRtcid" is specified without a subfield, modify all subfields
                    packet["o_ran_fh_c"].ecpriRtcid.du_port_id = RandNum(0, 3)
                    packet["o_ran_fh_c"].ecpriRtcid.bandsector_id = RandNum(0, 63)
                    packet["o_ran_fh_c"].ecpriRtcid.cc_id = RandNum(0, 15)
                    packet["o_ran_fh_c"].ecpriRtcid.ru_port_id = RandNum(0, 15)
                elif field == "ecpriSeqid.sequence_id":   
                    packet["o_ran_fh_c"].ecpriSeqid.sequence_id = RandNum(0, 255)
                elif field == "ecpriSeqid.e_bit": 
                    packet["o_ran_fh_c"].ecpriSeqid.e_bit = RandNum(0, 1)
                elif field == "ecpriSeqid.subsequence_id": 
                    packet["o_ran_fh_c"].ecpriSeqid.subsequence_id = RandNum(0, 127)
                    #packet["o_ran_fh_c"].ecpriSeqid.e_bit = 1
                elif field == "ecpriSeqid":
                    packet["o_ran_fh_c"].ecpriSeqid.sequence_id = RandNum(0, 255)
                    packet["o_ran_fh_c"].ecpriSeqid.e_bit = RandNum(0, 1)
                    packet["o_ran_fh_c"].ecpriSeqid.subsequence_id = RandNum(0, 127) 
                # Modify the c_plane fields
                elif field == "c_plane.dataDirection":
                    packet["o_ran_fh_c"].c_plane.dataDirection = RandNum(0, 1)
                elif field == "c_plane.payloadVersion":
                    packet["o_ran_fh_c"].c_plane.payloadVersion = RandNum(0, 7)
                elif field == "c_plane.filterIndex":
                    packet["o_ran_fh_c"].c_plane.filterIndex = RandNum(0, 15)
                elif field == "c_plane.frameId":
                    packet["o_ran_fh_c"].c_plane.frameId = RandByte()
                elif field == "c_plane.subframeId":
                    packet["o_ran_fh_c"].c_plane.subframeId = RandNum(0, 15)
                elif field == "c_plane.slotID":
                    packet["o_ran_fh_c"].c_plane.slotID = RandNum(0, 63)
                elif field == "c_plane.startSymbolId":
                    packet["o_ran_fh_c"].c_plane.startSymbolId = RandNum(0, 63)
                elif field == "c_plane.numberOfsections":
                    packet["o_ran_fh_c"].c_plane.numberOfsections = RandByte()
                elif field == "c_plane.sectionType":
                    packet["o_ran_fh_c"].c_plane.sectionType = RandNum(0,7)
                elif field == "c_plane.udCompHdr":
                    packet["o_ran_fh_c"].c_plane.udCompHdr = RandByte()
                elif field == "c_plane.reserved":
                    packet["o_ran_fh_c"].c_plane.reserved = RandByte()
                elif field == "c_plane":
                    packet["o_ran_fh_c"].c_plane.dataDirection = RandNum(0, 1)
                    packet["o_ran_fh_c"].c_plane.payloadVersion = RandNum(0, 7)
                    packet["o_ran_fh_c"].c_plane.filterIndex = RandNum(0, 15)
                    packet["o_ran_fh_c"].c_plane.frameId = RandByte()
                    packet["o_ran_fh_c"].c_plane.subframeId = RandNum(0, 15)
                    packet["o_ran_fh_c"].c_plane.slotID = RandNum(0, 63)
                    packet["o_ran_fh_c"].c_plane.startSymbolId = RandNum(0, 63)
                    packet["o_ran_fh_c"].c_plane.numberOfsections = RandByte()
                    packet["o_ran_fh_c"].c_plane.sectionType = RandByte()
                    packet["o_ran_fh_c"].c_plane.udCompHdr = RandByte()
                    packet["o_ran_fh_c"].c_plane.reserved = RandByte()
                elif field == "section.sectionId":
                    for section_layer in packet["o_ran_fh_c"].section:
                        section_layer.sectionId = RandNum(0, 4095)
                elif field == "section.rb":
                    for section_layer in packet["o_ran_fh_c"].section:
                        section_layer.rb = RandNum(0, 1)
                elif field == "section.symInc":
                    for section_layer in packet["o_ran_fh_c"].section:
                        section_layer.symInc = RandNum(0, 1)
                elif field == "section.startPrbc":
                    for section_layer in packet["o_ran_fh_c"].section:
                        section_layer.startPrbc = RandNum(0, 1023)
                elif field == "section.numPrbc":
                    for section_layer in packet["o_ran_fh_c"].section:
                        section_layer.numPrbc = RandByte()
                elif field == "section.reMask":
                    for section_layer in packet["o_ran_fh_c"].section:
                        section_layer.reMask = RandNum(0x000, 0xfff)
                elif field == "section.numSymbol":
                    for section_layer in packet["o_ran_fh_c"].section:
                        section_layer.numSymbol = RandNum(0, 15)
                elif field == "section.ef":
                    for section_layer in packet["o_ran_fh_c"].section:
                        section_layer.ef = RandNum(0,1)
                elif field == "section.beamId":
                    for section_layer in packet["o_ran_fh_c"].section:
                        section_layer.beamId = RandNum(0, 32767)
                elif field == "section":
                    for section_layer in packet["o_ran_fh_c"].section:
                        section_layer.sectionId = RandNum(0, 4095)
                        section_layer.rb = RandNum(0, 1)
                        section_layer.symInc = RandNum(0, 1)
                        section_layer.startPrbc = RandNum(0, 1023)
                        section_layer.numPrbc = RandByte()
                        section_layer.reMask = RandNum(0x000, 0xfff)
                        section_layer.numSymbol = RandNum(0, 15)
                        section_layer.ef = 0
                        section_layer.beamId = RandNum(0, 32767)
                else:
                    print(f"Error: {field} is not a valid field for fuzzing.")

        return packet

    def read_pcap(self):
        try:
            return rdpcap(self.pcap_file)
        except FileNotFoundError:
            print(f"Error: File not found - {self.pcap_file}")
            sys.exit(1)

    def write_pcap(self):
        try:
            output_filename = f"{self.output_dir}/{datetime.now().strftime('%m%d%H%M%S')}.pcap"
            wrpcap(output_filename, self.modified_packets)
            print(f"Modified packets written to {output_filename}")
        except PermissionError:
            print(f"Error: Permission denied - {output_filename}")
            sys.exit(1)

    def fuzz_and_send_packets(self, fields_to_fuzz, iterations=100):
        packets = self.read_pcap()
        for i in range(iterations):
            
            iteration_packets_sent = 0

            for packet_num, packet in enumerate(packets, start=1):
                fuzzed_packet = self.fuzz_o_ran_fh_c_packet(packet, fields_to_fuzz)
                # sendp(fuzzed_packet, iface=conf.iface, verbose=False)
                sendp(fuzzed_packet, iface="enp3s0f1", verbose=False)
                self.modified_packets.append(fuzzed_packet)
                iteration_packets_sent += 1

            print(f"Iteration {i + 1}. Packets sent: {iteration_packets_sent}")

        print(f"Total packets sent: {len(self.modified_packets)}")
        self.write_pcap()

def main():
    load_layer("oran_fh")
    
    pcap_file = ""
    output_dir = ""
    
    print("Finish loading the oran_fh protocol!\nStart fuzzing...")

    fuzzer = Fuzzer(pcap_file, output_dir)

    print("Enter the fields to fuzz in the following format:")
    print("Example 1: ecpriRtcid.du_port_id\nExample 2: ecpriRtcid (to fuzz all subfields)")

    fields_to_fuzz = input("Fields to fuzz: ").split(',')

    fuzzer.fuzz_and_send_packets(fields_to_fuzz)

if __name__ == "__main__":
    main()


#!/usr/bin/env python

from main import PKT_DIR_INCOMING, PKT_DIR_OUTGOING
import socket, struct, random

# TODO: Feel free to import any Python standard moduless as necessary.
# (http://docs.python.org/2/library/)
# You must NOT use any 3rd-party libraries, though.

class Firewall:
    TCP = 6
    UDP = 17
    def __init__(self, config, iface_int, iface_ext):
        self.iface_int = iface_int
        self.iface_ext = iface_ext

        # TODO: Load the firewall rules (from rule_filename) here.
        self.rules = []
        rules = open('rules.conf')
        for line in rules:
            if line[0] != '%' and line != '\n':
                line = line.replace('\n', '')
                line = line.split()
                line[1] = line[1].lower()
                line[0] = line[0].lower()
                self.rules.append(tuple(line)) # line has format: (<verdict>, <protocol>, <external IP address>, <external port>) 
                                               # or (<verdict>, dns, <domain name>)
                                               #or (log, http, <host name>)

    # @pkt_dir: either PKT_DIR_INCOMING or PKT_DIR_OUTGOING
    # @pkt: the actual data of the IPv4 packet (including IP header)
    def handle_packet(self, pkt_dir, pkt):
        header_len = (ord(pkt[0:1]) & 0x0f) * 4
        #drop packet if header length is < 5 (spec)
        if header_len < 5:
            return
        ip_header = pkt[0: header_len]
        transport_header = pkt[header_len:]
        protocol = ord(ip_header[9:10])
        
        if pkt_dir == PKT_DIR_OUTGOING:
            external_ip = ip_header[16: 20]
            external_port_in_bytes = transport_header[2:4]
            external_port = struct.unpack('!H', external_port_in_bytes)[0]
        #packet is incoming
        else:
            external_ip = ip_header[12:16] # initialize external_ip to source ip (where packet came from)
            external_port_in_bytes = transport_header[0:2]
            external_port = struct.unpack('!H', external_port_in_bytes)[0]

        try:
            external_ip = socket.inet_ntoa(external_ip) #go from bytes to ip string
        except socket.error:
            return

        #figure out what type of packet we have.
        is_dns_packet = False
        
        #handle dns parsing
        if external_port == 53 and protocol == Firewall.UDP:
            is_dns_packet = True #we know we have a DNS packet.
            dns_header = transport_header[8:]
            qd_count = struct.unpack('!H', dns_header[4:6])[0]
            if qd_count > 1:
                return
            dns_question = dns_header[12:] #question portion of dns header
            domain, qtype = self.get_domain_name(dns_question) #domain name (e.g. 'www.google.com')
            
            # only consider packets with proper qtype (1 or 28) for dns rule matches
            if qtype not in (1,28):
                is_dns_packet = False

        #handle packet rule matching.
        curr_match = None
        for rule in self.rules:
            #we have a deny tcp rule 
            if rule[1] == 'tcp' and self.external_ip_matches(external_ip, rule[2].lower()) and self.external_port_matches(external_port, rule[3]):
                # print('matched ip: ' + external_ip)
                curr_match = rule
            #only check DNS rules if packet is a dns packet
            elif is_dns_packet and rule[1].lower() == 'dns' and self.domain_matches(domain, rule[2].lower()):
                curr_match = rule
        
        #send packet if it does not match any rules.
        if curr_match == None:
            if pkt_dir == PKT_DIR_INCOMING:
                self.iface_int.send_ip_packet(pkt)
            elif pkt_dir == PKT_DIR_OUTGOING:
                self.iface_ext.send_ip_packet(pkt)
        else:
            if curr_match[1] == 'tcp':
                #add ip header
                new_pkt = struct.pack('!B', 69) #version_plus_hlen
                new_pkt += struct.pack('!B', 0) #tos 
                new_pkt += struct.pack('!H', 40) #total_len
                new_pkt += struct.pack('!L', 0) #identification_plus_offset
                new_pkt += struct.pack('!B', 3) #ttl
                
                #flag is this always tcp?
                new_pkt += struct.pack('!B', 6) #protocol
                dummy = new_pkt
                dummy += struct.pack('!H', 0) #empty checksum
                (external_ip)
                # print('source ip' + socket.inet_ntoa(pkt[16:20]))
                # print('destination ip' + socket.inet_ntoa(pkt[12:16]))
                dummy += pkt[16:20] #source
                dummy += pkt[12:16] #destination
                ip_checksum = self.gen_checksum(dummy)
                new_pkt += struct.pack('!H', ip_checksum) #checksum for actual packet
                new_pkt += pkt[16:20] #source for actual
                new_pkt += pkt[12:16] #destination for actual

                #add transport header
                new_pkt += transport_header[2:4] #source port
                new_pkt += transport_header[0:2] #destination port
                new_pkt += struct.pack('!L', random.randrange(0,10)) #seq number
                seq_num = struct.unpack('!L', transport_header[4:8])[0]
                new_pkt += struct.pack('!L', seq_num + 1) #ack num
                new_pkt += struct.pack('!B', 0) #offset + reserved fields   

                #set rst and ack flags
                new_pkt += struct.pack('!B', 20)

                new_pkt += struct.pack('!H', 0) #window
                dummy = new_pkt
                dummy += struct.pack('!H', 0) #checksum
                dummy += struct.pack('!H', 0) #urgent pointer
                tcp_checksum = self.gen_checksum(dummy[20:]) # pass 20 byte transport header
                new_pkt += struct.pack('!H', tcp_checksum) # tcp checksum for actual packet
                new_pkt += struct.pack('!H', 0) #urgent pointer for actual packet

                self.iface_int.send_ip_packet(new_pkt)
            # elif is_dns_packet and rule[1].lower() == 'dns' and self.domain_matches(domain, rule[2]):
            #     if qtype == 28:
            #         return





    # TODO: You can add more methods as you want.
    def gen_checksum(self, header):
        summ = 0
        for i in range(0,10):
            summ += struct.unpack('!H', header[0:2])[0]
            header = header[2:]
        summ_to_binstring = bin(summ).replace('0b', '')
        if len(summ_to_binstring) > 16:
            diff = len(summ_to_binstring) - 16
            partial_sum = summ_to_binstring[diff:] #get main 16bits
            carry = summ_to_binstring[0: diff + 1]
            summ = int(partial_sum, 2) + int(carry, 2)
        return summ ^ 0xffff

    def protocol_matches(self, packet_prot, rule_prot):
        if rule_prot == 'any':
            return True
        return packet_prot == self.protocol_string_to_num(rule_prot)
    
    @staticmethod
    def protocol_string_to_num(prot):
        if prot == 'icmp':
            return 1
        elif prot == 'tcp':
            return 6
        elif prot == 'udp':
            return 17 
    
    def external_ip_matches(self, external_ip, rule_ip):
        if rule_ip == 'any':
            return True
        #rule_ip is a 2 byte country code (e.g. 'it')
        elif len(rule_ip) == 2:
            external_ip = self.ip2long(external_ip) #go from bytes to ip string to long.
            db_entry = self.db_search(external_ip, self.ip_DB, 0, len(self.ip_DB) - 1)
            return db_entry and db_entry[2].lower() == rule_ip
        #we have cidr notation
        elif '/' in rule_ip:
            sig_bits = int(rule_ip[-1]) # get thing after the slash (number of bits we have to look at)
            if sig_bits == 0:
                return True
            rule_ip = rule_ip[0: rule_ip.index('/')] #isolate ip address
            rule_ip_as_num = self.ip2long(rule_ip)
            rule_ip_as_bin = '{0:032b}'.format(rule_ip_as_num) #go from num to binary string
            external_ip_as_num = self.ip2long(external_ip)
            external_ip_as_bin = '{0:032b}'.format(external_ip_as_num)
            return rule_ip_as_bin[0:sig_bits] == external_ip_as_bin[0:sig_bits]
        #regular ip
        else:
            return external_ip == rule_ip

    @staticmethod
    def external_port_matches(external_port, rule_port):
        if rule_port == 'any':
            return True
        if "-" not in rule_port:
            return external_port == int(rule_port)
        port_range = rule_port.split('-')
        return external_port >= int(port_range[0]) and external_port <= int(port_range[1])

    @staticmethod
    def domain_matches(domain, rule_domain):
        if rule_domain == "*":
            return True
        elif rule_domain[0] == "*":
            for i in range(1, len(rule_domain)):
                if rule_domain[-i] != domain[-i]:
                    return False
            return True
        else:
            return domain == rule_domain

    @staticmethod
    def get_domain_name(qname):
        length_byte = struct.unpack('!b', qname[0:1])[0]
        curr_byte = 1
        domain_str = ''
        while length_byte != 0:
            for i in range(0, length_byte):
                domain_str += chr(struct.unpack('!B', qname[curr_byte:(curr_byte + 1)])[0])
                curr_byte += 1
            domain_str += '.'
            length_byte = struct.unpack('!b', qname[curr_byte:(curr_byte + 1)])[0]
            curr_byte += 1
        domain_str = domain_str[0:-1] #get rid of extra '.' at end
        return domain_str, struct.unpack('!H', qname[curr_byte: curr_byte + 2])[0]

    @staticmethod
    def ip2long(ip):
        """
        Convert an IP string to long
        """
        try:
            packedIP = socket.inet_aton(ip)
        except socket.error:
            return
        return struct.unpack("!L", packedIP)[0]
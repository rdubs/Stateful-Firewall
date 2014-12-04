#!/usr/bin/env python

from main import PKT_DIR_INCOMING, PKT_DIR_OUTGOING
from ctypes import *
import socket, struct, random

# TODO: Feel free to import any Python standard moduless as necessary.
# (http://docs.python.org/2/library/)
# You must NOT use any 3rd-party libraries, though.

class Firewall:
    TCP = 6
    UDP = 17
    # map {(external IP, internal port) : ["request", request_seqno, "response", response_seqno]}
    http_connections = {}
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
        self.http_connections = {}

    # @pkt_dir: either PKT_DIR_INCOMING or PKT_DIR_OUTGOING
    # @pkt: the actual data of the IPv4 packet (including IP header)
    def handle_packet(self, pkt_dir, pkt):
        header_len = (ord(pkt[0:1]) & 0x0f) * 4
        #drop packet if header length is < 5 (spec)
        if header_len < 20:
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
            domain, qtype, qname_bytes = self.get_domain_name(dns_question) #domain name (e.g. 'www.google.com')
            
            # only consider packets with proper qtype (1 or 28) for dns rule matches
            if qtype not in (1,28):
                is_dns_packet = False

        #handle packet rule matching.
        curr_match = None
        for rule in self.rules:
            #we have a deny tcp rule 
            if rule[1] == 'tcp' and self.external_ip_matches(external_ip, rule[2].lower()) and self.external_port_matches(external_port, rule[3]):
                curr_match = rule
            #only check DNS rules if packet is a dns packet
            elif is_dns_packet and rule[1].lower() == 'dns' and self.domain_matches(domain, rule[2].lower()):
                curr_match = rule
        #send packet if it does not match any deny rules.
        if curr_match == None and protocol != Firewall.TCP and external_port != 80:
            if pkt_dir == PKT_DIR_INCOMING:
                self.iface_int.send_ip_packet(pkt)
            elif pkt_dir == PKT_DIR_OUTGOING:
                self.iface_ext.send_ip_packet(pkt)
            return

        #make sure curr_match exists
        elif curr_match and curr_match[1].lower() == 'tcp':
            source_ip = pkt[16:20]
            dest_ip = pkt[12:16]
            dummy_pkt = create_string_buffer(20)
            struct.pack_into('!BBHLBBHLL', dummy_pkt, 0, 69, 0, 40, 0, 64, 6, 0, struct.unpack('!L', source_ip)[0], struct.unpack('!L', dest_ip)[0])
            ip_checksum = self.gen_checksum(dummy_pkt.raw)
            new_pkt = create_string_buffer(20)
            struct.pack_into('!BBHLBBHLL', new_pkt, 0, 69, 0, 40, 0, 64, 6, ip_checksum, struct.unpack('!L', source_ip)[0], struct.unpack('!L', dest_ip)[0])
            new_pkt = new_pkt.raw
            
            #add transport header
            tcp_header = ''
            tcp_header += transport_header[2:4] #source port
            tcp_header += transport_header[0:2] #destination port
            tcp_header += struct.pack('!L', 0) #seq number--irrelevant
            seq_num = struct.unpack('!L', transport_header[4:8])[0]
            tcp_header += struct.pack('!L', seq_num + 1) #ack num
            
            tcp_header += struct.pack('!B', 80) #offset + reserved fields

            #set rst and ack flags
            tcp_header += struct.pack('!B', 20)

            tcp_header += struct.pack('!H', 0) #window
            dummy_tcp_header = tcp_header + struct.pack('!H', 0) #add empty checksum
            dummy_tcp_header += struct.pack('!H', 0) #urgent pointer
            tcp_pseudo_header = source_ip + dest_ip + struct.pack('!B', 0) + struct.pack('!B', 6) + struct.pack('!H', 20)
            tcp_checksum = self.gen_checksum(tcp_pseudo_header + dummy_tcp_header)

            new_pkt += tcp_header
            new_pkt += struct.pack('!H', tcp_checksum) # tcp checksum for actual packet
            new_pkt += struct.pack('!H', 0) #urgent pointer for actual packet

            self.iface_int.send_ip_packet(new_pkt)
            return
        elif curr_match and curr_match[1].lower() == 'dns':
            if qtype == 28:
                return
            #construct dns response packet
            #dns header
            dns_id = dns_header[0:2]
            b4_rcode = 128
            rcode = struct.unpack('!B', dns_header[3:4])[0] & 0xf
            qr_plus_rcode = struct.pack('!B', b4_rcode) + struct.pack('!B', rcode)
            qdcount = struct.pack('!H', 1)
            ancount = struct.pack('!H', 1)
            nscount = struct.pack('!H', 0)
            arcount = struct.pack('!H', 0)
            question = dns_header[12:] #FLAG is this okay
            dns_header = dns_id + qr_plus_rcode + qdcount + ancount + nscount + arcount + question

            #answer 
            name = qname_bytes
            ans_type = struct.pack('!H', 1) #A = 1
            ans_class = struct.pack('!H', 1)
            ans_ttl = struct.pack('!L', 1)
            rdlength = struct.pack('!H', 4) #FLAG
            rdata = struct.pack('!L', 917364886)
            dns_answer = name + ans_type + ans_class + ans_ttl + rdlength + rdata

            #add anwser to dns_header
            dns_header = dns_header + dns_answer
            dns_header_len = len(dns_header)

            #ip header
            dummy_ip_header = create_string_buffer(20)
            #version_plus_hlen = 69, tos, total_len, iden_plus_frag, ttl, prot, ip_checksum, source, destination 
            #FLAG might need < here
            struct.pack_into('!BBHLBBHLL', dummy_ip_header, 0, 69, 0, 28 + dns_header_len, 0, 64, 17, 0, struct.unpack('!L', pkt[16:20])[0], struct.unpack('!L', pkt[12:16])[0])
            ip_checksum = self.gen_checksum(dummy_ip_header.raw)
            ip_header = create_string_buffer(20)
            struct.pack_into('!BBHLBBHLL', ip_header, 0, 69, 0, 28 + dns_header_len, 0, 64, 17, ip_checksum, struct.unpack('!L', pkt[16:20])[0], struct.unpack('!L', pkt[12:16])[0])

            #udp header
            source_port = transport_header[2:4]
            dest_port = transport_header[0:2]
            udp_len = struct.pack('!H', 8 + dns_header_len)
            udp_checksum = struct.pack('!H', 0)

            # udp_pseudo_header = pkt[16:20] + pkt[12:16] + struct.pack('!B', 0) + struct.pack('!B', 17) + struct.pack('!H', 8 + dns_header_len)
            # udp_dummy_header = udp_pseudo_header + source_port + dest_port + udp_len + udp_checksum
            # udp_checksum = self.gen_checksum(udp_dummy_header)

            udp_header = source_port + dest_port + udp_len + udp_checksum

            dns_response_pkt = ip_header.raw + udp_header + dns_header

            self.iface_int.send_ip_packet(dns_response_pkt)
            return
        #check for http matches
        elif protocol == Firewall.TCP and external_port == 80:
            self.handle_http(pkt, external_ip, pkt_dir)

    # assemble responses / requests.
    def handle_http(self, pkt, external_ip, pkt_dir):
        header_len = (ord(pkt[0:1]) & 0x0f) * 4
        transport_header = pkt[header_len:]
        transport_len = 20
        payload = pkt[header_len + transport_len:]
        dest_port = struct.unpack('!H', transport_header[0:2])[0]
        if pkt_dir == PKT_DIR_INCOMING:
            dest_port = struct.unpack('!H', transport_header[2:4])[0]
        if  (external_ip, dest_port) not in self.http_connections:
            initial_seq_num = struct.unpack('!L', transport_header[4:8])[0]
            self.http_connections[(external_ip, dest_port)] = ["", initial_seq_num + 1, "", None]
        elif self.is_syn(transport_header) and self.is_ack(transport_header):
            self.http_connections[(external_ip, dest_port)][3] = struct.unpack('!L', transport_header[4:8])[0] + 1
        #tear down connection on fin ack
        # elif self.is_fin(transport_header) and self.is_ack(transport_header):
        #     del self.http_connections[(external_ip, dest_port)]
        
        # map {(external IP, internal port) : ["request", request_seqno, "response", response_seqno]}

        request = self.http_connections[(external_ip, dest_port)][0]
        response = self.http_connections[(external_ip, dest_port)][2]
        # assemble entire request + response
        if "\r\n\r\n" not in request or "\r\n\r\n" not in response:
            if pkt_dir == PKT_DIR_OUTGOING : #request
                stream = 0
                curr_seqno = 1
            else: #response
                stream = 2
                curr_seqno = 3
            packet_seq = struct.unpack('!L', transport_header[4:8])[0]
            if packet_seq > self.http_connections[(external_ip, dest_port)][curr_seqno]:
                return
            elif packet_seq  == self.http_connections[(external_ip, dest_port)][curr_seqno]:
                self.http_connections[(external_ip, dest_port)][stream] += payload # add http payload to request / response
                self.http_connections[(external_ip, dest_port)][curr_seqno] += len(payload) # increment sequence num
            #send packet through
            if pkt_dir == PKT_DIR_INCOMING:
                self.iface_int.send_ip_packet(pkt)
            elif pkt_dir == PKT_DIR_OUTGOING:
                self.iface_ext.send_ip_packet(pkt)
            #check if response is done
            if "\r\n\r\n" in self.http_connections[(external_ip, dest_port)][2]:
                self.log_http(external_ip, dest_port)

    def is_syn(self, transport_header):
        flags = struct.unpack('!B', transport_header[13:14])[0]
        #00000010
        return flags & 0x2 > 0

    def is_ack(self, transport_header):
        flags = struct.unpack('!B', transport_header[13:14])[0]
        #00010000
        return flags & 0x10 > 0

    def is_fin(self, transport_header):
        flags = struct.unpack('!B', transport_header[13:14])[0]
        return flags & 0x1 > 0


    # 3) Log HTTP        
    def log_http(self, external_ip, dest_port):    
        # now, extract relevant data
        request = self.http_connections[(external_ip, dest_port)][0]
        response = self.http_connections[(external_ip, dest_port)][2]
        request_lines = request.split('\r\n')
        response_lines = response.split('\r\n')

        contains_host = False
        for line in range(0, len(request_lines)):
            if len(request_lines[line].split()) < 2:
                continue
            if request_lines[line].split()[0].lower() == "host:":
                host_name = request_lines[line].split()[1].lower()
                contains_host = True
        if not contains_host:
            host_name = external_ip
        
        #check if log rule matched
        curr_match = None
        for rule in self.rules:
            if rule[0].lower() == 'log' and self.domain_matches(host_name, rule[2].lower()):
                curr_match = rule
        if not curr_match:
            return

        method = request.split()[0]
        path = request.split()[1]
        version = request.split()[2]
        status_code = response.split()[1]
        
        contains_CL = False
        for line in range(0, len(response_lines)):
            if len(response_lines[line].split()) < 2:
                continue
            if response_lines[line].split()[0].lower() == "content-length:":
                object_size = response_lines[line].split()[1]
                contains_CL = True
        if not contains_CL:
            object_size = "-1"

        bytestream = host_name + " " + method + " " + path + " " + version + " " + status_code + " " + object_size + "\n"
        #FLAG should i add a '\n', or will ".write()" do it for me?
        # write to log
        f = open('http.log', 'a')
        f.write(bytestream) # fix syntax
        f.flush()
        self.http_connections[(external_ip, dest_port)][0] = ''
        self.http_connections[(external_ip, dest_port)][2] = ''
        return

    # TODO: You can add more methods as you want.
    def gen_checksum(self, header):
        summ = 0
        for i in range(0,len(header) / 2):
            summ += struct.unpack('!H', header[0:2])[0]
            header = header[2:]
        summ_to_binstring = bin(summ).replace('0b', '')
        if len(summ_to_binstring) > 16:
            diff = len(summ_to_binstring) - 16
            partial_sum = summ_to_binstring[diff:] #get main 16bits
            carry = summ_to_binstring[0: diff]
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
            if len(domain) < len(rule_domain[1:]):
                return false
            for i in range(1, len(rule_domain)):
                if rule_domain[-i] != domain[-i]:
                    return False
            return True
        else:
            return domain == rule_domain

    @staticmethod
    def get_domain_name(qname):
        bytes_read = ''
        bytes_read += qname[0:1]
        length_byte = struct.unpack('!B', qname[0:1])[0]
        curr_byte = 1
        domain_str = ''
        while length_byte != 0:
            for i in range(0, length_byte):
                bytes_read += qname[curr_byte: (curr_byte + 1)]
                domain_str += chr(struct.unpack('!B', qname[curr_byte:(curr_byte + 1)])[0])
                curr_byte += 1
            domain_str += '.'
            bytes_read += qname[curr_byte: (curr_byte + 1)]
            length_byte = struct.unpack('!B', qname[curr_byte:(curr_byte + 1)])[0]
            curr_byte += 1
        domain_str = domain_str[0:-1] #get rid of extra '.' at end
        return domain_str, struct.unpack('!H', qname[curr_byte: curr_byte + 2])[0], bytes_read

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
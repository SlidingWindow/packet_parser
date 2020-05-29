#!/usr/bin/env python3

import scapy.all as scapy
from scapy.layers import http
import re, json,random,os,sys
import scapy.packet as packet

scapy.load_layer("http")

#Global variables here
PCAP_FILE = os.getcwd() + "/test.pcapng"

def dump_to_json(parsed_dict, part_name):
    out_file = PCAP_FILE.split("/")
    out_file = out_file[-1]

    out_file = out_file + '_' + part_name +  ".json" 
    with open(out_file, 'w') as f:
        f.write(json.dumps(parsed_dict, indent=2))


def create_host_dir(dr,rand_num):
    if os.path.exists(dr):
        dr = f"{dr}_{rand_num}"
        os.mkdir(dr)
        
    else:
        os.mkdir(dr)

    return dr
    

def read_pcap(file):
    pkts_list = scapy.rdpcap(file)
    sessions = pkts_list.sessions()
    return pkts_list, sessions

def parse_http_response(sessions):
    http_data = {}
    host_counter = 0

    for session,pkt in sessions.items():        
        for packet in sessions[session]:
            response_headers = []

            if packet.haslayer(http.HTTPResponse):
                http_layer = packet.getlayer(http.HTTPResponse)     #Raw response
                headers = str(http_layer).split("\\r\\n\\r\\n")
                hdrs = headers[0]
                post_body = http_layer.payload
                
                http_data[f"Host{host_counter}"] =  {}
                http_data[f"Host{host_counter}"]["Http_Version"] = str(http_layer.Http_Version)
                http_data[f"Host{host_counter}"]["Status_Code"] = str(http_layer.Status_Code)
                temp = hdrs.split("\\r\\n")
                
                for i in range(1, len(temp)):
                    #Example: 'Content-Encoding: gzip' . Split it to get a list which contains ['Content-Encoding', 'gzip']
                    hdr = temp[i].split(": ")
                    http_data[f"Host{host_counter}"][hdr[0]] = str(hdr[1])
                
                http_data[f"Host{host_counter}"]["POST_Body"] = str(post_body)
                http_data[f"Host{host_counter}"]["Raw Request"] = str(http_layer)
                
                #Extract images from POST Body and write to them to disk              
                if ('Content-Type' or 'content-type' or 'Content-type' or 'content-Type')  in http_data[f"Host{host_counter}"]:                    
                    if re.search('[iI]mage\/', str(http_data[f"Host{host_counter}"].values())):
                        print(f"[+]Writing image to the disk...")                        

                        rand_num = str(random.randrange(1000000, 9999999999999))
                        
                        h = f"Host_{host_counter}"
                        dr = create_host_dir(h,rand_num)
                        filename = f"{dr}/{rand_num}"
                        
                        with open(filename, 'wb') as f:
                                #Convert scapy.packet.raw object to bytes object and write to a binary file       
                                f.write(bytes(post_body)) 

                    else:
                        pass #other content types

                else:
                    #print(f"[-]Key not found or Content-Type is not Image: ")
                    pass

                host_counter+= 1

    return http_data


def parse_http_reqs(sessions):
    http_data = {}
    host_counter = 0

    for session,pkt in sessions.items():        
        for packet in sessions[session]:
            if packet.haslayer(http.HTTPRequest):
                http_layer = packet.getlayer(http.HTTPRequest)
                raw_req = str(http_layer)
                headers = str(http_layer).split("\\r\\n")
                #Remove last two garbage elements from headers list
                headers.pop(-1) # Remove "'"  caused by str(packet[TCP].payload).split("\\r\\n")
                headers.pop(-1) # Remove '' caused by str(packet[TCP].payload).split("\\r\\n")           

                #Store all HTTP headers, Raw request etc for this host in a dict 'http_data'
                http_data[f"Host{host_counter}"] =  {}
                http_data[f"Host{host_counter}"]["Method"] = str(http_layer.Method)
                http_data[f"Host{host_counter}"]["Path"] = str(http_layer.Path)
                http_data[f"Host{host_counter}"]["HTTP_Version"] = str(packet[TCP].Http_Version)   #Not sure as to why http_layer.HTTP_Version does not work
                http_data[f"Host{host_counter}"]["Host"] = str(http_layer.Host)

                #Start from Index 2 because we already captured a few headers above.
                for i in range(2, len(headers)):
                    hdr = headers[i].split(": ") 
                    http_data[f"Host{host_counter}"][hdr[0]] = hdr[1]

                http_data[f"Host{host_counter}"]["Raw_Request"] =  raw_req
                host_counter += 1    

    return http_data


def main():
    print(f"[+]Reading PCAP File: {PCAP_FILE}")
    pkts_list, sessions  = read_pcap(PCAP_FILE)

    print(f"[+]Trying to parse HTTP Requests...")
    http_reqs  = parse_http_reqs(sessions)
    
    print(f"[+]Trying to parse HTTP Responses...")
    http_resp = parse_http_response(sessions)
    
    print(f"[+]Writing HTTP Requests to JSON file...")
    dump_to_json(http_reqs, 'http_req')

    print(f"[+]Writing HTTP Responses to JSON file...") #This will overwrite existing HTTP Req file.. need to dump these two files in a dir, with diff name
    dump_to_json(http_resp, 'http_response')

if __name__ == "__main__":
    main()

"""
pcap_analyser.py
Written by Adam Gatherer
Nov/Dec 2021

To run this script, use it at the command line with a pcap file as an argument.
If no pcap file argument is given (or an invalid filename used), the script
will search the current working directory for a pcap file and use the first one
it finds. No argument given and no file found? It just won't run in that case!

Script is incomplete and does not perform all required functions. To be added
in the future: traffic over time analysis and graph production, better
exception handling, maybe reduce size of main(), add option to output data to
files instead of displaying on screen etc.
"""

import re
import os
import sys
import socket
import ipaddress
from datetime import datetime
import dpkt
import simplekml
import geoip2.database
from prettytable import PrettyTable


def img_hunter(layer5):
    """
    Takes in layer 5 packet data, scans for requests, if found extracts image
    URIs and returns them.
    """
    try:
        http_request = dpkt.http.Request(layer5)
        req = http_request.uri
        return re.search('^.*(\.gif|\.jpg|\.png)$', req).group()
    except Exception:
        None


def mail_hunter(layer5, mail_dict):
    """
    Checks input for presence of @, if found searches for e-mail addresses
    in the to/from fields. If none found, does nothing. If no layer5 data, does
    nothing, returns nothing. If addresses found, returns the to_from tuple and
    the mail_dict.
    """
    try:
        data = dpkt.http.Message(layer5)
        if re.search("@", repr(data)):
            #
            # Extracts the to/from fields as a string
            #
            address_line = (re.findall("\('from.*>'\)", repr(data)))
            #
            # Splits the whole line and extracts the list item corresponding
            # to the to/from e-mail addresses
            #
            from_address = ((address_line[0].split())[3])
            to_address = ((address_line[0].split())[5])
            #
            # The splits contain unwanted characters, this extracts them based
            # on the use of <> and converts the list item to a string and cuts
            # off the first and last characters to give a string that is just
            # the e-mail address.
            #
            to_address = (((re.findall("<.*>", to_address))[0])[1:-1])
            from_address = (((re.findall("<.*>", from_address))[0])[1:-1])
            to_from = (to_address, from_address)
            if to_address not in mail_dict["to"]:
                mail_dict["to"].append(to_address)
            if from_address not in mail_dict["from"]:
                mail_dict["from"].append(from_address)
            return (to_from, mail_dict)
    except Exception:
        None


def arg_checker(filename):
    """
    Checks if the file given in the argument is valid, returns first found
    pcap file in directory if invalid filename given.
    """
    if filename in os.listdir():
        print(f'Found {filename}, loading...')
        return filename
    else:
        print(f'File "{filename}" not found, searching cwd for .pcap...')
        for i in os.listdir():
            if re.search("^.*\.pcap$", i):
                print(f'Found "{i}", loading...')
                return i
                break


def geolocater(dst_ip):
    """
    Takes in the current destination IP, returns a dictionary of geoip2 data.
    If it can't find the databse, or something goes horribly wrong, it does
    nothing and returns nothing.'
    """
    try:
        reader = geoip2.database.Reader("Geo.mmdb")
        rec = reader.city(dst_ip)
        try:
            city = rec.city.names["en"]
        except KeyError:
            city = "Not found"
        try:
            country = rec.country.names["en"]
        except KeyError:
            country = "Not found"
        try:
            lat = rec.location.latitude
        except KeyError:
            lat = "n/a"
        try:
            long = rec.location.longitude
        except KeyError:
            long = "n/a"
        geo_dict = {"city": city, "country": country, "lat": lat,
                        "long": long, "count": 1}
        return geo_dict
    except Exception:
        print(Exception, file=sys.stderr)


def kml_kreator(kml_dict, file):
    """
    Takes in a dictionary created by geolocater() and the 'file' variable
    (name of pcap). Processes to a KML format, saves as a file in the cwd.
    """
    kml = simplekml.Kml()
    for ip_addr, data in kml_dict.items():
        kml.newpoint(name=ip_addr,
                     coords=[(data["long"], data["lat"])],
                     description=f'{data["count"]} packets for {data["city"]}'
                     )
    print(f'[*] Saving {file}.kml to {os.getcwd()}...')
    kml.save(f'{file}.kml')


def show_argv():
    """
    Returns system arguments.
    """
    return sys.argv


def main():
    """
    Main body of script.
    """
    img_list = []
    mail_list = []
    mail_dict = {"to": [], "from": []}
    protocol_dict = {}
    ip_dict = {}
    kml_dict = {}
    args = show_argv()
    try:
        filename = args[1]
    except IndexError:
        filename = None
    file = arg_checker(filename)
    packetlist = []
    #
    # Attempts to read pcap file and saves as tuple for later use
    #
    try:
        print(f'Reading pcap file {file}...')
        with open(file, 'rb') as f:
            pcap = dpkt.pcap.Reader(f)
            for t_s, buf in pcap:
                packetlist.append((t_s, buf))
    except Exception as err:
        print(f'Error type{type(err)}:{err}', file=sys.stderr)
        print(f'No valid filename given, no valid pcap files found in"{os.getcwd()}/"!')
        sys.exit(0)
    #
    # Main loop for analysing packets
    #
    for t_s, buf in packetlist:
        layer3 = (dpkt.ethernet.Ethernet(buf)).data
        layer4 = layer3.data
        layer5 = layer4.data
        pkt_length = len(layer3)
        protocol = (str(type(layer4))[8:-2])
        protocol = (protocol.split("."))[2]
        if protocol in protocol_dict:
            protocol_dict[protocol]["count"] += 1
            if t_s <= protocol_dict[protocol]["first_ts"]:
                protocol_dict[protocol]["first_ts"] = t_s
            if t_s >= protocol_dict[protocol]["last_ts"]:
                protocol_dict[protocol]["last_ts"] = t_s
            protocol_dict[protocol]["length"] += pkt_length
        else:
            protocol_dict[protocol] = {"count": 0, "first_ts": 0,
                                       "last_ts": 0, "length": 0}
            protocol_dict[protocol]["count"] += 1
            protocol_dict[protocol]["first_ts"] = t_s
            protocol_dict[protocol]["last_ts"] = t_s
            protocol_dict[protocol]["length"] = pkt_length
        if img_hunter(layer5):
            img_list.append(img_hunter(layer5))
        if mail_hunter(layer5, mail_dict):
            mail_hunter(layer5, mail_list)
        try:
            src_ip = socket.inet_ntoa(layer3.src)
            dst_ip = socket.inet_ntoa(layer3.dst)
            if (src_ip, dst_ip) not in ip_dict:
                ip_dict[(src_ip, dst_ip)] = 1
            else:
                ip_dict[(src_ip, dst_ip)] += 1
        except Exception:
            print("Error")
        try:
            if not (ipaddress.ip_address(dst_ip).is_multicast or ipaddress.ip_address(dst_ip).is_private):
                if dst_ip not in kml_dict:
                    kml_dict[dst_ip] = geolocater(dst_ip)
                else:
                    kml_dict[dst_ip]["count"] += 1
        except Exception as err:
            print(f'Problem with packet {buf}', file=sys.stderr)
            print(f'Error type {type(err)}: {err}', file=sys.stderr)
    #
    # Table for to/from IP pairs
    #
    print("\n[*] Building IP to/from table...")
    ip_pair_tbl = PrettyTable()
    ip_pair_tbl.field_names = ["Source", "Dest.", "Count"]
    ip_pair_tbl.align = "l"
    ip_dict = dict(sorted(ip_dict.items(), key=lambda item: item[1],
                          reverse=True))
    for key, val in ip_dict.items():
        ip_pair_tbl.add_row([key[0], key[1], val])
    print(ip_pair_tbl)
    #
    # Table for packet analysis
    #
    print("\n[*] Building packet analysis table...")
    for key in protocol_dict.values():
        avg = (key["length"]) // (key["count"])
        key["length"] = avg
    pkt_table = PrettyTable()
    pkt_table.field_names = ["Type", "No. packets", "First", "Last",
                             "Mean Length"]
    pkt_table.align = "l"
    for key in protocol_dict.items():
        tb_proto = key[0]
        tb_count = key[1]["count"]
        tb_first = key[1]["first_ts"]
        tb_last = key[1]["last_ts"]
        tb_mean = key[1]["length"]
        #
        # Change the timestamp to a nice human-readable timestamp
        #
        tb_first = (datetime.utcfromtimestamp(tb_first).strftime('%D %H:%M:%S'))
        tb_last = (datetime.utcfromtimestamp(tb_last).strftime('%D %H:%M:%S'))
        pkt_table.add_row([tb_proto, tb_count, tb_first, tb_last, tb_mean])
    print(pkt_table)
    #
    # Pretty table for the filenames and URIs
    #
    print("\n[*] Building URI table...")
    uri_table = PrettyTable()
    uri_table.field_names = ["Filename", "Full URI"]
    uri_table.align = "l"
    for i in img_list:
        filename = ((i.split("/"))[-1])
        uri_table.add_row([filename, i])
    print(uri_table)
    #
    # E-mail pairs
    #
    print("\n[*] Building e-mail pair table...")
    print("To:")
    for i in mail_dict["to"]:
        print(i)
    print("From:")
    for i in mail_dict["from"]:
        print(i)
    #
    # Pretty table for IP address analysis
    #
    print("\n[*] Building IP address analysis table...")
    ip_table = PrettyTable()
    ip_table.field_names = ["Source", "Destination", "Count"]
    ip_table.align = "l"
    for key in ip_dict.items():
        ip_table.add_row([key[0][0], key[0][1], key[1]])
    print(ip_table)
    #
    # KML Kreator function to create KML file (and save!)
    #
    print("\n[*] Building KML file...")
    kml_kreator(kml_dict, file)


if __name__ == "__main__":
    main()

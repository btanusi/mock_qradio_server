import socket
import sys
import struct

import json
import datetime
import unittest
from bitstring import BitArray

# Create a TCP/IP socket
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Bind the socket to the port
server_address = ('localhost', 10000)
print('starting up on {} port {}'.format(*server_address))
sock.bind(server_address)

# Listen for incoming connections
sock.listen(1)

while True:
    # Wait for a connection
    print('waiting for a connection')
    connection, client_address = sock.accept()
    try:
        print('connection from', client_address)

        # Receive the data in small chunks and retransmit it
        while True:
            data = connection.recv(32)
            print('received {!r}'.format(data))

            if not data:
                print('no data from', client_address)
                break
            else:
                print('sending data back to the client')
                #string = '\x52\x54\x4C\x20\x00\x00\x00\x1c\x00\x00\x00\x07\x00\x00\x00\xde\xad\xbe\xef\x08\xb0\xc0\x00\x00\x01\x00\x00'
                #otherstring = '52544C200000001c00000007000000deadbeef08b0c00000010000'
                #string = '0805c0120025000f46740054000033e0ffff002000000434004f600000'
                #string = 'deadbeef0805c0120025000f46740054000033e0ffff002000000434004f600000'
                #this_string_works = '0805C0120025000F46740054000033E0FFFF002000000434004F600000DEADBEEF0805C0120025000F467400'
                #this_string_also_works_one_byte = '0805C0120025000F46740054000033E0FFFF002000000434004F600000DEADBEEF0805C0120001000F467400'
                #this_string_does_not_work = '0805C0120025000F46740054000033E0FFFF002000000434004F600000DEADBEEF0805C0120025000F467400'
                #this_string_has_one_too_little_bytes = '0805C0120025000F46740054000033E0FFFF002000000434004F600000DEADBEEF0805C0120024000F467400'
                this_string_is_the_one = 'DEADBEEF0805c0120025000f46740054000033e0ffff002000000434004f6000000f4240000000000000000000000000DEADBEEF'
                #testing = '52 53 43 3A 01 00 52 54 4C 20 00 00 00 1C 00 0000 01 00 00 00 60 DE AD BE EF 18 06 C0 00 00 010C 2C 52 54 4C 20 00 00 00 1E 00 00 00 02 00 0000 70 DE AD BE EF 19 DF C0 00 00 03 08 F3 00 0152 54 4C 20 00 00 00 1E 00 00 00 06 00 00 00 70DE AD BE EF 19 DF C0 00 00 03 08 F3 00 01 52 544C 20 00 00 00 1C 00 00 00 07 00 00 00 60 DE ADBE EF 18 B3 C0 00 00 01 00 95 52 54 4C 20 00 0000 1C 00 00 00 07 00 00 00 DE AD BE EF 08 B0 C000 00 01 00 00 52 54 4C 20 00 00 00 1C 00 00 00 07 00 00 00 DE AD BE EF 08 B0 C0 00 00 01 00 0008 05 C0 12 00 25 00 0F 46 74 00 54 00 00 33 E0FF FF 00 20 00 00 04 34 00 4F 60 00 00 08 05 C012 00 25 00 0F 46 74 00 54 00 00 33 E0 FF FF 0020 00 00 04 34 00 4F 60 00 00 DE AD BE EF 08 05C0 12 00 25 00 0F 46 74 00 54 00 00 33 E0 FF FF00 20 00 00 04 34 00'

                data = bytes.fromhex(this_string_is_the_one)

                #new_data = struct.pack(hex(this_string_is_the_one))


                connection.sendall(data)
            #if data:
            #    print('sending data back to the client')
            #    connection.sendall(data)
            #else:
            #    print('no data from', client_address)
            #    break

    finally:
        # Clean up the connection
        connection.close()


def _binary_from_target(target, mnemonic, mapping, **kwargs):
    """
    Return a binary packet defined in mapping[target]['mnemonics'][mnemonic]
    With values filled in from kwargs
    """
    # Look up definition for this target and mnemonic
    packet_def = mapping[target]['mnemonics'][mnemonic]
    values = []
    struct_def = '>'
    for field_name, field in packet_def['fields'].items():
        num_bytes = int(field['size']) // 8
        # Add a struct definition for packet based on bit size and signed/unsigned
        # 24-bit integers get packed into 3-byte strings
        field_defs = {'8':  {'UINT': 'B', 'INT': 'b'}, \
                      '16': {'UINT': 'H', 'INT': 'h'}, \
                      '24': {'UINT': '3s', 'INT': '3s'}, \
                      '32': {'UINT': 'I', 'INT': 'i'}}
        if field['type'] in ['INT', 'UINT']:
            struct_def += field_defs[field['size']][field['type']]
        elif field['type'] == 'FLOAT':
            struct_def += 'f'
        elif field['type'] in ['STRING', 'BLOCK']:
            struct_def += "%ds" % num_bytes

        # Append a value for this field: either a passed in value, default value, or zero
        value = None  # value to append
        if field_name in kwargs:
            value = kwargs[field_name]
        elif 'value' in field:
            if field['type'] in ['INT', 'UINT']:
                value = int(field['value'])
            elif field['type'] == 'FLOAT':
                value = float(field['value'])
            else:
                value = field['value'].encode('utf-8')
        else:
            if field['type'] in ['STRING', 'BLOCK']:
                value = b"\x00" * num_bytes
            else:
                value = 0
        # Look out for 24-bit integers and pack them into strings first
        if field['size'] == '24' and field['type'] == 'UINT':
            value = BitArray(uint=value, length=24).bytes
        elif field['size'] == '24' and field['type'] == 'INT':
            value = BitArray(int=value, length=24).bytes
        values.append(value)
    return struct.pack(struct_def, *values)

def telemetry(self, target, packet, **kwargs):
    """
    Create a new telemetry packet given a target and packet name
    The rest of the parameters are variable depending on the packet definition
    Where possible, this function will fill in default values (although these are usually
    not defined for telemetry packets)
    Fills in 0 for anything not defined and with no default value
    Returns a byte string
    """
    return _binary_from_target(target, packet, self.tlm_map, **kwargs)

def test_hk_tlm_pkt(self):
    cmd = self.tsim.telemetry('CFE_TIME', 'HK_TLM_PKT', CCSDS_STREAMID=2053, \
                            CCSDS_SEQUENCE=49170, CCSDS_LENGTH=37, CCSDS_SECONDS=1001076, \
                            CCSDS_SUBSECS=84, CLOCK_STATE_FLAGS=13280, CLOCK_STATE_API=-1, \
                            LEAP_SECONDS=32, MET_SECONDS=1076, MET_SUBSECS=5201920, \
                            STCF_SECONDS=1000000)
    return cmd
    #self.assertEqual(cmd.hex(), '0805c0120025000f46740054000033e0ffff002000000434004f600000' '0f4240000000000000000000000000')

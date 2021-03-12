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
server_address = ('localhost', 10000) #line 13 of cmd_tlm_server.txt : INTERFACE LOCAL_CFS_INT tcpip_client_interface.rb localhost 10000 10000 nil nil
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
            """
            if not data:
                print('no data from', client_address)
                break
            else:
                print('sending a tlm packet back to the client')

                #Connect LOCAL_CFS_INT: 
                CFE_TIME__HK_TLM_PKT = 'DEADBEEF0805c0120025000f46740054000033e0ffff002000000434004f6000000f4240000000000000000000000000'
                CFE_ES__SHELL_TLM_PKT = 'DEADBEEF080FC0120008000F4674005401'

                #Connect CMD_ACK_INT:
                QRADIO__ACK = '52544C220000000100000001000000010000000100000001'
                
                tlm_data_hex = 'DEADBEEF080FC0120008000F4674005401'
                tlm_data_bytes = bytes.fromhex(tlm_data_hex)
                connection.sendall(tlm_data_bytes)
            """

    finally:
        # Clean up the connection
        connection.close()

"""
# a function from HaS/decoders/team_simulator/team_simulator.py with data on CFE_TIME HK_TLM_PKT
def test_hk_tlm_pkt(self):
    cmd = self.tsim.telemetry('CFE_TIME', 'HK_TLM_PKT', CCSDS_STREAMID=2053, \
                            CCSDS_SEQUENCE=49170, CCSDS_LENGTH=37, CCSDS_SECONDS=1001076, \
                            CCSDS_SUBSECS=84, CLOCK_STATE_FLAGS=13280, CLOCK_STATE_API=-1, \
                            LEAP_SECONDS=32, MET_SECONDS=1076, MET_SUBSECS=5201920, \
                            STCF_SECONDS=1000000)
    return cmd
    self.assertEqual(cmd.hex(), '0805c0120025000f46740054000033e0ffff002000000434004f600000' '0f4240000000000000000000000000')
"""

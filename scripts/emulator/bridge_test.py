import requests
import json
import binascii
import os

url = 'http://{}/exchange/device'.format(os.getenv('KK_BRIDGE', '127.0.0.1:5000'))

def test_single_packet_write_read():
    # send ping with short message
    msg = [63, 35, 35, 0, 1, 0, 0, 0, 13, 10, 5, 104, 101, 108, 108, 111, 16, 0, 24, 1, 32, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]

    hex = ''.join(format(x, '02x') for x in msg)
    data = json.dumps({'data':hex}, indent=4)
    headers = {'content-type': 'application/json'}

    resp = requests.post(url=url, data=data, headers=headers)

    # receive ping response
    resp = requests.get(url=url)
    assert(resp.json()['data'] == u'3f23230002000000070a0568656c6c6f000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000')


def test_multiple_packet_write_read():
    # send ping with message that doesn't fit in a single packet
    testPackets = [[63, 35, 35, 0, 1, 0, 0, 0, 114, 10, 106, 104, 101, 108, 108, 111, 111, 116, 117, 104, 111, 117, 117, 117, 117, 117, 117, 117, 117, 117, 117, 117, 117, 117, 117, 117, 117, 117, 117, 117, 117, 117, 117, 117, 117, 117, 117, 117, 117, 117, 117, 117, 117, 117, 117, 117, 117, 117, 117, 117, 117, 117, 117, 117],
	[63, 117, 117, 117, 117, 117, 117, 117, 117, 117, 117, 117, 110, 116, 104, 110, 116, 104, 110, 116, 104, 110, 116, 104, 116, 104, 110, 110, 116, 104, 110, 104, 116, 110, 104, 116, 110, 104, 116, 110, 104, 116, 104, 110, 116, 104, 110, 116, 104, 110, 116, 104, 110, 116, 16, 0, 24, 1, 32, 0, 0, 0, 0, 0]]

    # send both packets of request
    for packet in testPackets:
        hex = ''.join(format(x, '02x') for x in packet)
        data = json.dumps({'data':hex}, indent=4)
        headers = {'content-type': 'application/json'}

        resp = requests.post(url=url, data=data, headers=headers)


    # receive 2 packets
    results = [requests.get(url=url) for i in range(0,2)]

    assert(results[0].json()['data'] == u'3f232300020000006c0a6a68656c6c6f6f7475686f75757575757575757575757575757575757575757575757575757575757575757575757575757575757575')
    assert(results[1].json()['data'] == u'3f75757575757575757575756e74686e74686e74686e746874686e6e74686e68746e68746e68746e6874686e74686e74686e74686e7400000000000000000000')

test_single_packet_write_read()
test_multiple_packet_write_read()

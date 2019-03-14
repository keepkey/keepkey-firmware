import requests
import json
import binascii
import os

url = 'http://{}/exchange/device'.format(os.getenv("KK_BRIDGE", '127.0.0.1:5000'))
print("KK_BRIDGE", os.getenv("KK_BRIDGE"))

def test_single_packet_write_read():
    # send ping
    msg = [63, 35, 35, 0, 1, 0, 0, 0, 13, 10, 5, 104, 101, 108, 108, 111, 16, 0, 24, 1, 32, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]

    print(len(msg))

    hex = ''.join(format(x, '02x') for x in msg)
    data = json.dumps({'data':hex}, indent=4)
    headers = {'content-type': 'application/json'}

    resp = requests.post(url=url, data=data, headers=headers)
    print(resp)

    # receive ping response
    resp = requests.get(url=url)
    print(resp.json())
    assert(resp.json()['data'] == u'3f23230002000000070a0568656c6c6f000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000')
    print('a')


# def test_multiple_packet_write_read():


test_single_packet_write_read()

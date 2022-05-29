
from flask import Flask, Response, request, jsonify
app = Flask(__name__)

import socket
import json
import binascii
# import sys


PACKET_SIZE = 64
MESSAGE_TYPES_WITHOUT_RESPONSE = [100, 103, 104, 105]

main = ('0.0.0.0', 11044)
debug = ('0.0.0.0', 11045)

ms = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
ms.connect(main)

ds = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
ds.connect(debug)

app = Flask(__name__)
@app.route('/raw/<string:kind>', methods=['POST'])
def raw(kind):
    kk = ds if kind == 'debug' else ms if kind == 'device' else None
    if kk is None:
        return Response('', status=404, mimetype='application/octet-stream')

    msg = request.get_data()

    # print("msg: " + str(binascii.b2a_hex(msg)), file=sys.stderr)

    if not (len(msg) >= 8 and msg[0] == 0x23 and msg[1] == 0x23):
        return Response('', status=400, mimetype='application/octet-stream')

    msgType = msg[2] << 8 | msg[3] << 0
    msgLength = msg[4] << 24 | msg[5] << 16 | msg[6] << 8 | msg[7] << 0

    if not len(msg) == msgLength + 8:
        return Response('', status=400, mimetype='application/octet-stream')

    # break frame into segments
    SEGMENT_SIZE = PACKET_SIZE - 1
    for segment in [msg[i:i + SEGMENT_SIZE] for i in range(0, len(msg), SEGMENT_SIZE)]:
        frame = bytes([0x3f]) + segment + bytes(([0] * (SEGMENT_SIZE - len(segment))))
        # print("frame: " + str(binascii.b2a_hex(frame)), file=sys.stderr)
        kk.send(frame)

    # return Response('{}', status=200, mimetype='application/json')

    if MESSAGE_TYPES_WITHOUT_RESPONSE.count(msgType) > 0:
        # print("no response expected")
        return Response('', status=200, mimetype='application/octet-stream')

    first = kk.recv(PACKET_SIZE)
    # print("first: " + str(binascii.b2a_hex(first)), file=sys.stderr)

    # Check that buffer starts with: "?##" [ 0x3f, 0x23, 0x23 ]
    # "?" = USB reportId, "##" = KeepKey magic bytes
    # Message ID is bytes 4-5. Message length starts at byte 6.
    if not (len(first) >= 9 and first[0] == 0x3f and first[1] == 0x23 and first[2] == 0x23):
        return Response('', status=500, mimetype='application/octet-stream')

    msgLength = first[5] << 24 | first[6] << 16 | first[7] << 8 | first[8] << 0
    data = first[1:]

    while len(data) < msgLength + 8:
        # Drop USB "?" reportId in the first byte
        next = kk.recv(PACKET_SIZE)
        # print("next: " + str(binascii.b2a_hex(next)), file=sys.stderr)
        if not next[0] == 0x3f:
            return Response('', status=500, mimetype='application/octet-stream')
        data = data + next[1:]
    
    data = data[:msgLength + 8]

    # print("data: " + str(binascii.b2a_hex(data)), file=sys.stderr)

    return Response(data, status=200, mimetype='application/octet-stream')

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0')

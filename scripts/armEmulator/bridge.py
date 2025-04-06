
from flask import Flask, Response, request, jsonify
app = Flask(__name__)

import socket
import json
import binascii


PACKET_SIZE = 64

main = ('0.0.0.0', 11044)
debug = ('0.0.0.0', 11045)

ms = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
ms.connect(main)

ds = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
ds.connect(debug)

app = Flask(__name__)

@app.route('/exchange/<string:kind>', methods=['GET', 'POST'])
def exchange(kind):

    kk = ds if kind == 'debug' else ms

    if request.method == 'POST':
        content = request.get_json(silent=True)
        msg = bytearray.fromhex(content["data"])
        kk.send(msg)
        return Response('{}', status=200, mimetype='application/json')

    if request.method == 'GET':
        data = kk.recv(PACKET_SIZE)
        body = '{"data":"' + binascii.hexlify(data).decode("utf-8") + '"}'
        return Response(body, status=200, mimetype='application/json')

    return Response('{}', status=404, mimetype='application/json')

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0')

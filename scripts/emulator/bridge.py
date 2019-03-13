
from flask import Flask, Response, request, jsonify
app = Flask(__name__)

import socket
import json
import binascii


PACKET_SIZE = 64

device = ('0.0.0.0', 21324)
debug = ('0.0.0.0', 21325)
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.connect(device)

app = Flask(__name__)

@app.route('/exchange/<string:kind>', methods=['GET', 'POST'])
def exchange(kind):

    kk = device
    if kind == 'debug':
        kk = debug

    if request.method == 'POST':

        content = request.get_json(silent=True)
        msg = bytearray.fromhex(content["data"])
        s.send(msg)

        return Response('{}', status=200, mimetype='application/json')

    if request.method == 'GET':
        data = s.recv(PACKET_SIZE)
        body = '{"data":"' + binascii.hexlify(data).decode("utf-8") + '"}'
        return Response(body, status=200, mimetype='application/json')

    return Response('{}', status=404, mimetype='application/json')

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0')

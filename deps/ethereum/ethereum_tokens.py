#!/bin/env python

from __future__ import print_function
import io
import json
import md5
import os.path
import sys

HERE = os.path.dirname(os.path.realpath(__file__))

def print_token(outf, network, token):
    chain_id = network['chain_id']
    address = token['address'][2:]
    address = '\\x' + '\\x'.join([address[i:i+2] for i in range(0, len(address), 2)])
    symbol = token['symbol']
    decimals = token['decimals']
    net_name = network['symbol'].lower()
    tok_name = token['name']

    line = '\t{%d, "%s", " %s", %d}, // %s / %s' % (chain_id, address, symbol, decimals, net_name, tok_name)
    print(line, file=outf)

def print_tokens(outf, network):
    net_name = network['symbol'].lower()
    filename = HERE + '/ethereum-lists/dist/tokens/%s/tokens-%s.json' % (net_name, net_name)

    if not os.path.isfile(filename):
        return

    with open(filename, 'r') as f:
        tokens = json.load(f)

        for token in tokens:
            print_token(outf, network, token)

def main():
    if len(sys.argv) != 2:
        print("Usage:\n\tpython %s ethereum_tokens.def" % (__file__,))
        sys.exit(-1)

    out_filename = sys.argv[1]
    outf = io.StringIO()

    with open(HERE + '/ethereum_networks.json', 'r') as f:
        networks = json.load(f)

        for network in networks:
            print_tokens(outf, network)

    if os.path.isfile(out_filename):
        with open(out_filename, 'r') as inf:
            in_digest = md5.new(inf.read()).digest()
            out_digest = md5.new(outf.getvalue().encode('utf-8')).digest()
            if in_digest == out_digest:
                print(out_filename + ": Already up to date")
                return

    print(out_filename + ": Updating")

    with open(out_filename, 'w') as f:
        print(outf.getvalue().encode('utf-8'), file=f, end='')

if __name__ == "__main__":
    main()

#!/usr/bin/python

import argparse
import os

"""
Build helper script to shortcut common build scenarions.
"""

from fabric.api import local


def proc_args():
    parser = argparse.ArgumentParser(description = 'Build helper front end tool.')
    parser.add_argument('-s', '--stm32', help = 'Build for the stm32 eval board.', action = 'store_true')
    parser.add_argument('-l', '--linux', help = 'Build the native linux x64 build', action = 'store_true')
    parser.add_argument('-d', '--debug', help = 'Build debug variant.', action = 'store_true')
    parser.add_argument('-v', '--verbose', help = 'Build with verbose output.', action = 'store_true')
    args = parser.parse_args()

    return args

def main():

    args = proc_args()

    buildargs = ''

    if args.debug:
        buildargs += ' debug=1'
    if args.verbose:
        buildargs += ' verbose=1'

    if args.stm32:
        target ='arm-none-gnu-eabi'
    else:
        target='x86_64-linux-gnu-none'

    local('scons ' + 'target='+target + buildargs)
    

if __name__ == '__main__':
    main()


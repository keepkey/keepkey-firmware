#!/usr/bin/python

import argparse
import os

"""
Build helper script to shortcut common build scenarions.
"""

from fabric.api import local


def proc_args():
    parser = argparse.ArgumentParser(description = 'Build helper front end tool.')
    parser.add_argument('-c',    '--console',    help = 'Build with serial debug console enabled', action = 'store_true')
    parser.add_argument('-s',    '--stm32',      help = 'Build for the stm32 eval board.', action = 'store_true')
    parser.add_argument('-l',    '--linux',      help = 'Build the native linux x64 build', action = 'store_true')
    parser.add_argument('-d',    '--debug',      help = 'Build debug variant.', action = 'store_true')
    parser.add_argument('-v',    '--verbose',    help = 'Build with verbose output.', action = 'store_true')
    parser.add_argument('-b','--bldtype',    help = 'Build type <options: bldr | app>', action = 'append')
    args = parser.parse_args()

    return args

def main():

    args = proc_args()

    buildargs = ''

    if args.console:
        buildargs += ' console=1'
    if args.debug:
        buildargs += ' debug=1'
    if args.verbose:
        buildargs += ' verbose=1'

    if args.bldtype:
        if args.bldtype[0] == 'bldr':
            print '******************************************'
            print '*       Building KeepKey Bootloader      *'
            print '******************************************'
            buildargs += ' bldtype=bldr'
        elif args.bldtype[0] == 'app':
            print '******************************************'
            print '*       Building KeepKey Application     *'
            print '******************************************'
            buildargs += ' bldtype=app'
    	else:
            # Invalid build type.  Abandon build!!!
            print '\n ... error : <-b ', args.bldtype[0], '> is not a valid build type option < bldr, app>\n'
            quit()
    else:
        # build type option missing.  
        print '\n ... error: Build type option <-b: bldr or app> missing in command line\n'
        quit()

    if args.stm32:
        target ='arm-none-gnu-eabi'
        local('scons ' + 'target='+target + buildargs)
        
    else:
        target='x86_64-linux-gnu-none'
        local('scons ' + 'target='+target + buildargs)
    

if __name__ == '__main__':
    main()


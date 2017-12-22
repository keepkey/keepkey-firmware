#!/usr/bin/python

import argparse
import os
import json

DEVICE_PROTOCOL = 'device-protocol'
FIRMWARE_BUILD_DIR = os.getcwd()

"""
Build helper script to shortcut common build scenarions.
"""

from fabric.api import local

def proc_args():
    parser = argparse.ArgumentParser(description = 'Build helper front end tool.')
    parser.add_argument('-i',  '--invert',     help = 'Build with inverted display.', action = 'store_true')
    parser.add_argument('-dl', '--debug-link',  help = 'Build with Debug Link.', action = 'store_true')
    parser.add_argument('-mp', '--memory-protect',  help = 'Build with memory protection', action = 'store_true')
    parser.add_argument('-p',  '--project', 
                        help = 'Build specific project (bootloader, bootstrap, crypto, interface, keepkey, keepkey_board, nanopb).', 
                        action = 'store')
    parser.add_argument('-b',  '--build-type', 
                        help = 'Build specifc build type (bstrap, bldr, app).', 
                        action = 'store')
    parser.add_argument('-bf',  '--bump-feature', help = 'Bump feature release version.', action = 'store_true')
    parser.add_argument('-bb',  '--bump-bug-fix', help = 'Bump bug fix version.', action = 'store_true')
    parser.add_argument('-bt',  '--bump-test', help = 'Bump test version.', action = 'store_true')
    parser.add_argument('-salt',  '--salt-logo', help = 'Build with the salt logo', action = 'store_true')
    parser.add_argument('-d',  '--debug', help = 'Build debug variant.', action = 'store_true')
    parser.add_argument('-v',  '--verbose', help = 'Build with verbose output.', action = 'store_true')
    args = parser.parse_args()

    return args

def bump_version(args):
    version = json.load(open('version.json', 'r'))

    if(args.bump_feature):
        version['MAJOR_VERSION'] += 1
        version['MINOR_VERSION'] = 0
        version['PATCH_VERSION'] = 0
    elif(args.bump_bug_fix):
        version['MINOR_VERSION'] += 1
        version['PATCH_VERSION'] = 0
    elif(args.bump_test):
        version['PATCH_VERSION'] += 1

    json.dump(version, open('version.json', 'w'))

def compile_protocol_buffers():
    version = json.load(open('version.json', 'r'))
    tag = 'v%s.%s.%s' % (version['MAJOR_VERSION'], version['MINOR_VERSION'], version['PATCH_VERSION'])

    if not os.path.exists('../%s' % DEVICE_PROTOCOL):
        local('git clone -b %s https://github.com/keepkey/%s.git ../%s' % (tag, DEVICE_PROTOCOL, DEVICE_PROTOCOL))

    if not os.path.exists('interface/local'):
        os.mkdir('interface/local')
    
    local('cp interface/public/*.options ../%s/.' % DEVICE_PROTOCOL)
    os.chdir('../%s' % DEVICE_PROTOCOL)
    local('protoc -I. -I/usr/include --plugin=nanopb=protoc-gen-nanopb --nanopb_out=. *.proto')
    os.chdir('/%s' % FIRMWARE_BUILD_DIR)
    local('mv ../%s/*.pb.c interface/local' % DEVICE_PROTOCOL)
    local('mv ../%s/*.pb.h interface/public' % DEVICE_PROTOCOL)

def main():

    args = proc_args()

    if(args.bump_feature or args.bump_bug_fix or args.bump_test):
        bump_version(args)
        return

    compile_protocol_buffers()

    buildargs = ''

    if args.invert:
        buildargs += ' invert=1'
    if args.debug_link:
        buildargs += ' debug_link=1'
    if args.memory_protect:
        buildargs += ' memory_protect=1'
    if args.build_type:
        build_aliases = {'bstrap': 'bootstrap', 'bldr': 'bootloader', 'app': 'keepkey'}
        buildargs += ' project=%s' % (build_aliases[args.build_type])
    else:
        if args.project:
            buildargs += ' project=%s' % (args.project)
    if args.debug:
        buildargs += ' debug=1'
    if args.verbose:
        buildargs += ' verbose=1'
    if args.salt_logo:
        buildargs += ' salt-logo=1'

    target ='arm-none-gnu-eabi'
    local('scons ' + 'target='+target + buildargs)

if __name__ == '__main__':
    main()

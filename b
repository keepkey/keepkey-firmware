#!/usr/bin/python

import argparse
import os

"""
Build helper script to shortcut common build scenarions.
"""

from fabric.api import local



def proc_app_version(ver_type, operator):
    app_major_version = 0
    app_minor_version = 0
    app_patch_version = 0
    line = "NULL"

    #open application version header file  
    f = open("keepkey/public/app_version.h", "rw+")
    while line !="":
        file_offset = f.tell()
        line = f.readline()
        lineImg = line

        if 'MAJOR_VERSION' in line:
            line_offset = len('#define MAJOR_VERSION ')
            app_major_version = int(line[line_offset: line_offset+3])
            if ver_type == 'MAJOR_VERSION':
                if operator == "+":
                    app_major_version += 1
                else:
                    app_major_version = 0 
                f.seek(file_offset + line_offset)
                f.write(str(app_major_version))

        if 'MINOR_VERSION' in line:
            line_offset = len('#define MINOR_VERSION ')
            app_minor_version = int(line[line_offset: line_offset+3])
            if ver_type == 'MINOR_VERSION':
                if operator == "+":
                    app_minor_version += 1
                else:
                    app_minor_version = 0
                f.seek(file_offset + line_offset)
                f.write(str(app_minor_version))

        if 'PATCH_VERSION' in line:
            line_offset = len('#define PATCH_VERSION ')
            app_patch_version = int(line[line_offset: line_offset+3])
            if ver_type == 'PATCH_VERSION':
                if operator == "+":
                    app_patch_version += 1
                else:
                    app_patch_version = 0
                f.seek(file_offset + line_offset)
                f.write(str(app_patch_version))
    f.close()
    version = str(app_major_version) + '.' + str(app_minor_version) + '.' + str(app_patch_version)
    return version

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
    parser.add_argument('-d',  '--debug', help = 'Build debug variant.', action = 'store_true')
    parser.add_argument('-rel_feature',  '--app_feature_release', help = 'Build release for feature update.  Increment major version.', action = 'store_true')
    parser.add_argument('-rel_bugfix',  '--app_debug_release', help = 'Build release for bug fixes.  Increment minor version', action = 'store_true')
    parser.add_argument('-rel_test',  '--app_test_release', help = 'Build release for testing.  Increment patch version', action = 'store_true')
    parser.add_argument('-v',  '--verbose', help = 'Build with verbose output.', action = 'store_true')
    args = parser.parse_args()

    return args

def main():

    args = proc_args()

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

    version = proc_app_version('NO VERSION UPDATE', '0')

    if args.build_type == 'app':
        if args.app_feature_release:
            # Increment major version on feature release
            version = proc_app_version('MAJOR_VERSION', '+')  
            # Reset minor & patch version on feature release
            version = proc_app_version('MINOR_VERSION', '0')  
            version = proc_app_version('PATCH_VERSION', '0')
        if args.app_debug_release:
            # Increment minor version on feature release
            version = proc_app_version('MINOR_VERSION', '+')
            # Reset patch verion on minor release
            version = proc_app_version('PATCH_VERSION', '0')
        if args.app_test_release:
            # Increment patch version on feature release
            version = proc_app_version('PATCH_VERSION', '+')

    if args.verbose:
        buildargs += ' verbose=1'

    target ='arm-none-gnu-eabi'
    local('scons ' + 'target='+target + buildargs)

    print "***********************************************"
    print "Application version # %s" % version
    print "***********************************************"

if __name__ == '__main__':
    main()

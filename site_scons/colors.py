import sys
import os


colors = {}
colors['cyan']   = '\033[96m'
colors['purple'] = '\033[95m'
colors['blue']   = '\033[34m'
colors['green']  = '\033[92m'
colors['yellow'] = '\033[93m'
colors['red']    = '\033[91m'
colors['end']    = '\033[0m'


def cstr(color, s):
    return '%s%s%s' % (colors[color], s, colors['end'])

def colorize(env):

#If the output is not a terminal, remove the colors
    if not sys.stdout.isatty():
       for key, value in colors.iteritems():
          colors[key] = ''

    compile_source_message = '%sCompiling %s ==> %s$SOURCE%s' % \
       (colors['cyan'], colors['purple'], colors['yellow'], colors['end'])

    compile_shared_source_message = '%sCompiling shared %s ==> %s$SOURCE%s' % \
       (colors['blue'], colors['purple'], colors['yellow'], colors['end'])

    link_program_message = '%sLinking %s ==> %s$TARGET%s' % \
       (colors['green'], colors['purple'], colors['yellow'], colors['end'])

    link_library_message = '%sLinking Static %s==> %s$TARGET%s' % \
       (colors['green'], colors['purple'], colors['yellow'], colors['end'])

    ranlib_library_message = '%sRanlib %s==> %s$TARGET%s' % \
       (colors['green'], colors['purple'], colors['yellow'], colors['end'])

    link_shared_library_message = '%sLinking Shared %s==> %s$TARGET%s' % \
       (colors['green'], colors['purple'], colors['yellow'], colors['end'])

    env['CXXCOMSTR']      = compile_source_message
    env['CCCOMSTR']       = compile_source_message
    env['SHCCCOMSTR']     = compile_shared_source_message
    env['SHCXXCOMSTR']    = compile_shared_source_message
    env['ARCOMSTR']       = link_library_message
    env['RANLIBCOMSTR']   = ranlib_library_message
    env['SHLINKCOMSTR']   = link_shared_library_message
    env['LINKCOMSTR']     = link_program_message


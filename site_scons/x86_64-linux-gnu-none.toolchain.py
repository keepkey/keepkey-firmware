from SCons.Script import *
from SCons.Builder import *

CROSS_COMPILE='x86_64-linux-gnu-'

def load_toolchain():
    env = DefaultEnvironment()

    env['CC'] = CROSS_COMPILE + 'gcc'
    env['CXX'] = CROSS_COMPILE + 'g++'
    env['AR'] = 'ar'
    env['OBJPREFIX']    = ''
    env['OBJSUFFIX']    = '.o'
    env['LIBPREFIX']    = 'lib'
    env['LIBSUFFIX']    = '.a'
    env['SHCCFLAGS']    = '$CCFLAGS'
    env['SHOBJPREFIX']  = '$OBJPREFIX'
    env['SHOBJSUFFIX']  = '$OBJSUFFIX'
    env['PROGPREFIX']   = ''
    env['PROGSUFFIX']   = '.elf'
    env['SHLIBPREFIX']  = 'lib'
    env['SHLIBSUFFIX']  = '.so'
    env['LINKFLAGS']    = []
    env['LIBPREFIXES']  = [ '$LIBPREFIX' ]
    env['LIBSUFFIXES']  = [ '$LIBSUFFIX' ]
    env['CFLAGS'] = ['-std=gnu99']
    env['CXXFLAGS'] = ['-std=gnu++11']
    env['CCFLAGS'] = ['-Wall', '-Wextra']
    env['OBJCOPY'] = 'objcopy'
    env['OBJDUMP'] = 'objdump'

    debug = ARGUMENTS.get('debug', 0)
    if int(debug):
        env.Append(CCFLAGS = ['-g'])

    add_builders(env)

#
# Adds custom diagnostic builders that output toolchain or platform specific diagnotic aids,
# such as map files, srecords, etc.
def add_builders(env):
    #
    # Generate mapfile for debugging
    #
    def generate_map(source, target, env, for_signature):
        return '%s -CgDlSt %s > %s' % (env['OBJDUMP'], source[0], target[0])

    #
    # SREC file because Paul likes them.
    #
    def generate_srec(source, target, env, for_signature):
        return '%s -O ihex %s %s' % (env['OBJCOPY'], source[0], target[0])

    env.Append(BUILDERS=\
        {
        'Mapfile' : Builder(
            generator = generate_map,
            suffix = '.map',
            src_suffix = '.elf'),
        'SRecord' : Builder(
            generator = generate_srec,
            suffix = '.srec',
            src_suffix = '.elf')
        })





                


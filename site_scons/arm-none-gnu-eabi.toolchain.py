"""
Snagged alot of settings from:
    http://sourceforge.net/apps/trac/xpcc/browser/trunk/scons/arm.py?rev=651
"""
from SCons.Script import *
import os
import re

root = os.environ.get('GCC_ROOT')

if root != None:
    print("Defaulting to configured toolchain location:" + root)
    TOOLCHAIN_ROOT=root
    TOOLCHAIN_LIBDIR=os.path.join(TOOLCHAIN_ROOT, 'lib/gcc/arm-none-eabi/4.8.3')
    TOOLCHAIN_BINDIR=os.path.join(TOOLCHAIN_ROOT, 'bin')
    CROSS_COMPILE=TOOLCHAIN_BINDIR + '/arm-none-eabi-'
else:
    # Grab it from the path
    CROSS_COMPILE='arm-none-eabi-'

OPENCM3_ROOT = os.path.join(Dir('#').abspath, 'libopencm3')

SCM_REVISION = os.popen("git rev-parse HEAD").read().rstrip()

DEFS=['-DSTM32F2',
      '-DBOOTLOADER_MAJOR_VERSION=1', 
      '-DBOOTLOADER_MINOR_VERSION=0', 
      '-DBOOTLOADER_PATCH_VERSION=0',
      '-DMAJOR_VERSION=1', 
      '-DMINOR_VERSION=0', 
      '-DPATCH_VERSION=0',
      '-DNDEBUG',
      '-DSCM_REVISION=\'"%s"\'' % (re.sub(r'(..)', r'\\x\1', SCM_REVISION)),
      '-DPB_FIELD_16BIT=1',
      '-DQR_MAX_VERSION=0']

WARNS=['-Wall',
       '-Wno-sequence-point',
       '-Wextra',
       '-Wformat',
       '-Wformat-nonliteral',
       '-Wformat-security',
       '-Wimplicit-function-declaration',
       '-Winit-self',
       '-Wmultichar',
       '-Wpointer-arith',
       '-Wredundant-decls',
       '-Wreturn-type',
       '-Wshadow',
       '-Wsign-compare',
       '-Wstrict-prototypes',
       '-Wundef',
       '-Wuninitialized',
       '-Werror']

def load_toolchain():
    env = DefaultEnvironment()

    env['CC'] = CROSS_COMPILE + 'gcc'
    env['CXX'] = CROSS_COMPILE + 'g++'
    env['AR'] = CROSS_COMPILE + 'ar'
    env['AS'] = CROSS_COMPILE + 'g++' 
    env['OBJCOPY']      = CROSS_COMPILE + 'objcopy'
    env['OBJDUMP'] = CROSS_COMPILE + 'objdump'
    env['LINK']         = CROSS_COMPILE + 'gcc'
    env['OBJPREFIX']    = ''
    env['OBJSUFFIX']    = '.o'
    env['LIBPREFIX']    = 'lib'
    env['LIBSUFFIX']    = '.a'
    env['SHCCFLAGS']    = '$CCFLAGS'
    env['SHOBJPREFIX']  = '$OBJPREFIX'
    env['SHOBJSUFFIX']  = '$OBJSUFFIX'
    env['PROGPREFIX']   = ''
    env['PROGSUFFIX']   = '.elf'
    env['RANLIB']         = CROSS_COMPILE + 'ranlib'
    env['SHLIBPREFIX']  = 'lib'
    env['SHLIBSUFFIX']  = '.so'

    env['LINKFLAGS']    = [ 
                    '-mthumb',
                    '-mcpu=cortex-m3',
                    '-nostartfiles',
                    '-msoft-float',
                    '-L'+OPENCM3_ROOT+'/lib',
                    '-specs=nosys.specs',
                    # Mapfile output via linker.  Shows the memory map and 
                    # high level symbol table info 
                    '-Wl,-Map=${TARGET.base}.linkermap',
                    '-Wl,--gc-sections',
                    ]

    env['LIBPREFIXES']  = [ '$LIBPREFIX' ]
    env['LIBSUFFIXES']  = [ '$LIBSUFFIX' ]


    env['CCFLAGS'] = [
            '-mthumb',
            '-mcpu=cortex-m3',
            '-msoft-float',
            '-ffunction-sections',
            '-fdata-sections',
            '-fno-common',
            '-fstack-protector-all',
            '-I'+OPENCM3_ROOT+'/include',
            ]

    env['CCFLAGS'] = env['CCFLAGS'] + DEFS + WARNS

    env['CXXFLAGS'] = [
            "-fno-exceptions",
            "-fno-rtti",
            "-fno-threadsafe-statics",
            "-fuse-cxa-atexit",
            "-Woverloaded-virtual",
            "-Weffc++",
            "-std=gnu++11"
            ]

    env['CFLAGS'] = ['-std=gnu99' ]

    #
    # Assembler flags
    # 
    env['ASFLAGS'] = [
            "-mcpu=cortex-m3",
            "-mthumb",
            "-gdwarf-2",
            "-xassembler-with-cpp",
            "-Wa,-adhlns=${TARGET.base}.lst",
    ]

    #
    # Debug
    #
    if int(ARGUMENTS.get('debug', 0)):
        env['CCFLAGS'] += ['-g', '-Os', '-DDEBUG_ON']
    else:
        env['CCFLAGS'] += ['-Os', '-g']

    add_builders(env)



#
# Adds custom diagnostic builders that output toolchain or platform specific diagnotic aids,
# such as map files, srecords, etc.
def add_builders(env):
    #
    # Generate mapfile for debugging
    #
    def generate_map(source, target, env, for_signature):
        return '%s -dSt %s > %s' % (env['OBJDUMP'], source[0], target[0])

    #
    # SREC file because Paul likes them.
    #
    def generate_srec(source, target, env, for_signature):
        return '%s -O ihex %s %s' % (env['OBJCOPY'], source[0], target[0])

    #
    # bin file for bootloader
    #
    def generate_bin(source, target, env, for_signature):
        return '%s -O binary %s %s' % (env['OBJCOPY'], source[0], target[0])

    env.Append(BUILDERS=\
        {
        'Mapfile' : Builder(
            generator = generate_map,
            suffix = '.map',
            src_suffix = '.elf'),
        'SRecord' : Builder(
            generator = generate_srec,
            suffix = '.srec',
            src_suffix = '.elf'),
        'Binfile' : Builder(
            generator = generate_bin,
            suffix = '.bin',
            src_suffix = '.elf')
        })
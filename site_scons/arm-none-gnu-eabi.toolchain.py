"""
Snagged alot of settings from:
    http://sourceforge.net/apps/trac/xpcc/browser/trunk/scons/arm.py?rev=651
"""
from SCons.Script import *
import os

TOOLCHAIN_ROOT='/opt/carbon/gcc-arm-none-eabi-4_8-2014q1'
TOOLCHAIN_LIBDIR=os.path.join(TOOLCHAIN_ROOT, 'lib/gcc/arm-none-eabi/4.8.3')
TOOLCHAIN_BINDIR=os.path.join(TOOLCHAIN_ROOT, 'bin')
CROSS_COMPILE=TOOLCHAIN_BINDIR + '/arm-none-eabi-'

OPENCM3_ROOT = os.path.join(Dir('#').abspath, 'libopencm3')

#
# TODO: These are hacked in for now.  It should be part of the hal for this particular eval board impl.
#
DEFS=['-DSTM32F2', 
      '-DDEBUG_LINK=0', 
      '-DBOOTLOADER_MAJOR_VERSION=0', 
      '-DBOOTLOADER_MINOR_VERSION=0', 
      '-DBOOTLOADER_PATCH_VERSION=0',
      '-DPB_FIELD_16BIT=1']

def load_toolchain():
    env = DefaultEnvironment()

    env['CC'] = CROSS_COMPILE + 'gcc'
    env['CXX'] = CROSS_COMPILE + 'g++'
    env['AR'] = CROSS_COMPILE + 'ar'
    env['AS'] = CROSS_COMPILE + 'g++' 
    env['OBJCOPY']      = CROSS_COMPILE + 'objcopy'
    env['OBJDUMP'] = CROSS_COMPILE + 'objdump'
    env['LINK']         = CROSS_COMPILE + 'g++'
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

    """
    env['LINKFLAGS']    = [ '--static',
            '-Wl,--start-group',
                    '-lc',
                    '-lgcc',
                    '-lnosys',
                    '-Wl,--end-group',
                    '-L'+Dir('#').abspath,
                    '-L'+OPENCM3_ROOT+'/lib',
                    '-L'+OPENCM3_ROOT+'/lib/stm32/f2',
                    '-T' + Dir('#').abspath + '/memory_bootloader.ld', 
                    '-nostartfiles',
                    '-mthumb',
                    '-march=armv7',
                    '-mfix-cortex-m3-ldrd',
                    '-msoft-float']

    """
    env['LINKFLAGS']    = [ 
                        '-specs=nosys.specs', 
                        '-mthumb', 
                        '-L'+Dir('#').abspath,
                        '-L'+OPENCM3_ROOT+'/lib',
                        '-L'+OPENCM3_ROOT+'/lib/stm32/f2',
                        '-T' + Dir('#').abspath + '/memory_bootloader.ld', 
                        '-nostartfiles', 
                        '-mcpu=cortex-m3',
                        #'-mfix-cortex-m3-ldrd',
                        '-msoft-float'
                        ] 


    env['LIBPREFIXES']  = [ '$LIBPREFIX' ]
    env['LIBSUFFIXES']  = [ '$LIBSUFFIX' ]
    env['CCFLAGS'] = [
            "-mcpu=cortex-m3",
            "-mthumb",                       # use THUMB='-mthumb' to compile as thumb code (default for AT91SAM)
            "-mfloat-abi=soft",
            "-mthumb-interwork",
            "-gdwarf-2",
            "-funsigned-char",
            "-funsigned-bitfields",
            "-fshort-enums",
            "-ffunction-sections",
            "-fdata-sections",
            "-fno-split-wide-types",
            "-fno-move-loop-invariants",
            "-fno-tree-loop-optimize",
            "-fno-unwind-tables",
            "-mlong-calls",         # when using ".fastcode" without longcall:
            "-Wall",
            "-Wformat",
            "-Wextra",
            "-Wundef",
            "-Winit-self",
            "-Wpointer-arith",
            "-Wunused",
            "-Wfatal-errors",
            "-Wa,-adhlns=${TARGET.base}.lst",
            "-DBASENAME=${SOURCE.file}",
            "-static",
            "-Wformat-security",
            "-Wformat-nonliteral",
            "-Wshadow",
            "-Wuninitialized",
            "-msoft-float",
            '-I'+OPENCM3_ROOT+'/include'
            ]

    """
    env['CCFLAGS'] = [
            '-W',
            '-Wall',
            '-Wextra',
            '-Wimplicit-function-declaration',
            '-Wredundant-decls',
            '-Wundef',
            '-Wshadow',
            '-Wpointer-arith',
            '-Wformat',
            '-Wreturn-type',
            '-Wsign-compare',
            '-Wmultichar',
            '-Wformat-nonliteral',
            '-Winit-self',
            '-Wuninitialized',
            '-Wformat-security',
            '-Werror',
            '-fno-common',
            '-fno-exceptions',
            '-fvisibility=internal',
            '-mcpu=cortex-m3',
            '-mthumb',
            '-msoft-float',
            '-DSTM32F2',
            '-I'+OPENCM3_ROOT+'/include'
            ]
    """

    # For ST BSP
    env['CCFLAGS'].append(DEFS)

    env['CXXFLAGS'] = [
            #"-fverbose-asm",
            #"-save-temps",          # save preprocessed files
            "-fno-exceptions",
            "-fno-rtti",
            "-fno-threadsafe-statics",
            "-fuse-cxa-atexit",
            #"-nostdlib",
            "-Woverloaded-virtual",
            "-Weffc++",
            "-std=gnu++11"
            ]

    env['CFLAGS'] = ['-std=gnu99' ]

           # Assembler flags
    env['ASFLAGS'] = [
            "-mcpu=cortex-m3",
            "-mthumb-interwork",
            "-mthumb",
            "-gdwarf-2",
            "-xassembler-with-cpp",
            "-Wa,-adhlns=${TARGET.base}.lst",
    ]


    debug = ARGUMENTS.get('debug', 0)
    if int(debug):
        env['CCFLAGS'].append(['-g', '-O0'])
    else:
        env['CCFLAGS'].append(['-Os', '-g'])

    add_builders(env)



#
# Adds custom diagnostic builders that output toolchain or platform specific diagnotic aids,
# such as map files, srecords, etc.
def add_builders(env):
    #
    # Generate mapfile for debugging
    #
    def generate_map(source, target, env, for_signature):
        return '%s -gdSt %s > %s' % (env['OBJDUMP'], source[0], target[0])

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

                

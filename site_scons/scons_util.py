import glob
import os
import pprint
import sets
import toolchains
import re

from SCons.Script import *

import colors
import status

#
# Root directory for the build
#
BUILD_DIR = 'build'
COMPONENT_SETS = {}

#
# Finds all of the projects from the root of the product tree.  It key's off the existence of a SConscript file
# to determine if a given directory is a component project or not.
#
# @return list of projects.
#
def get_projects():
    projects = {}

    ignores = ['.git', '.hg', 'build']

    for root, dirs, files in os.walk(Dir('#').abspath):
        for i in ignores:
            if i in dirs:
                dirs.remove(i)

        if 'SConscript' in files:
            projects[os.path.basename(root)] = root

    return projects

def glob_ext(path, extensions):
    files = []
    if not os.path.exists(path): 
        return []

    for f in os.listdir(path):
        if re.match('.*\.('+extensions+')$', f):
            files.append(os.path.join(path, f))

    return files
     
#
# Finds all of the project source files for the specified platform that conform to the project directory structure convention.
#
# The following order of precedence exists, from most specific to least specific:
# 1 local/<platform>/<flavor>/
# 2 local/<platform>/
# 3 local/
#
# Flavor exists to support different backend implementations of a given project.
#
# @return the list of source files for the project, list of proto files
#
# Supported extensions: .cpp .c .proto .s
#
def find_project_source_files(project_root, platform, flavors):
    assert project_root != None, "No project root specified."

    #
    # Prefixes are ordered in sequence of preference.  Most specific 
    # may override common implementations.
    #
    prefixes = []
    if(flavors):
        for f in flavors:
            prefixes.append(os.path.join('local', platform, flavors[f]))
            prefixes.append(os.path.join('local', flavors[f]))
    if(platform):
        prefixes.append(os.path.join('local', platform))

    prefixes.append(os.path.join('local'))

    source_files = []
    proto_files = []

    for path in prefixes:
        pfiles = glob_ext(os.path.join(project_root, path), 'c|cpp|s')
        unique_files = [os.path.relpath(f, project_root) for f in pfiles if os.path.basename(f) in sets.Set([os.path.basename(x) for x in pfiles])]
        source_files += unique_files

    if(flavors):
        for f in flavors:
            prefixes.append(os.path.join('public', platform, flavors[f]))
            prefixes.append(os.path.join('public', flavors[f]))
    if(platform):
        prefixes.append(os.path.join('public', platform))

    prefixes.append(os.path.join('public'))

    for path in prefixes:
        pfiles = glob_ext(os.path.join(project_root, path), 'proto')
        unique_files = [os.path.relpath(f, project_root) for f in pfiles if os.path.basename(f) in sets.Set([os.path.basename(x) for x in pfiles])]
        proto_files += unique_files

    return source_files, proto_files

#
# Executable targets are denoted by an _app convention.  All source files with an _app suffice will be built into an
# executable.  Everything will be composed into a library.
#
# @return list of _app source files, and a corresponding list of other 'support' files.
#
def find_executable_targets(project_files, project_flavors):

    
    exe_suffix = '_main'

    exe_list = []
    support_files = []

    for f in project_files:
        if(os.path.basename(os.path.splitext(f)[0]).endswith('_main')):
            exe_list.append(f)
        else:
            support_files.append(f)

    return exe_list, support_files

#
# Take a given list of dependencies and expand against the component set map.
#
# @return an updated list of dependencies
#
def expand_deps(deplist):
    newlist = []
    for d in deplist:
        if len(COMPONENT_SETS)>0 and d.upper() in COMPONENT_SETS:
            for i in COMPONENT_SETS[d.upper()]:
                newlist.append(i)
        else:
            newlist.append(d)
    return newlist

#
# Call this from your project SConscript.
#
# Any _app's will be linked into an exe.  All other sources will be compiled into a library.  All _apps will link to
# that library.  Other projects may link to the library.
#
# @param env Scons environment
# @param deps List of project dependencies
# @param libs List of non-project dependencies (-lboost, -ljsoncpp, for example)
#
def init_project(env, deps=None, libs=None, project_defines=None):
    project_path = Dir('.').srcnode().abspath
    project_name = os.path.basename(project_path)
    bindir = os.path.join(env['VARIANT_BASE_DIR'], 'bin')
    libdir = os.path.join(env['VARIANT_BASE_DIR'], 'lib')

    print('--------------------' + project_name + '----------------------')

    if deps != None:
        deps = expand_deps(deps)

    build_os = env.get('os', 'native')

    #
    # Handle flavor #defines
    #
    flavors = None
    flavor_map = get_flavors()

    linkflags = []
    if project_name == 'bootstrap':
        linkflags = env['LINKFLAGS'] + ['-T' + Dir('#').abspath + '/memory_bootstrap.ld']
    elif project_name == 'bootloader':
        linkflags = env['LINKFLAGS'] + ['-T' + Dir('#').abspath + '/memory_bootloader.ld']
    else:
        linkflags = env['LINKFLAGS'] + ['-T' + Dir('#').abspath + '/memory.ld']

    project_flavors = {}
    if project_name in flavor_map:
        project_flavors = flavor_map[project_name]
        
        for flavor_name in project_flavors:
            flavor = project_flavors[flavor_name]
            print project_name + '-' + flavor_name + ' flavor set to: ' + flavor
            env['CPPDEFINES']['FLAVOR_' + flavor_name.upper()] = flavor
    

    project_files, proto_files = find_project_source_files(project_path, build_os, project_flavors)

    exe_targets, support_files = find_executable_targets(project_files, project_flavors)

    #
    # Setup default include paths
    #
    include_paths = project_includes(project_name, env)

    dep_include_paths = []
    if deps != None:
        for d in deps:
            dep_include_paths.append(dep_includes(d, env))

    # 
    # Build support project library
    #
    support_library = env.StaticLibrary(os.path.join(libdir, project_name), 
                              support_files,
                              CPPPATH=include_paths + dep_include_paths,
                              CPATH=include_paths + dep_include_paths)

    print "Library: lib%s library added" % project_name

    # 
    # Create exe targets
    #
    deplibs = [support_library]
    deplibpaths = [support_library[0].get_dir()]

    if(deps != None):
        deplibs.append(deps)
    	for d in deps:
  	    deplibpaths.append('../' + d)
	
    if(libs != None):
	deplibs.append(libs)

    platform_libs = ''
    if(build_os == 'linux'):
        platform_libs = '-Wl,-Bdynamic -lbsd'

    for exe_source in exe_targets:
        exename = os.path.splitext(os.path.basename(exe_source))[0]
        exe = env.Program(os.path.join(bindir, exename), 
                      exe_source, 
                      LIBS=[deplibs], 
                      _LIBFLAGS= '-Wl,--start-group ' + env['_LIBFLAGS'] + ' -Wl,--end-group ' + platform_libs,
                      LINKFLAGS=linkflags,
		              LIBPATH=deplibpaths,
                      CPPPATH=include_paths + dep_include_paths,
                      CPATH=include_paths + dep_include_paths)

        try:
            env.Mapfile(exe)
            env.SRecord(exe)
            env.Binfile(exe)
        except AttributeError:
            print "No platform specific output defined."

        print 'Program: %s added' % exename

#
# Initialize the platform specification, following the gnu tuple concept.
#
# @param env platform information is added into this environment map.
#
def init_platform(env):
    platform = ARGUMENTS.get('target', 'native')
    if platform == 'native':
        env['os'] = 'linux'
        env['arch'] = 'x86_64'
        env['vendor'] =  'gnu'
        env['abi'] = 'none'
    else:
        # arch-os-vendor-abi
        (arch, os, vendor, abi) = platform.split('-')
        env['arch'] = arch
        if(os == 'none'):
            os = 'baremetal'
        env['os'] = os
        env['vendor'] = vendor
        env['abi'] = abi

    return env

   #
# Top level product init function.  Call this from your top level SConstruct.
#
def init_product():
    status.register_build_status_handler()

    projects = get_projects()

    target = ARGUMENTS.get('target', 'native')
    if target != 'native':
        toolchain_dir = os.path.join(Dir('#').abspath, 'site_scons')    
        toolchain_name = ARGUMENTS.get('target')
        assert toolchains.load_toolchain(toolchain_dir, toolchain_name) == True,\
            "Toolchain '%s' not found." % toolchain_name

    env = DefaultEnvironment()
    
    init_platform(env)
    env.Append(CPPDEFINES={'PRODUCT_NAME' : current_project_name()})

    #
    # Disable alternate pretty strings for verbose output.
    #
    if not ARGUMENTS.get('verbose'):
        colors.colorize(env)

    #
    # Configure the default product environment
    #
    default_include_dirs = [Dir('#').abspath]
    env['CPPPATH'] = default_include_dirs
    env['CPATH'] = default_include_dirs

    debug = ARGUMENTS.get('debug', 0)
    if int(debug): 
        variant = 'debug'
    else:
        variant = 'release'

    variant_base_dir = os.path.join(Dir('#').abspath, BUILD_DIR, target, variant)
    env['VARIANT_BASE_DIR'] = variant_base_dir
    for p in projects:
        SConscript(os.path.join(projects[p], 'SConscript'), 
                   variant_dir=os.path.join(variant_base_dir, '.obj', p), 
                   exports = ['env'],
                   duplicate=0)

    #
    # Add tags convenience target to build ctags file at product root.
    #
    phony_target('tags', 'ctags -R --c++-kinds=+p --fields=+iaS --extra=+qf ' + Dir('#').abspath)

    Clean('.', BUILD_DIR)

#
# Similar to makefile @phony target.  Use to do things like add a map file or build tags.
#
def phony_target(target, action):
    phony = Environment(ENV = os.environ,
                        BUILDERS = { 'phony' : Builder(action = action) })
    AlwaysBuild(phony.phony(target = target, source = 'SConstruct'))

def current_project_name():
    project_path = Dir('.').srcnode().abspath
    project_name = os.path.basename(project_path)

    return project_name

def current_project_path():
    project_path = Dir('.').srcnode().abspath

    return project_name

# 
# Order of precendence is:
#   full_specified from root > flavor > os > local > public > project_base
#
# @return list of include paths for a given component
#
def project_includes(project_name, env):
    project_path = get_projects()[project_name]

    include_paths = []

    flavors = get_flavors()
    project_flavors = {}
    if project_name in flavors:
        project_flavors = flavors[project_name]

    include_paths.append( Dir('#').abspath)
    [include_paths.append(os.path.join(project_path, 'local', env['os'], project_flavors[f])) for f in project_flavors]
    include_paths.append(os.path.join(project_path, 'local', env['os']))
    [include_paths.append(os.path.join(project_path, 'local', project_flavors[f])) for f in project_flavors]
    include_paths.append(os.path.join(project_path, 'local'))
    [include_paths.append(os.path.join(project_path, 'public', env['os'], project_flavors[f])) for f in project_flavors]
    include_paths.append(os.path.join(project_path, 'public', env['os']))
    [include_paths.append(os.path.join(project_path, 'public', project_flavors[f])) for f in project_flavors]
    include_paths.append(os.path.join(project_path, 'public'))
    include_paths.append(project_path)

    return include_paths


#
# Returns a list of include paths for a given dependency
#
def dep_includes(project_name, env):
    project_path = get_projects()[project_name]
    include_paths = []

    flavors = get_flavors()
    project_flavors = {}
    if project_name in flavors:
        project_flavors = flavors[project_name]

    [include_paths.append(os.path.join(project_path, 'public', env['os'], flavor)) for flavor in project_flavors.values()]
    include_paths.append(os.path.join(project_path, 'public', env['os']))
    [include_paths.append(os.path.join(project_path, 'public', flavor)) for flavor in project_flavors.values()]
    include_paths.append(os.path.join(project_path, 'public'))
    include_paths.append(project_path)

    return include_paths

def get_flavors():
    flavors = {}

    #
    # Add flavor args to the map for easy access
    #
    for arg in ARGUMENTS:
        x = arg.split('-')
        if len(x) == 3:
            if x[0] == 'flavor':
                if x[1] in flavors:
                    flavors[x[1]][x[2]] = ARGUMENTS.get(arg)
                else:
                    flavors[x[1]] = {x[2] : ARGUMENTS.get(arg)}

    return flavors


            









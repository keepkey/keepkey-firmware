#
# @brief Top level interface for toolchain definitions
#
import imp
import glob
from SCons.Script import *

def load_toolchain(toolchain_dir, toolchain):
    platform_toolchain_spec = imp.find_module(toolchain + '.toolchain', [toolchain_dir])
    assert platform_toolchain_spec != None, "Toolchain for '%s' not found." % toolchain

    toolchain_module = imp.load_module(toolchain, *platform_toolchain_spec)
            
    toolchain_module.load_toolchain()
    return True


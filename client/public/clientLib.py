#
# See http://polywww.in2p3.fr/activites/physique/glast/workbook/pages/SCons/sconsOvrvw_working.htm#librariesDependOtherLibraries
# 
# This allows the top level program depending on this project to automagically import any deps this component 
# requires.
def generate(env, **kw):
    if not kw.get('depsOnly', 0):
        env.Tool('addLibrary', library = ['libclient'])
    env.Tool('addLibrary', library = env['protobuf'])

def exists(env):
    return 1

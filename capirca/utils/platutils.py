import capirca.lib.plat
from pkgutil import walk_packages

def LoadExportedPlatforms():
    modules = []
    for loader, module_name, is_pkg in walk_packages(capirca.lib.plat.__path__):
        module = loader.find_module(module_name).load_module(module_name)
        modules.append(module)
    return modules

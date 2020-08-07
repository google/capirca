import capirca.platforms.exported as exported
from pkgutil import walk_packages

def LoadExportedPlatforms():
    modules = []
    for loader, module_name, is_pkg in walk_packages(exported.__path__):
        module = loader.find_module(module_name).load_module(module_name)
        modules.append(module)
    return modules

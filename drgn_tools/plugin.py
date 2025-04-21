# Copyright (c) 2025, Oracle and/or its affiliates.
# Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl/
"""
The ``drgn_tools.plugin`` module contains a drgn plugin for Oracle Linux.

Plugins allow customizing drgn's behavior, most importantly with respect to how
it searches for debuginfo. The Oracle Linux plugin provides several
functionalities that make it easier to work with kernel debuginfo in the Oracle
Linux environment.

1. A debuginfo finder called "ctf", which uses Compact Type Format (CTF) and
   kallsyms in order to provide basic debuginfo functionality. This finder is
   disabled by default and can be enabled with "--try-symbols-by=ctf".

2. A debuginfo finder called "vmlinux_repo", which uses a configured "vmlinux
   repository" file path, where debuginfo files are extracted into a single
   directory named after the UTS_RELEASE value. This finder is enabled by
   default.

3. A debuginfo finder called "ol_yum", which attempts to download the debuginfo
   RPM for a given kernel, then extracts the relevant debuginfo files into the
   "vmlinux_repo" directory. This finder is disabled by default and can be
   enabled with "--try-symbols-by=ol_yum".
"""
import logging
import os
from pathlib import Path
from typing import List

from drgn import Program
from drgn import ProgramFlags
from drgn.helpers.linux.kallsyms import load_module_kallsyms
from drgn.helpers.linux.kallsyms import load_vmlinux_kallsyms

from drgn_tools.debuginfo import _get_configured_fetchers
from drgn_tools.debuginfo import OracleLinuxYumFetcher

try:
    # Plugins require drgn 0.0.31, which is also the first version to include
    # the Module API. This file won't be used on earlier drgn versions, but it
    # should at least be possible to import it when earlier versions are used.
    from drgn import MainModule
    from drgn import Module
    from drgn import ModuleFileStatus
    from drgn import RelocatableModule
except ImportError:
    pass

try:
    from _drgn import _linux_helper_load_ctf

    HAVE_CTF = True
except ImportError:
    HAVE_CTF = False


CTF_PATHS = [
    "./vmlinux.ctfa",
    "/lib/modules/{uname}/kernel/vmlinux.ctfa",
]

TAINT_OOT_MODULE = 12
logger = logging.getLogger("drgn.plugin.oracle")

VMLINUX_REPO = Path(
    os.environ.get("VMLINUX_REPO", os.path.expanduser("~/vmlinux_repo"))
)


def ctf_debuginfo_finder(modules: List["Module"]):
    prog = modules[0].prog

    ctf_loaded = "vmlinux_kallsyms" in prog.registered_symbol_finders()
    logger.debug("ctf: enter debuginfo finder ctf_loaded=%r", ctf_loaded)

    for module in modules:
        if isinstance(module, MainModule) and not ctf_loaded:
            uname = prog["UTS_RELEASE"].string_().decode()
            for path in CTF_PATHS:
                path = path.format(uname=uname)
                if os.path.isfile(path):
                    _linux_helper_load_ctf(prog, path)
                    finder = load_vmlinux_kallsyms(prog)
                    prog.register_symbol_finder("vmlinux_kallsyms", finder, enable_index=0)
                    module.address_range = (
                        prog.symbol("_stext").address,
                        prog.symbol("_end").address,
                    )
                    finder = load_module_kallsyms(prog)
                    prog.register_symbol_finder("module_kallsyms", finder, enable_index=1)
                    ctf_loaded = True
                    module.debug_file_status = ModuleFileStatus.DONT_NEED
                    logger.debug("ctf: load %s", path)
                    break
            else:
                logger.debug("failed to find vmlinux.ctfa")
        elif isinstance(module, RelocatableModule) and ctf_loaded:
            # CTF contains symbols for all in-tree modules. Mark them DONT_NEED
            if module.object.taints & TAINT_OOT_MODULE:
                logger.debug("out of tree module: %s", module.name)
            else:
                module.debug_file_status = ModuleFileStatus.DONT_NEED


def vmlinux_repo_finder(modules: List["Module"]):
    prog = modules[0].prog
    uname = prog["UTS_RELEASE"].string_().decode()
    logger.debug("vmlinux_repo: enter debuginfo finder")
    if not (VMLINUX_REPO / uname).is_dir():
        return
    for module in modules:
        if isinstance(module, MainModule):
            module.try_file(VMLINUX_REPO / uname / "vmlinux")
        elif isinstance(module, RelocatableModule):
            filename = f"{module.name.replace('-', '_')}.ko.debug"
            module.try_file(VMLINUX_REPO / uname / filename)


def ol_yum_finder(modules: List["Module"]):
    prog = modules[0].prog
    uname = prog["UTS_RELEASE"].string_().decode()
    logger.debug("ol_yum: enter debuginfo finder")
    for fetcher in _get_configured_fetchers():
        if isinstance(fetcher, OracleLinuxYumFetcher):
            break
        else:
            fetcher = OracleLinuxYumFetcher()
    fetcher.out_dir = VMLINUX_REPO  # type: ignore
    mod_names = []
    for mod in modules:
        if isinstance(mod, MainModule):
            mod_names.append("vmlinux")
        elif isinstance(mod, RelocatableModule) and not (
            mod.object.taints & TAINT_OOT_MODULE
        ):
            mod_names.append(mod.name)
    if mod_names:
        fetcher.fetch_modules(uname, mod_names, quiet=False)
        vmlinux_repo_finder(modules)


def drgn_prog_set(prog: Program) -> None:
    if not prog.flags & ProgramFlags.IS_LINUX_KERNEL:
        return

    if HAVE_CTF:
        prog.register_debug_info_finder("ctf", ctf_debuginfo_finder)

    # This is registered first because it costs only one stat() to see whether
    # or not we have a directory for this kernel version. Whereas the default
    # debuginfo finder searches many paths for each module. It costs practically
    # nothing to check this when there's no vmlinux_repo, but if there is one,
    # then the default finder wastes about 0.5 seconds prior to calling this.
    prog.register_debug_info_finder(
        "vmlinux-repo", vmlinux_repo_finder, enable_index=0
    )

    prog.register_debug_info_finder("ol-yum", ol_yum_finder)

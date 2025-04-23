# Copyright (c) 2025, Oracle and/or its affiliates.
# Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl/
"""
For each vmcore, fetch CTF data and debuginfo
"""
import os
import re
import shutil
import subprocess
import sys
import tempfile
from fnmatch import fnmatch
from pathlib import Path
from typing import Iterable

from drgn import Architecture
from drgn import Program

from drgn_tools.corelens import all_corelens_modules
from drgn_tools.debuginfo import CtfCompatibility
from drgn_tools.debuginfo import fetch_debuginfo
from drgn_tools.debuginfo import KernelVersion
from drgn_tools.module import KernelModule
from drgn_tools.util import download_file


# fmt: off
MODULES = {
    "ext4",
    "sunrpc", "nfs", "nfsd", "nfsv3", "nfsv4", "lockd", "nfs_acl", "nfs_ssc",
    "nvme", "nvme_core",
    "raid0", "raid1", "raid456",
    "rdma_cm", "rds", "rds_rdma", "rds_tcp",
    "ib_cm", "ib_core", "ib_ipoib", "iw_cm",
    "mlx5_ib", "mlx5_core", "mlxfw", "mlx4_ib", "mlx4_core",
    "virtio",
    "virtio_balloon",
    "virtio_blk",
    "virtio_console",
    "virtio_dma_buf",
    "virtio_crypto",
    "virtio_gpu",
    "virtio_input",
    "virtio_mem",
    "virtio_net",
    "virtio_pci",
    "virtio_pci_legacy_dev",
    "virtio_pci_modern_dev",
    "virtio_pmem",
    "virtio_ring",
    "virtio_rng",
    "virtio_scsi",
    "virtio_vdpa",
    "dm_historical_service_time",
    "dm_io_affinity",
    "dm_mod",
    "dm_multipath",
    "dm_queue_length",
    "dm_round_robin",
    "dm_service_time",
}
# fmt: on

PATTERNS = set()
for module in all_corelens_modules().values():
    if module.skip_unless_have_kmods:
        MODULES.update(module.skip_unless_have_kmods)
    PATTERNS.update(module.debuginfo_kmods)


def need_module(mod: str) -> bool:
    return mod in MODULES or module_matches(mod, PATTERNS)


def module_matches(kmod: str, pats: Iterable[str]) -> bool:
    # Fast path for any direct match
    if kmod in pats:
        return True
    for pat in pats:
        if pat.startswith("re:"):
            if re.fullmatch(pat[3:], kmod):
                return True
        elif fnmatch(kmod, pat):
            return True
    return False


class Vmcore:
    name: str
    path: Path
    release: str
    prog: Program
    arch: str
    kver: KernelVersion
    ctf_compat: CtfCompatibility

    def __init__(
        self,
        name: str,
        path: Path,
        release: str,
        prog: Program,
        arch: str,
        kver: KernelVersion,
        ctf_compat: CtfCompatibility,
    ):
        self.name = name
        self.path = path
        self.release = release
        self.prog = prog
        self.arch = arch
        self.kver = kver
        self.ctf_compat = ctf_compat

    def rpm_name(self) -> str:
        uek_ver = self.kver.uek_version

        if self.kver.is_uek and uek_ver in (4, 5, 6):
            return f"kernel-uek-{self.release}.rpm"
        elif self.kver.is_uek:
            return f"kernel-uek-core-{self.release}.rpm"
        elif self.kver.ol_version >= 8:
            return f"kernel-core-{self.release}.rpm"
        else:
            return f"kernel-{self.release}.rpm"


def get_vmcore(path: Path):
    name = path.parent.name
    prog = Program()
    prog.set_core_dump(path)
    release = prog["UTS_RELEASE"].string_().decode()
    kver = KernelVersion.parse(release)
    if prog.platform.arch == Architecture.X86_64:
        arch = "x86_64"
    elif prog.platform.arch == Architecture.AARCH64:
        arch = "aarch64"
    else:
        raise Exception("unsupported arch")

    uname = path.parent / "UTS_RELEASE"
    if not uname.exists():
        with uname.open("w") as f:
            print(f"Write UTS_RELEASE for vmcore {name}")
            f.write(release)

    ctf_sup = CtfCompatibility.get(kver, host_ol=9)
    print(f"VMCORE {name} {release} CTF: {ctf_sup}")
    ctf_sup_ol7 = CtfCompatibility.get(kver, host_ol=7)
    print(f"VMCORE {name} {release} CTF OL 7: {ctf_sup_ol7}")

    return Vmcore(name, path, release, prog, arch, kver, ctf_sup)


def get_ctfa(vmcore: Vmcore):
    print(f"CTF for VMCORE: {vmcore.name}")
    if vmcore.ctf_compat in (
        CtfCompatibility.NO,
        CtfCompatibility.LIMITED_PROC,
    ):
        print("     => Skip CTF (compatibility)")
        return
    dst = vmcore.path.parent / "vmlinux.ctfa"
    if dst.is_file():
        print("     => CTF Already exists!")
        return
    on_system = Path(f"/lib/modules/{vmcore.release}/kernel/vmlinux.ctfa")
    if on_system.is_file():
        print(f"     => Used file on-disk: {on_system}")
        shutil.copyfile(on_system, dst)
        return
    rpm = vmcore.rpm_name()
    url = f"https://yum.oracle.com/repo/OracleLinux/OL{vmcore.kver.ol_version}/UEKR{vmcore.kver.uek_version}/{vmcore.kver.arch}/getPackage/{rpm}"
    print(f"URL   : {url}")
    with tempfile.TemporaryDirectory() as td:
        tdp = Path(td)
        rpm_path = tdp / rpm
        with open(rpm_path, "wb") as f:
            download_file(url, f, quiet=False)
        subprocess.run(
            f"rpm2cpio {rpm_path} | cpio -id --quiet '*/vmlinux.ctfa'",
            shell=True,
            check=True,
            cwd=tdp,
        )
        src = tdp / f"lib/modules/{vmcore.release}/kernel/vmlinux.ctfa"
        shutil.move(src, dst)


def get_dwarf(vmcore: Vmcore) -> None:
    print(f"DWARF for VMCORE: {vmcore.name}")
    dst = vmcore.path.parent / "vmlinux"
    mods_in_vmcore = {"vmlinux"}
    repo_dir = Path.home() / "vmlinux_repo" / vmcore.release
    if dst.is_file():
        print("     => DWARF Already exists!")
        vmcore.prog.load_debug_info([dst])
        mods_to_fetch = []
        for mod in KernelModule.all(vmcore.prog):
            name = mod.name.replace("-", "_")
            if need_module(name):
                mods_in_vmcore.add(name)
                dst_file = dst.parent / f"{name}.ko.debug"
                if not dst_file.is_file():
                    mods_to_fetch.append(name)
        if mods_to_fetch:
            print("     => missing mods:", ", ".join(mods_to_fetch))
    else:
        print("     => DWARF not yet found")
        mods_to_fetch = list(MODULES) + ["vmlinux"]

    if not dst.is_file() or mods_to_fetch:
        print("     => Fetching debuginfo")
        name_to_path = fetch_debuginfo(vmcore.release, mods_to_fetch)
        if dst.is_file():
            vmlinux = dst
        else:
            vmlinux = name_to_path["vmlinux"]
        vmcore.prog.load_debug_info([vmlinux])
        for mod in KernelModule.all(vmcore.prog):
            name = mod.name.replace("-", "_")
            if need_module(name):
                mods_in_vmcore.add(name)

    if not repo_dir.exists():
        repo_dir.mkdir(parents=True)

    for modname in mods_in_vmcore:
        if modname == "vmlinux":
            file = "vmlinux"
        else:
            file = f"{modname}.ko.debug"

        repo = repo_dir / file
        dst = vmcore.path.parent / file

        if not repo.exists() and dst.exists():
            print(f"     => Move {modname} to repo ({vmcore.release})")
            shutil.move(dst, repo)

        if dst.is_file():
            if dst.stat().st_ino != repo.stat().st_ino:
                dst.unlink()
                print(f"     => Remove duplicate {modname} ({vmcore.release})")
        if not dst.is_file():
            os.link(repo, dst)
            print(f"     => Link {modname} ({vmcore.release})")


if __name__ == "__main__":
    if len(sys.argv) == 1 or sys.argv[1] in ("-h", "--help"):
        print(
            "usage: python -m testing.vmcore.debuginfo VMCORE [VMCORE [...]]"
        )
        sys.exit(1)
    for c in sys.argv[1:]:
        vmcore = get_vmcore(Path(c))
        get_ctfa(vmcore)
        get_dwarf(vmcore)

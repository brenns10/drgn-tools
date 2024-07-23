# Copyright (c) 2024, Oracle and/or its affiliates.
# Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl/
"""
Generate tables of stack offsets for lock functions.

Use the lockmod kernel module within this directory and load it.
Then use this script to find its threads and generate a list of stack offsets.
"""
import functools
import os
import sys
import time
import typing
from collections import Counter
from typing import Dict
from typing import List
from typing import Tuple

from drgn import Architecture
from drgn import FaultError
from drgn import Object
from drgn import Program
from drgn import StackFrame
from drgn.helpers.common import print_annotated_stack
from drgn.helpers.linux import for_each_task


def fp(prog: Program, frame: StackFrame) -> int:
    # On x86_64 we use the stack pointer for offsets, because the ORC info
    # guarantees we will have it.
    if prog.platform.arch == Architecture.X86_64:
        return frame.register("rsp")
    elif prog.platform.arch == Architecture.AARCH64:
        return frame.register("fp")
    else:
        raise NotImplementedError("Only aarch64 and x86_64 are supported")


def find_offsets(
    kind: str, fn_sub: str, var: str, task: Object
) -> List[Tuple[int, str]]:
    """
    Find a stack offset for a lock function symbol to get its lock pointer

    :param kind: kind of lock (mutex, sem, rwsem)
    :param fn_sub: substring that will be in the function symbol
    :param var: name of variable which the lock points at
    :param task: ``struct task_struct *``
    """
    prog = task.prog_
    trace = prog.stack_trace(task)

    for frame in trace:
        try:
            frame_sym = frame.symbol()
        except LookupError:
            continue
        if fn_sub in frame_sym.name:
            ref_fp, fn = fp(prog, frame), frame_sym.name
            break
    else:
        print(f"Could not find {kind}-related frame")
        return []

    addr = prog[var].address_

    lo = fp(prog, trace[0])
    hi = fp(prog, trace[-2])
    if hi < lo or hi > lo + 4096:
        hi = lo + 4096
    offsets = []
    for sp in range(lo, hi, 8):
        try:
            stack_word = prog.read_u64(sp)
        except FaultError:
            break
        if stack_word == addr:
            offsets.append(((sp - ref_fp) // 8, fn))
    if not offsets:
        print(f"Could not find {kind} in stack")
        print(f"Seeking: {addr:x} from {lo:x} to {hi:x}")
        print_annotated_stack(trace)

    return offsets


def main(prog: Program) -> None:
    kinds = ["mutex", "sem", "rwsem"]
    offsets: Dict[str, typing.Counter[Tuple[int, str]]] = {}
    comms = {
        "mutex": b"lockmod-mutex_",
        "sem": b"lockmod-sem_",
        "rwsem": b"lockmod-rwsem_",
    }
    functions = {
        "mutex": functools.partial(
            find_offsets, "mutex", "mutex", "lockmod_mutex"
        ),
        "sem": functools.partial(find_offsets, "sem", "down", "lockmod_sem"),
        "rwsem": functools.partial(
            find_offsets, "rwsem", "down", "lockmod_rwsem"
        ),
    }
    counts = {k: 0 for k in kinds}

    ko = sys.argv[1]
    os.system(f"insmod {ko}")
    prog.load_debug_info([ko])

    try:
        print("-->", prog["UTS_RELEASE"].string_().decode())
        for task in for_each_task(prog):
            comm = task.comm.string_()
            for kind in kinds:
                if not comm.startswith(comms[kind]):
                    continue
                counts[kind] += 1
                res = functions[kind](task)
                s = offsets.setdefault(kind, Counter())
                s.update(res)

        for kind in kinds:
            print(f"   -> {kind} (saw {counts[kind]} stacks)")
            for (offset, name), count in offsets[kind].most_common():
                print(f"{offset}\t{name}\t{count} stacks")

    finally:
        f = open("/proc/lockmod_test")
        f.close()
        time.sleep(1)
        os.system("rmmod lockmod")


if __name__ == "__main__":
    prog: Program
    main(prog)  # noqa

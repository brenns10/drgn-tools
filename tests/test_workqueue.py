# Copyright (c) 2023, Oracle and/or its affiliates.
# Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl/
import drgn
from drgn.helpers.linux.cpumask import for_each_online_cpu
from drgn.helpers.linux.percpu import per_cpu_ptr
from drgn.helpers.linux.pid import for_each_task

from drgn_tools import workqueue as wq

# import pytest


def system_workqueue_names(prog: drgn.Program):
    # Pick some global workqueues that will always exist
    return {
        prog["system_wq"].name.string_(),
        prog["system_highpri_wq"].name.string_(),
        prog["system_long_wq"].name.string_(),
        prog["system_unbound_wq"].name.string_(),
        prog["system_freezable_wq"].name.string_(),
    }


def test_for_each_workqueue(prog: drgn.Program) -> None:
    # The found workqueue names should be a superset of the test names.
    wq_names = {workq.name.string_() for workq in wq.for_each_workqueue(prog)}
    assert wq_names >= system_workqueue_names(prog)


def test_for_each_pool(prog: drgn.Program) -> None:
    # See the comment in _cpu_worker_pools
    cpu0_pools = wq._cpu_worker_pools(prog, 0)
    cpu0_normal_pool = cpu0_pools[0].address_of_()
    cpu0_highprio_pool = cpu0_pools[1].address_of_()
    all_pools = [pool for pool in wq.for_each_pool(prog)]
    assert cpu0_normal_pool in all_pools
    assert cpu0_highprio_pool in all_pools


def test_for_each_worker(prog: drgn.Program) -> None:
    kworker_tasks = [
        task.value_()
        for task in for_each_task(prog)
        if task.comm.string_().decode().startswith("kworker")
    ]
    kworker_obtained = [
        worker.task.value_() for worker in wq.for_each_worker(prog)
    ]
    assert kworker_tasks.sort() == kworker_obtained.sort()


def test_for_each_pool_worker(prog: drgn.Program) -> None:
    test_pool = wq._cpu_worker_pools(prog, 0)[0].address_of_()
    kworkers = [
        workers.value_()
        for workers in wq.for_each_worker(prog)
        if workers.pool.value_() == test_pool.value_()
    ]
    pool_kworkers = [
        workers.value_() for workers in wq.for_each_pool_worker(test_pool)
    ]
    assert kworkers.sort() == pool_kworkers.sort()


def test_for_each_cpu_worker_pool(prog: drgn.Program) -> None:
    cpu0_worker_pools = [p.address_ for p in wq._cpu_worker_pools(prog, 0)]
    worker_pools = [
        worker_pool.value_()
        for worker_pool in wq.for_each_cpu_worker_pool(prog, 0)
    ]
    assert worker_pools == cpu0_worker_pools


def test_for_each_pwq(prog: drgn.Program) -> None:
    workq = prog["system_wq"]
    pwqs = [pwq.value_() for pwq in wq.for_each_pwq(workq)]
    cpu_pwqs_attr = "cpu_pwqs" if hasattr(workq, "cpu_pwqs") else "cpu_pwq"
    cpu_pwqs_list = [
        per_cpu_ptr(getattr(workq, cpu_pwqs_attr), cpu).value_()
        for cpu in for_each_online_cpu(prog)
    ]
    assert pwqs.sort() == cpu_pwqs_list.sort()


def test_for_each_pending_work_on_cpu(prog: drgn.Program) -> None:
    for work in wq.for_each_pending_work_on_cpu(prog, 0):
        pass


def test_for_each_pending_work_in_pool(prog: drgn.Program) -> None:
    pool = wq._cpu_worker_pools(prog, 0)[0].address_of_()
    for work in wq.for_each_pending_work_in_pool(pool):
        pass


def test_for_each_pending_work_of_pwq(prog: drgn.Program) -> None:
    cpu_pwqs_0 = wq.workqueue_get_pwq(prog["system_wq"], 0)
    for work in wq.for_each_pending_work_of_pwq(cpu_pwqs_0):
        pass


def test_show_all_workqueues(prog: drgn.Program) -> None:
    wq.show_all_workqueues(prog)

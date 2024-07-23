//# Copyright (c) 2024, Oracle and/or its affiliates.
//# Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl/
//
// lockmod.c: create several threads which use mutex and semaphore APIs,
// so we can test stack offsets where the lock variables are found.
#define pr_fmt(fmt) "lockmod: " fmt

#include <linux/module.h>
#include <linux/version.h>

#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/kthread.h>

#include <linux/mutex.h>
#include <linux/semaphore.h>
#include <linux/rwsem.h>

DEFINE_MUTEX(lockmod_mutex);
DECLARE_RWSEM(lockmod_rwsem);

/*
 * 48380368dec14 ("Change DEFINE_SEMAPHORE() to take a number argument")
 * In v6.4
 */
#if LINUX_VERSION_CODE < KERNEL_VERSION(6,4,0)
DEFINE_SEMAPHORE(lockmod_sem);
#else
DEFINE_SEMAPHORE(lockmod_sem, 1);
#endif

DECLARE_COMPLETION(lockmod_doexit);
DECLARE_COMPLETION(lockmod_ready);
bool locked;
struct proc_dir_entry *pde;


/* A proc file which is used to trigger the unlocking of the mutex & semaphore,
 * which allows the kthreads to exit and the module to be removed gracefully. */
static int lockmod_seq_show(struct seq_file *seq, void *offset)
{
        seq_printf(seq, "done\n");
        return 0;
}

static int lockmod_open(struct inode *inode, struct file *file)
{
	if (locked) {
		complete(&lockmod_doexit);
		pr_info("sent signal to unlock\n");
	}
        return single_open(file, lockmod_seq_show, NULL);
}

static int lockmod_release(struct inode *inode, struct file *file)
{
        return seq_release(inode, file);
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(5,6,0)
static const struct file_operations lockmod_fops = {
	.owner			= THIS_MODULE,
	.open			= lockmod_open,
	.read			= seq_read,
	.llseek		= seq_lseek,
	.release                = lockmod_release,
};
#else
static const struct proc_ops lockmod_fops = {
	.proc_open		= lockmod_open,
	.proc_read		= seq_read,
	.proc_lseek		= seq_lseek,
	.proc_release		= lockmod_release,
};
#endif


static int lockmod_owner(void *unused)
{
	pr_info("[owner] hello!\n");
	__module_get(THIS_MODULE);
	mutex_lock(&lockmod_mutex);
	down(&lockmod_sem);
	down_write(&lockmod_rwsem);
	locked = true;

	/* We are up and locked! Release the kthreads. */
	complete(&lockmod_ready);

	pr_info("[owner] ready and waiting to exit\n");

	/* Now wait until we should exit */
	wait_for_completion(&lockmod_doexit);
	pr_info("[owner] time to exit\n");

	locked = false;
	up_write(&lockmod_rwsem);
	up(&lockmod_sem);
	mutex_unlock(&lockmod_mutex);
	module_put(THIS_MODULE);
	return 0;
}

/* Kthreads to exercise different mutex locking functions: */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,14,0)
#define MUTEX_CASES \
	X(lock, mutex_lock(&lockmod_mutex)) \
	X(lock_nested, mutex_lock_nested(&lockmod_mutex, 0)) \
	X(lock_io, mutex_lock_io(&lockmod_mutex)) \
	X(lock_io_nested, mutex_lock_io_nested(&lockmod_mutex, 0)) \
	X(lock_killable, do {} while (mutex_lock_killable(&lockmod_mutex) < 0)) \
	X(lock_killable_nested, do {} while (mutex_lock_killable_nested(&lockmod_mutex, 0) < 0)) \
	X(lock_interruptible, do {} while (mutex_lock_interruptible(&lockmod_mutex) < 0)) \
	X(lock_interruptible_nested, do {} while (mutex_lock_interruptible_nested(&lockmod_mutex, 0) < 0))
#else
#define MUTEX_CASES \
	X(lock, mutex_lock(&lockmod_mutex)) \
	X(lock_nested, mutex_lock_nested(&lockmod_mutex, 0)) \
	X(lock_killable, do {} while (mutex_lock_killable(&lockmod_mutex) < 0)) \
	X(lock_killable_nested, do {} while (mutex_lock_killable_nested(&lockmod_mutex, 0) < 0)) \
	X(lock_interruptible, do {} while (mutex_lock_interruptible(&lockmod_mutex) < 0)) \
	X(lock_interruptible_nested, do {} while (mutex_lock_interruptible_nested(&lockmod_mutex, 0) < 0))
#endif

#define X(kind, lock_code) \
	static int do_mutex_ ## kind(void *unused) { \
		__module_get(THIS_MODULE); \
		lock_code; \
		mutex_unlock(&lockmod_mutex); \
		module_put(THIS_MODULE); \
		return 0; \
	}
MUTEX_CASES
#undef X

#define SEM_CASES \
	X(down, down(&lockmod_sem)) \
	X(down_interruptible, do {} while (down_interruptible(&lockmod_sem) < 0)) \
	X(down_killable, do {} while (down_killable(&lockmod_sem) < 0)) \
	X(down_timeout, do {} while (down_timeout(&lockmod_sem, 86400 * HZ)))

#define X(kind, lock_code) \
	static int do_sem_ ## kind(void *unused) { \
		__module_get(THIS_MODULE); \
		lock_code; \
		up(&lockmod_sem); \
		module_put(THIS_MODULE); \
		return 0; \
	}
SEM_CASES
#undef X

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,15,0)
#define RWSEM_CASES \
	X(down_read, down_read(&lockmod_rwsem), up_read) \
	X(down_read_nested, down_read_nested(&lockmod_rwsem, 0), up_read) \
	X(down_read_interruptible, do {} while (down_read_interruptible(&lockmod_rwsem) < 0), up_read) \
	X(down_read_killable, do {} while (down_read_killable(&lockmod_rwsem) < 0), up_read) \
	X(down_read_killable_nested, do {} while (down_read_killable_nested(&lockmod_rwsem, 0) < 0), up_read) \
	X(down_write, down_write(&lockmod_rwsem), up_write) \
	X(down_write_nested, down_write_nested(&lockmod_rwsem, 0), up_write) \
	X(down_write_killable, do {} while (down_write_killable(&lockmod_rwsem) < 0), up_write) \
	X(down_write_killable_nested, do {} while (down_write_killable_nested(&lockmod_rwsem, 0) < 0), up_write)
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(4,14,0)
#define RWSEM_CASES \
	X(down_read, down_read(&lockmod_rwsem), up_read) \
	X(down_read_nested, down_read_nested(&lockmod_rwsem, 0), up_read) \
	X(down_read_killable, do {} while (down_read_killable(&lockmod_rwsem) < 0), up_read) \
	X(down_write, down_write(&lockmod_rwsem), up_write) \
	X(down_write_nested, down_write_nested(&lockmod_rwsem, 0), up_write) \
	X(down_write_killable, do {} while (down_write_killable(&lockmod_rwsem) < 0), up_write) \
	X(down_write_killable_nested, do {} while (down_write_killable_nested(&lockmod_rwsem, 0) < 0), up_write)
#else
#define RWSEM_CASES \
	X(down_read, down_read(&lockmod_rwsem), up_read) \
	X(down_read_nested, down_read_nested(&lockmod_rwsem, 0), up_read) \
	X(down_write, down_write(&lockmod_rwsem), up_write) \
	X(down_write_nested, down_write_nested(&lockmod_rwsem, 0), up_write)
#endif

#define X(kind, lock_code, upfn) \
	static int do_rwsem_ ## kind(void *unused) { \
		__module_get(THIS_MODULE); \
		lock_code; \
		upfn(&lockmod_rwsem); \
		module_put(THIS_MODULE); \
		return 0; \
	}
RWSEM_CASES
#undef X

/*
 * Module initialization and exit routines.
 */
static int __init init_lockmod(void)
{
	pde = proc_create("lockmod_test", 0444, NULL, &lockmod_fops);
	if (!pde)
		return -ENOENT;

	pr_info("[init] starting owner thread\n");
	kthread_run(lockmod_owner, NULL, "lockmod-owner");

	/* Wait until we are locked and loaded. */
	pr_info("[init] waiting until owner is ready\n");
	wait_for_completion(&lockmod_ready);
	pr_info("[init] owner is ready: launching kthreads\n");

	#define X(kind, lock_code) kthread_run(&do_mutex_ ## kind, NULL, "lockmod-mutex_" #kind);
	MUTEX_CASES
	#undef X

	#define X(kind, lock_code) kthread_run(&do_sem_ ## kind, NULL, "lockmod-sem_" #kind);
	SEM_CASES
	#undef X

	#define X(kind, a, b) kthread_run(&do_rwsem_ ## kind, NULL, "lockmod-rwsem_" #kind);
	RWSEM_CASES
	#undef X

	pr_info("[init] module initialized\n");
	return 0;
}

static void __exit exit_lockmod(void)
{
	proc_remove(pde);
	pde = NULL;
	pr_info("successful exit\n");
}

module_init(init_lockmod);
module_exit(exit_lockmod);

MODULE_AUTHOR("Stephen Brennan <stephen.s.brennan@oracle.com>");
MODULE_DESCRIPTION("Create kthreads which sleep waiting for locks");
MODULE_LICENSE("GPL");

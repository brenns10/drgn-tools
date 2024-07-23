# Lock Offset Tables

When running with DWARF debuginfo, drgn can usually automatically load a lock
variable out of a stack frame, using the CFI. But when running with CTF, we need
to determine the stack frame offset to use. Also, sometimes drgn returns a false
negative ("absent" object) when the correct lock pointer is actually available
on the stack. For both those cases, we would like to have a hardcoded list of
stack offsets to use for getting locks out of stack frames.

This document describes the generation of the table and contains the manually
validated results. The final table is copied into `drgn_tools/locking.py`

## Background

Of course, a general purpose solution for getting a variable value from a stack
frame is very difficult. Some functions will spill a variable to the stack, but
that's only if they cannot hold the variable in an available register. The rest
of the time, they'll keep it in a callee-saved register. And then, the location
that register gets saved to the stack will depend on the callee functions.
Thankfully, we only care about the case where the thread is stuck in schedule(),
so we can hardcode just this one case.

To resolve this, we have created a kernel called "lockmod".  It launches
kthreads which will go to sleep waiting for various kinds of locks.  Then the
`generate_lock_tables.py` script will search for those kthreads and look for the
offset of the variable in the stack.

Since it's theoretically possible for these offsets to change, even during a UEK
release, we have an `automatic_lock_tables.sh` script which can be scheduled
`@reboot` for the root crontab. This will compute the offsets and then install
the next kernel to test.

## Steps to Generate each list

These steps are inexect and they use Yo with my configurations.

1. Launch OCI instance of desired kind.
2. Copy the files:
   ```
   yo scp ../automatic_lock_tables.sh Makefile lockmod.c ../generate_lock_tables.py ol9arm-1:lockmod/
   ```
3. SSH in and set the root crontab:
   ```
   @reboot /usr/bin/bash -x /home/opc/lockmod/automatic_lock_tables.sh >>/home/opc/biglog.txt 2>&1
   ```
4. Get a list of all the available kernel-uek versions:
   ```
   sudo dnf list --showduplicates kernel-uek.aarch64
   ```
5. Paste that into a file, organize it and normalize it, then copy it as
   `kernels.txt`. I've kept around a copy of these files in the `input/`
   directory.
6. Finally, install the kernel at the top of the file and reboot into it. This
   will start the automatic process that should continue until the end of the
   list is reached. NB: the process goes from the top to the bottom.
   If you're already booted into it, you can save some time by `cd lockmod &&
   sudo bash -x automatic_lock_tables.sh >>/home/opc/biglog.txt 2>&1`

Below is a set of commands roughly equivalent to what I did. It is not a shell
script; many of these need to be run in separate tmux windows to monitor.
Further, sometimes things went wrong and needed to be moved along. That's not
covered here.

```
yo launch -p ol9    -n ol9-uek7-x86_64
yo launch -p ol9arm -n ol9-uek7-aarch64
yo launch -p ol8    -n ol8-uek7-x86_64
yo launch -p ol8arm -n ol8-uek7-aarch64
yo launch -p ol8    -n ol8-uek6-x86_64
yo launch -p ol8arm -n ol8-uek6-aarch64
yo launch -p ol7    -n ol7-uek6-x86_64
yo launch -p ol7    -n ol7-uek5-x86_64
yo launch -p ol7    -n ol7-uek4-x86_64

# wait for all of these to launch
INSTANCES="ol9-uek7-x86_64 ol9-uek7-aarch64 ol8-uek7-x86_64 ol8-uek7-aarch64 ol8-uek6-x86_64 ol8-uek6-aarch64 ol7-uek6-x86_64 ol7-uek5-x86_64 ol7-uek4-x86_64"

for inst in $INSTANCES; do
    echo $inst
    yo scp ../automatic_lock_tables.sh Makefile lockmod.c ../generate_lock_tables.py \
           $inst:lockmod/
    yo scp ../$inst.txt $inst:kernels.txt
done

# Now manually do for each machine: (first one ol7 only)
sudo curl -o /etc/yum.repos.d/stepbren.repo \
    https://kernel.us.oracle.com/~stepbren/files/stepbren-ol7.repo
sudo yum -y install drgn
# For OL8 UEK6 x86_64, install drgn-tools as well, and configure the debuginfo fetcher.
# This is necessary because the CTF is broken for a lot of those kernels. The
# automatic_lock_tables.sh script will fetch DWARF debuginfo to make the script work
# for that case.
sudo yum-config-manager --enable ol7_UEKR4
sudo yum-config-manager --enable ol7_UEKR5
sudo yum-config-manager --enable ol8_UEKR6
sudo crontab -e
# add @reboot /usr/bin/bash -x /home/opc/lockmod/automatic_lock_tables.sh >>/home/opc/biglog.txt 2>&1
sudo yum install -y kernel-uek{,-devel}-$(head -n1 kernels.txt)
sudo grubby --set-default /boot/vmlinuz-$(head -n1 kernels.txt)
sudo reboot

# And finally:
yo console ol9-uek7-x86_64
yo console ol9-uek7-aarch64
yo console ol8-uek7-x86_64
yo console ol8-uek7-aarch64
yo console ol8-uek6-x86_64
yo console ol8-uek6-aarch64
yo console ol7-uek6-x86_64
yo console ol7-uek5-x86_64
yo console ol7-uek4-x86_64


# At the end:
for inst in $INSTANCES; do
    yo scp $inst:log.txt result/$inst.txt
done
```

## Hiccups

**OL7 UEK4**

I encountered trouble with UEK4 support for early kernels. I'm not entirely
clear what the issue was, but I did make things simpler by only checking those
after the following version:

`4.1.12-124.70.2.el7uek.x86_64`

This should be fine since we do not support the truly ancient UEK4 builds.

**OL8 UEK6 aarch64**

I encountered that many of the UEK6U1 and UEK6U2 kernels had `/proc/kcore` that
appeared empty to userspace. I'm not 100% confident why this was. An example of
this was:

`5.4.17-2036.102.0.2.el8uek.aarch64`

I decided that for aarch64, we could only support UEK6U3 and newer.

## Result

Here is the summarized result. The logs for each table are provided below.

```
####################  OL7 UEK4 x86_64  ####################
mutex:
  __mutex_lock_interruptible_slowpath: -5
  __mutex_lock_slowpath: -5
  __mutex_lock_killable_slowpath: -5
sem:
  __down_common: -6
rwsem:
  rwsem_down_write_failed: -3
  rwsem_down_read_failed: -4
####################  OL7 UEK5 x86_64  ####################
mutex:
  __mutex_lock.isra.5: -8
sem:
  __down_common: -7
rwsem:
  rwsem_down_write_failed_killable: -7
  rwsem_down_write_failed: -9
  rwsem_down_read_failed: -9
  rwsem_down_read_failed_killable: -9
####################  OL7 UEK6 x86_64  ####################
mutex:
  mutex_lock.isra.11: -9
  mutex_lock.isra.10: -9 or -10
sem:
  __down_common: -7
rwsem:
  rwsem_down_read_slowpath: -4
  rwsem_down_write_slowpath: -9 or -3
####################  OL8 UEK6 x86_64  ####################
mutex:
  __mutex_lock.isra.8: -5
sem:
  __down: -7
  __down_interruptible: -7
  __down_killable: -7
  __down_timeout: -7
rwsem:
  rwsem_down_write_slowpath: -6
  rwsem_down_read_slowpath: -3
####################  OL8 UEK7 x86_64  ####################
mutex:
  __mutex_lock.constprop.0: -1
sem:
  __down_common: -20
rwsem:
  rwsem_down_read_slowpath: -7 or -8
  rwsem_down_write_slowpath: -7 or -5
####################  OL8 UEK6 aarch64  ####################
mutex:
  __mutex_lock.isra.9: 2
sem:
  __down: 2
  __down_interruptible: 2
  __down_killable: 2
  __down_timeout: 2
rwsem:
  rwsem_down_write_slowpath: 2
  rwsem_down_read_slowpath: 2
####################  OL8 UEK7 aarch64  ####################
mutex:
  __mutex_lock.constprop.0: 2
sem:
  __down_common: 2
rwsem:
  rwsem_down_read_slowpath: 2
  rwsem_down_write_slowpath: 2
####################  OL9 UEK7 x86_64  ####################
mutex:
  __mutex_lock.constprop.0: -6
sem:
  __down_common: -20
rwsem:
  rwsem_down_read_slowpath: -7 or -8
  rwsem_down_write_slowpath: -7 or -5
####################  OL9 UEK7 aarch64  ####################
mutex:
  __mutex_lock.constprop.0: 2
sem:
  __down_common: 2
rwsem:
  rwsem_down_read_slowpath: 2
  rwsem_down_write_slowpath: 2
```

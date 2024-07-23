#!/usr/bin/bash
# Copyright (c) 2024, Oracle and/or its affiliates.
# Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl/
# Run at startup with cron. Builds the lockmod kernel module and then runs the
# drgn script against it to detect offsets. Saves the offsets, installs the next
# kernel in a list, and reboots.
# @reboot /usr/bin/bash -x /home/opc/lockmod/automatic_lock_tables.sh >>/home/opc/biglog.txt 2>&1

export PATH=$PATH:/usr/sbin  # to help find insmod
CURR=$(uname -r)
echo "STARTUP: SLEEP 10" >/dev/kmsg
sleep 10
DRGN_ARGS=-C

# Case-by-case workarounds:
# OL8 UEK7: enable gcc-toolset-11 for module build
# OL8 UEK6 x86_64: some CTF is bad, use DWARF instead
case $CURR in
    5.15.*.el8uek*)
        source /opt/rh/gcc-toolset-11/enable
        ;;
    5.4.*.el8uek.x86_64)
        python3 -m drgn_tools.debuginfo $CURR
        DRGN_ARGS="-s /root/vmlinux_repo/$CURR/vmlinux"
        ;;
esac

cd /home/opc/lockmod
sudo -u opc make clean
sudo -u opc make

if ! drgn $DRGN_ARGS generate_lock_tables.py lockmod.ko >> /home/opc/log.txt 2>&1; then
    echo "FAILED GENERATING LOCK TABLES" >/dev/kmsg
    exit 1
else
    echo "SUCCESS GENERATING LOCK TABLES" >/dev/kmsg
fi
rm -rf /root/vmlinux_repo


NEXT=$(awk "/$CURR/"'{getline; print}' /home/opc/kernels.txt)

if [ "$CURR" = "$NEXT" ]; then
    echo "COMPLETED CHECKING ALL PACKAGES" >/dev/kmsg
else
    echo "REBOOTING INTO $NEXT" >/dev/kmsg
    if ! yum install -y kernel-uek-$NEXT kernel-uek-devel-$NEXT; then
        echo "FAILED TO INSTALL $NEXT" >/dev/kmsg
        exit 1
    fi
    grubby --set-default /boot/vmlinuz-$NEXT
    reboot
fi

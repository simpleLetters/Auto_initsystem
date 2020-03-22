#!/bin/bash
# vim: set expandtab tabstop=4 shiftwidth=4 softtabstop=4:
#
# Author : Nicolas Brousse <nicolas@brousse.info>
# From : https://www.shell-tips.com/2010/09/13/linux-sysctl-configuration-and-tuning-script/
#
# Added kernel version < 2.6.33 set net.ipv4.tcp_congestion_control=htcp
# Notes :
#   This script is a simple "helper" to configure your sysctl.conf on linux
#   There is no silver bullet. Don't expect the perfect setup, review comments
#   and adapt the parameters to your needs and application usage.
#
#   Use this script at your OWN risk. There is no guarantee whatsoever.
#
# License :
#   This work is licenced under the CC-GNU LGPL version 2.1 or later.
#   To view a copy of this licence, visit http://creativecommons.org/licenses/LGPL/2.1/
#   or send a letter to :
#
#           Creative Commons
#           171 Second Street, Suite 300
#           San Francisco, California 94105, USA
#
# May 2012, Jon Zobrist <jon@jonzobrist.com> http://www.jonzobrist.com/
# Things added : 
# Apache max file handlers update to /etc/security/limits.conf
# Check and add pam_limits.so is loaded by the su program (as many things run via su)
# Backing up of previous sysctl.conf file
# Merging of previous sysctl.conf settings if new settings don't override
# tcp_available_congestion_control detection and setting
# Updates hosted on github at https://github.com/jonzobrist/Bash-Admin-Scripts

host=$(hostname)

ARCH=$(uname -m)
KERNEL_STRING=$(uname -r | sed -e 's/[^0-9]/ /g')
KERNEL_VERSION=$(echo "${KERNEL_STRING}" | awk '{ print $1 }')
MAJOR_VERSION=$(echo "${KERNEL_STRING}" | awk '{ print $2 }')
MINOR_VERSION=$(echo "${KERNEL_STRING}" | awk '{ print $3 }')
echo "${KERNEL_VERSION}.${MAJOR_VERSION}.${MINOR_VERSION}"
CURRENT_SYSCTL_FILE=/tmp/sysctl-existing-$(date +%F-%s)

touch ${CURRENT_SYSCTL_FILE}
#chmod og-rwx ${CURRENT_SYSCTL_FILE}
grep -v '^#' /etc/sysctl.conf | grep . >> ${CURRENT_SYSCTL_FILE}
BACKUP_SYSCTL="sysctl.conf-$(date +%F-%s)"
echo "moving sysctl.conf to /etc/${BACKUP_SYSCTL}"
mv /etc/sysctl.conf /etc/${BACKUP_SYSCTL}

which bc
if [ $? -ne 0 ]; then
    echo "This script require GNU bc, cf. http://www.gnu.org/software/bc/"
    echo "On Linux Debian/Ubuntu you can install it by doing : apt-get install bc"
fi

echo "Update sysctl for $host"

mem_bytes=$(awk '/MemTotal:/ { printf "%0.f",$2 * 1024}' /proc/meminfo)
shmmax=$(echo "$mem_bytes * 0.90" | bc | cut -f 1 -d '.')
echo "shmmax = " $shmmax 
shmall=$(expr $mem_bytes / $(getconf PAGE_SIZE))
echo "shmall = " $shmall
max_orphan=$(echo "$mem_bytes * 0.10 / 65536" | bc | cut -f 1 -d '.')
echo "max_orphan = " $max_orphan
file_max=$(echo "$mem_bytes / 4194304 * 256" | bc | cut -f 1 -d '.')
echo "file_max = " = $file_max
max_tw=$(($file_max*2))
echo "max_tw =" $max_tw
min_free=$(echo "($mem_bytes / 1024) * 0.01" | bc | cut -f 1 -d '.')
echo "min_free = " $min_free

if [ "${KERNEL_VERSION}" -lt 3 ] && [ "${MAJOR_VERSION}" -lt 7 ] && [ "${MINOR_VERSION}" -lt 33 ]
 then
    CONGESTION_CONTROL="htcp"
 else
    if [ "$(sysctl net.ipv4.tcp_available_congestion_control | grep reno)" ]
     then
        CONGESTION_CONTROL="reno"
    else
        CONGESTION_CONTROL="cubic"
    fi
fi

if [ "$1" != "ssd" ]; then
    vm_dirty_bg_ratio=5
    vm_dirty_ratio=15
else
    # This setup is generally ok for ssd and highmem servers
    vm_dirty_bg_ratio=3
    vm_dirty_ratio=5
fi
 
>/etc/sysctl.conf cat << EOF
# manage by puppet
# Kernel sysctl configuration file for Red Hat Linux
#
# For binary values, 0 is disabled, 1 is enabled.  See sysctl(8) and
# sysctl.conf(5) for more details.

# Controls IP packet forwarding
#{% if 'Ubuntu' in salt['grains.get']('os') %}
net.ipv4.ip_forward = 1
#{% else %}
#net.ipv4.ip_forward = 0
#{% endif %}


# Controls source route verification
net.ipv4.conf.default.rp_filter = 1

# Controls the use of TCP syncookies
net.ipv4.tcp_syncookies = 1

# Do not accept source routing
net.ipv4.conf.default.accept_source_route = 0

# Disable source routing and redirects
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.all.accept_source_route = 0

# Controls the System Request debugging functionality of the kernel
kernel.sysrq = 0

# Controls whether core dumps will append the PID to the core filename.
# Useful for debugging multi-threaded applications.
kernel.core_uses_pid = 1

# Basic TCP tuning
net.ipv4.tcp_keepalive_time = 600
net.ipv4.tcp_synack_retries = 1
net.ipv4.tcp_syn_retries = 1

# Disable netfilter on bridges.
# net.bridge.bridge-nf-call-ip6tables = 0
# net.bridge.bridge-nf-call-iptables = 0
# net.bridge.bridge-nf-call-arptables = 0

# RFC1337
net.ipv4.tcp_rfc1337 = 1

# Defines the local port range that is used by TCP and UDP
# to choose the local port
net.ipv4.ip_local_port_range = 1024  65535

# Log packets with impossible addresses for security
net.ipv4.conf.all.log_martians = 1

# Disable Explicit Congestion Notification in TCP
net.ipv4.tcp_ecn = 0

# Enable window scaling as defined in RFC1323
net.ipv4.tcp_window_scaling = 1

# Enable timestamps (RFC1323)
net.ipv4.tcp_timestamps = 1

# DISable select acknowledgments
net.ipv4.tcp_sack = 0

# Enable FACK congestion avoidance and fast restransmission
net.ipv4.tcp_fack = 1

# DISABLE Allows TCP to send "duplicate" SACKs
net.ipv4.tcp_dsack = 0


# No controls source route verification (RFC1812)
net.ipv4.conf.default.rp_filter = 0


# Make room for more TIME_WAIT sockets due to more clients,
# and allow them to be reused if we run out of sockets
# Also increase the max packet backlog
net.core.netdev_max_backlog = 20000

# TODO : change TCP_SYNQ_HSIZE in include/net/tcp.h
# to keep TCP_SYNQ_HSIZE*16<=tcp_max_syn_backlog
net.ipv4.tcp_max_syn_backlog = 65536
net.core.somaxconn = 65000

# Enable fast recycling TIME-WAIT sockets
# ubunt 18.04 not support
#net.ipv4.tcp_tw_recycle = 1

#/*打开快速回收time_wait状态的socket*/
net.ipv4.tcp_tw_reuse = 1

# tells the kernel how many TCP sockets that are not attached
# to any user file handle to maintain
net.ipv4.tcp_max_orphans = $max_orphan

# How may times to retry before killing TCP connection, closed by our side
net.ipv4.tcp_orphan_retries = 1

# how long to keep sockets in the state FIN-WAIT-2
# if we were the one closing the socket
net.ipv4.tcp_fin_timeout = 10

# maximum number of sockets in TIME-WAIT to be held simultaneously
net.ipv4.tcp_max_tw_buckets = $max_tw

# don't cache ssthresh from previous connection
net.ipv4.tcp_no_metrics_save = 1
net.ipv4.tcp_moderate_rcvbuf = 1

# Increase Linux autotuning TCP buffer limits
# Set max to 16MB for 1GE and 32M (33554432) or 54M (56623104) for 10GE
# Don't set tcp_mem itself! Let the kernel scale it based on RAM.
net.core.rmem_default = 16777216
net.core.wmem_default = 16777216
net.core.optmem_max = 40960

# increase Linux autotuning TCP buffer limits
net.ipv4.tcp_rmem = 4096 87380 16777216 
net.ipv4.tcp_wmem = 4096 65536 16777216

# increase TCP max buffer size
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216

net.core.netdev_max_backlog = 2500
net.core.somaxconn = 65000

# Discourage Linux from swapping idle processes to disk (default = 60)
vm.swappiness = 10

# Disable TCP slow start on idle connections
net.ipv4.tcp_slow_start_after_idle = 0

# You can monitor the kernel behavior with regard to the dirty
# pages by using grep -A 1 dirty /proc/vmstat
vm.dirty_background_ratio = $vm_dirty_bg_ratio
vm.dirty_ratio = $vm_dirty_ratio

# required free memory (set to 1% of physical ram)
vm.min_free_kbytes = $min_free

vm.overcommit_memory = 1

# system open file limit
fs.file-max = $file_max

# Core dump suidsafe
fs.suid_dumpable = 2 

kernel.core_pattern = core.%e.%p.%t
kernel.printk = 4 4 1 7
kernel.core_uses_pid = 1
kernel.sysrq = 0
kernel.msgmax = 65536
kernel.msgmnb = 65536

# This file (new in Linux 2.5) specifies the value at which PIDs wrap around
# (i.e., the value in this file is one greater than the maximum PID). The
# default value for this file, 32768, results in the same range of PIDs as
# on earlier kernels. On 32-bit platfroms, 32768 is the maximum value for
# pid_max. On 64-bit systems, pid_max can be set to any value up to 2^22
# (PID_MAX_LIMIT, approximately 4 million).
kernel.pid_max = 4194303

# Maximum shared segment size in bytes
# Controls the maximum shared segment size, in bytes
# On 64-bit systems, this is a theoretical 2^64bytes. 
# So the "theoretical limit" for SHMMAX is the amount of physical RAM that you have. 
# However, to actually attempt to use such a value could potentially lead to a situation where no system memory is available for anything else. 
# Therefore a more realistic "physical limit" for SHMMAX would probably be "physical RAM - 2Gb".
# 60 * 1024 * 1024 * 1024
kernel.shmmax = $shmmax

# Maximum number of shared memory segments in pages
kernel.shmall = $shmall

net.ipv4.tcp_congestion_control=${CONGESTION_CONTROL}

# ubuntu 18.04 not support
#net.nf_conntrack_max = 6553600
# net.netfilter.nf_conntrack_tcp_timeout_established = 20

#kernel.yama.ptrace_scope = 0

vm.dirty_background_ratio = 5
vm.dirty_ratio = 10

EOF

SAVEIFS=$IFS
IFS=$(echo -en "\n\b")
for LINE in $(grep -v '^#' ${CURRENT_SYSCTL_FILE} | grep . )
 do
    unset RESULT
    MY_VAR=$(echo ${LINE} | awk '{ print $1 }')
    RESULT=$(grep ${MY_VAR} /etc/sysctl.conf)
    if [ "${RESULT}" ]
     then
        echo "${MY_VAR} exists in new sysctl.conf, skipping"
     else
        echo "Adding ${MY_VAR} from old sysctl.conf to new"
        echo "${LINE}"
        echo "${LINE}" >> /etc/sysctl.conf
    fi
    
done
IFS=$SAVEIFS

##
# add mod ip_conntrack and bridge
##

# modprobe ip_conntrack
# modprobe bridge

/sbin/sysctl -p /etc/sysctl.conf
exit $?

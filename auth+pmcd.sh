#! /bin/sh

set -eu

# Initialize a little unprivileged pcp pmcd metrics collector
# process within this container; run this in a background subshell.
# No special signal handling or cleanup required.
(
# Setup pmcd to run in unprivileged mode of operation
. /etc/pcp.conf

PATH=$PATH:$PCP_BINADM_DIR
export PATH

# Configure pmcd with a minimal set of DSO agents
rm -f $PCP_PMCDCONF_PATH; # start empty
echo "# Name  ID  IPC  IPC Params  File/Cmd" >> $PCP_PMCDCONF_PATH;
echo "pmcd     2  dso  pmcd_init   $PCP_PMDAS_DIR/pmcd/pmda_pmcd.so"   >> $PCP_PMCDCONF_PATH;
echo "proc     3  dso  proc_init   $PCP_PMDAS_DIR/proc/pmda_proc.so"   >> $PCP_PMCDCONF_PATH;
echo "linux   60  dso  linux_init  $PCP_PMDAS_DIR/linux/pmda_linux.so" >> $PCP_PMCDCONF_PATH;
echo "prometheus 144 pipe binary notready python $PCP_PMDAS_DIR/prometheus/pmdaprometheus.python" >> $PCP_PMCDCONF_PATH;
rm -f $PCP_VAR_DIR/pmns/root_xfs $PCP_VAR_DIR/pmns/root_jbd2 $PCP_VAR_DIR/pmns/root_root $PCP_VAR_DIR/pmns/root
echo 'prometheus       144:*:*' > $PCP_VAR_DIR/pmns/prometheus
touch $PCP_VAR_DIR/pmns/.NeedRebuild

# allow unauthenticated access to proc.* metrics (default is false)
export PROC_ACCESS=1
export PMCD_ROOT_AGENT=0

# NB: we can't use the rc.pmcd script.  It assumes that it's run as root.
cd $PCP_VAR_DIR/pmns
./Rebuild
pmnsadd -n root prometheus

# Add our lone prometheus source
URLSD=$PCP_PMDAS_DIR/prometheus/urls.d
mkdir -p $URLSD
echo 'http://localhost:8089/metrics' > $URLSD/wit.url

cd $PCP_LOG_DIR

: "${PCP_HOSTNAME:=`hostname`}"
# possibly: filter pod name?

# We can log in plaintext to stdout also, even though Auth uses
# JSON.  pmcd is not chatty and only speaks up during errors.
exec /usr/libexec/pcp/bin/pmcd -l /dev/force-logging-to-stderr -f -A -H $PCP_HOSTNAME
) &
sleep 5 # give time for pmcd's startup messages, so it doesn't intermix with Auth's


exec bin/auth ${1+"$@"}

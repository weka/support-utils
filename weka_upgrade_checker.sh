#!/usr/bin/env bash

#version=1.0

# Colors
export NOCOLOR="\033[0m"
export CYAN="\033[0;36m"
export YELLOW="\033[1;33m"
export RED="\033[0;31m"
export GREEN="\033[1;32m"
export BLUE="\033[1;34m"

DIR='/tmp'
SSHCONF="$DIR/ssh_config"
LOG="$DIR/weka_upgrade_checker.log"
LARGE_CLUSTER=100 #Total number of hosts and clients in cluster
HOSTSPACE1=5000 #Minimum Free space on BACKEND in /weka specified in MBs
HOSTSPACE2=50 #Minimum Free space on BACKEND in /opt/weka/logs specified in MBs
HOSTSPACEMIN=25 #Absolute Minimum Free space on BACKEND in /opt/weka/logs specified in MBs "ONLY on small clusters"
CLIENTSPACE1=5000 #Minimum Free space on CLIENTS in /weka specified in MBs
CLIENTSPACE2=10 #Minimum Free space on CLIENTS in /opt/weka/logs specified in MBs
CLIENTSPACEMIN=5 #Absolute Minimum Free space on CLIENTS in /opt/weka/logs specified in MBs "ONLY on small clusters"

usage()
{
cat <<EOF
Usage: [-a for AWS insistence.]
Usage: [-c for skipping client upgrade checks.]
Usage: [-r  Check remote system. Enter valid ip address of a weka backend or client.]
This script checks Weka Clusters for Upgrade eligibility. On non-AWS insistences you must run the script as root user.
OPTIONS:
  -a  Creates a specific aws ssh config file for AWS insistence.
  -c  Skips client checks
  -r  Check remote system. Enter valid ip address of a weka backend or client.
EOF
exit
}

while getopts ":ashr:" opt; do
        case ${opt} in
          a ) AWS=1
	  ;;
          s ) SKPCL=true
          ;;
          r ) RHOST=${OPTARG}
          shift
          ;;
          h ) usage
	  ;;
          * ) echo "Invalid Option Try Again!"
	     usage
	  ;;
        esac
done

shift $((OPTIND -1))

if [ -z $AWS ]; then
cat > $SSHCONF <<EOF
BatchMode yes
Compression yes
CompressionLevel 9
StrictHostKeyChecking no
PasswordAuthentication no
ConnectTimeout 5
GlobalKnownHostsFile $DIR/global_known_hosts
IdentityFile /home/ec2-user/.ssh/support_id_rsa.pem
EOF
fi

if [ -z $AWS ]; then
  SSH='/usr/bin/ssh'
else
  SSH="/usr/bin/ssh -F /tmp/ssh_config"
fi

function logit() {
	echo -e "[${USER}][$(date)] - ${*}\n" >> ${LOG}
}

function LogRotate () {
local f="$1"
local limit="$2"
# Deletes old log file
	if [ -f "$f" ] ; then
		CNT=${limit}
		let P_CNT=CNT-1
	if [ -f "${f}"."${limit}" ] ; then
		rm "${f}"."${limit}"
	fi

# Renames logs .1 trough .3
while [[ $CNT -ne 1 ]] ; do
	if [ -f "${f}"."${P_CNT}" ] ; then
		mv "${f}"."${P_CNT}" "${f}"."${CNT}"
	fi
	let CNT=CNT-1
	let P_CNT=P_CNT-1
done

# Renames current log to .1
mv "$f" "${f}".1
echo "" > "$f"
fi
}

LogRotate $LOG 3

function NOTICE() {
echo -e "\n${CYAN}$1${NOCOLOR}"
logit "${CYAN}""[$1]""${NOCOLOR}"
}

function GOOD() {
echo -e "${GREEN}$1${NOCOLOR}"
logit "${GREEN}"[ SUCCESS ] "$1" "${NOCOLOR}"
}

function WARN() {
echo -e "${YELLOW}$1${NOCOLOR}"
logit "${YELLOW}"[ WARN ] "$1" "${NOCOLOR}"
}

function BAD() {
echo -e "${RED}$1${NOCOLOR}"
logit "${RED}"[ FAILED ] "$1" "${NOCOLOR}"
}

if [ ! -z "$RHOST" ]; then
  if ! [[ $RHOST =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
  BAD "Must enter a valid ip address, cannot continue."
	exit 1
  fi
fi

if [ -z "$AWS" ]; then
	if [ "$(id -u)" -ne 0 ]; then
	BAD "Must run as root user, cannot continue."
	exit 1
	fi
fi

NOTICE "WEKA USER LOGIN TEST"
WEKALOGIN=$(weka cluster nodes 2>&1 | awk '/error:/ {print $1}')
if [ "$WEKALOGIN" == "error:" ]; then
  BAD "Please login using weka user login first, cannot continue."
  exit 1
else
  GOOD "Weka user login successful."
fi

NOTICE "VERIFYING WEKA AGENT"
WEKAVERIFY=$(lsmod | grep -i weka)
if [ -z "$WEKAVERIFY" ]; then
  BAD "Weka is NOT installed on host or the container is down, cannot continue."
  exit 1
else
	WEKAERSION=$(weka status -J | awk '/"release":/ {print $2}' | tr -d ',""')
  GOOD "Weka verified $WEKAERSION."
fi

NOTICE "WEKA IDENTIFIED"
CLUSTER=$(weka status | grep cluster | awk '{print $2}')
UUID=$(weka status | grep cluster | awk '{print $3}')
CLUSTERSTATUS=$(weka status | grep status | head -n -1 | cut -d':' -f2)
IOSTATUS=$(weka status | grep status | tail -n +2 | cut -d':' -f2)
GOOD "Working on CLUSTER: $CLUSTER UUID: $UUID STATUS:${CLUSTERSTATUS}${IOSTATUS}."

#verify local container status otherwise commands will fail
NOTICE "VERIFYING WEKA LOCAL CONTAINER STATUS"
CONSTATUS=$(weka local ps --no-header -o name,running | grep -i default | awk '{print $2}')
if [ "$CONSTATUS" == "False" ]; then
  BAD "Weka local container is down cannot continue."
  exit
else
  GOOD "Weka local container is running."
fi

NOTICE "CHECKING FOR ANY ALERTS"
WEKAALERTS="$(weka status | awk '/alerts:/ {print $2}')"
if [ "$WEKAALERTS" != 0 ]; then
	WARN "$WEKAALERTS Weka alerts present, for additional detials see log ${LOG}."
  logit "weka alerts"
else
	GOOD "No Weka alerts present."
fi

NOTICE "CHECKING REBUILD STATUS"
REBUILDSTATUS="$(weka status rebuild -J | awk '/progressPercent/ {print $2}' | tr -d ',')"
if [ "$REBUILDSTATUS" != 0 ]; then
	BAD "Rebuilding, CURRENT PROGRESS:$REBUILDSTATUS%"
else
	GOOD "No rebuild in progress."
fi

NOTICE "VERIFYING WEKA BACKEND HOST STATUS"
WEKAHOST=$(weka cluster host --no-header -o id,hostname,status -b | grep -v UP)
if [ -z "$WEKAHOST" ]; then
  GOOD "Verified all backend host's are UP."
else
  WEKAHOST=$(weka cluster host -o id,hostname,status -b | grep -v UP)
	BAD "Failed backend hosts detected."
	WARN "\n$WEKAHOST\n"
fi

NOTICE "VERIFYING WEKA CLIENT(S) STATUS"
WEKACLIENT=$(weka cluster host --no-header -c | grep -v UP)
if [ -z "$WEKACLIENT" ]; then
  GOOD "Verified all client's are up."
else
  WEKACLIENT=$(weka cluster host -o id,hostname,status,mode -c | grep -v UP)
	BAD "Failed WEKA clients detected."
	WARN "\n$WEKACLIENT\n"
fi

NOTICE "VERIFYING WEKA NODES STATUS"
WEKANODES=$(weka cluster nodes | grep -v UP)
if [ -z "$WEKANODES" ]; then
  GOOD "Weka Nodes Status OK."
else
  WEKANODES=$(weka cluster nodes -o host,ips,status,role,mode | grep -v UP)
	BAD "Failed Weka Nodes Found."
	WARN "\n$WEKANODES\n"
fi

NOTICE "VERIFYING WEKA FS SNAPSHOTS UPLOAD STATUS"
WEKASNAP=$(weka fs snapshot --no-header -o stow,object | grep -i upload)
if [ -z "$WEKASNAP" ]; then
  GOOD "Weka snapshot upload status ok."
else
  WEKASNAP=$(weka fs snapshot --no-header -o name,stow,object)
	BAD "Following snapshots are being uploaded."
	WARN "\n$WEKASNAP\n"
fi

function check_ssh_connectivity() {
  if $SSH "$1" exit &>/dev/null; then
    GOOD "	[SSH PASSWORDLESS CONNECTIVITY CHECK] SSH connectivity test PASSED on Host $2 $1"
  else
    BAD "	[SSH PASSWORDLESS CONNECTIVITY CHECK] SSH connectivity test FAILED on Host $2 $1"
    return 1
  fi
}

function weka_agent_service() {
  if [ -z "$AWS" ]; then
    WEKAAGENTSRV=$(systemctl is-active weka-agent)
  else
    WEKAAGENTSRV=$(sudo service weka-agent status | cut -d' ' -f3)
  fi

  if [[ "$WEKAAGENTSRV" == "active" || "$WEKAAGENTSRV" == "RUNNING" ]]; then
		GOOD "	[WEKA AGENT SERVICE] Weka Agent Serivce is running on host $1"
	else
		BAD "	[WEKA AGENT SERVICE] Weka Agent Serivce is NOT running on host $1"
	fi
}

function diffdate() {
	local DIFF
  if [ -z "$1" ]; then
    BAD "	[TIME SYNC CHECK] Unable to determine time on Host $2."
    return 1
  fi

  DIFF=$(( $(date --utc '+%s') - $1 ))
  if [ "$DIFF" -lt 0 ]; then
    let DIFF="(( 0 - "$DIFF" ))"
  fi

  if [ "$DIFF" -gt 60 ]; then
    BAD "	[TIME SYNC CHECK] There is a time difference of grater than 60s between Host $(hostname) and $2, time difference of ${DIFF}s."
  else
    GOOD "	[TIME SYNC CHECK] Time in sync between host $(hostname) and $2 total difference ${DIFF}s."
  fi
}

function weka_container_status() {
  if [ -z "$1" ]; then
    BAD "	[WEKA CONTAINER STATUS] Unable to determine container status on Host $2."
    return 1
  fi

  if [ "$1" != "True" ]; then
    BAD "	[WEKA CONTAINER STATUS] Weka local container is down on Host $2."
  else
    GOOD "	[WEKA CONTAINER STATUS] Weka local container is running Host $2."
  fi
}

LOGSDIR1='/opt/weka'
LOGSDIR2='/opt/weka/logs'
TOTALHOSTS=$(weka cluster host --no-header | wc -l)
function freespace_backend() {
  if [ -z "$1" ]; then
    BAD "	[FREE SPACE CHECK] Unable to determine free space on Host $3."
    return 1
  fi

  if [ "$1" -lt "$HOSTSPACE1" ]; then
    BAD "	[FREE SPACE CHECK] Host $3 has less than recommended free space of ~$(($1 / 1000))GB in $LOGSDIR1."
    WARN "	[REDUCE TRACES CAPACITY & INCREASE DIRECTORY SIZE] https://stackoverflow.com/c/weka/questions/1785/1786#1786"
  else
    GOOD "	[FREE SPACE CHECK] Host $3 has recommended free space of ~$(($1 / 1000))GB in $LOGSDIR1."
  fi

  if [[ "$TOTALHOSTS" -ge "$LARGE_CLUSTER" && "$2" -lt "$HOSTSPACE2" ]]; then
    BAD "	[FREE SPACE CHECK] Host $3 has less than recommended free space of $2MB in $LOGSDIR2"
    WARN "	[REDUCE TRACES CAPACITY & INCREASE DIRECTORY SIZE] https://stackoverflow.com/c/weka/questions/1785/1786#1786"
    return 1
  fi

  if [ "$2" -lt "$HOSTSPACEMIN" ]; then
    BAD "	[FREE SPACE CHECK] Host $3 has Less than Recommended Free Space of $2MB in $LOGSDIR2."
    WARN "	[REDUCE TRACES CAPACITY & INCREASE DIRECTORY SIZE] https://stackoverflow.com/c/weka/questions/1785/1786#1786"
  else
    GOOD "	[FREE SPACE CHECK] Host $3 has Recommended Free Space of $2MB in $LOGSDIR2."
  fi
}

function upgrade_container() {
  if [ -z "$1" ]; then
    GOOD "	[UPGRADE CONTAINER CHECK] No upgrade containers found on Host $2."
  else
    BAD "	[UPGRADE CONTAINER CHECK] Upgrade container found on Host $2 status $1."
  fi
}

function weka_mount() {
  if [ -z "$1" ]; then
    GOOD "	[CHECKING WEKA MOUNT] NO Mount point on '/weka' found on Host $2."
  else
    BAD "	[CHECKING WEKA MOUNT] Mount point on '/weka' found on Host $2."
  fi
}

function freespace_client() {
  if [ -z "$1" ]; then
    BAD "	[FREE SPACE CHECK] Unable to Determine Free Space on Host $3."
    return 1
  fi

  if [ "$1" -lt "$CLIENTSPACE1" ]; then
    BAD "	[FREE SPACE CHECK] Host $3 has Less than Recommended Free Space of $(($1 / 1000))GB in $LOGSDIR1."
    WARN "	[REDUCE TRACES CAPACITY & INCREASE DIRECTORY SIZE] https://stackoverflow.com/c/weka/questions/1785/1786#1786"
  else
    GOOD "	[FREE SPACE CHECK] Host $3 has Recommended Free Space of $(($1 / 1000))GB in $LOGSDIR1."
  fi

  if [[ "$TOTALHOSTS" -ge "$LARGE_CLUSTER" && "$2" -lt "$CLIENTSPACE2" ]]; then
    BAD "	[FREE SPACE CHECK] Host $3 has Less than Recommended Free Space of $2MB in $LOGSDIR2"
    WARN "	[REDUCE TRACES CAPACITY & INCREASE DIRECTORY SIZE] https://stackoverflow.com/c/weka/questions/1785/1786#1786"
    return 1
  fi

  if [ "$2" -lt "$CLIENTSPACEMIN" ]; then
    BAD "	[FREE SPACE CHECK] Host $3 has Less than Recommended Free Space of $2MB in $LOGSDIR2."
    WARN "	[REDUCE TRACES CAPACITY & INCREASE DIRECTORY SIZE] https://stackoverflow.com/c/weka/questions/1785/1786#1786"
  else
    GOOD "	[FREE SPACE CHECK] Host $3 has Recommended Free Space of $2MB in $LOGSDIR2."
  fi
}

function client_web_test() {
  WEBTEST=$(curl -sL -w "%{http_code}" "http://www.google.com/" -o /dev/null)
  if [ "$WEBTEST" = 200 ]; then
    GOOD "	[HTTP CONNECTIVITY TEST] HTTP connectivity is up."
  elif [  "$WEBTEST" = 5 ]; then
    WARN "	[HTTP CONNECTIVITY TEST] Blocked by Web Proxy."
  else
    BAD "	[HTTP CONNECTIVITY TEST] Internet access maybe down."
  fi
}

BACKEND=$(weka cluster host --no-header -b | awk '{print $3}')
CLIENT=$(weka cluster host --no-header -c | awk '{print $3}')

function backendloop() {
local CURHOST REMOTEDATE WEKACONSTATUS RESULTS1 RESULTS2 UPGRADECONT MOUNTWEKA
  CURHOST=$(weka cluster host --no-header -o hostname,ips | grep -w "$1" | awk '{print $1}')
  NOTICE "VERIFYING SETTINGS ON BACKEND HOST $CURHOST"
	check_ssh_connectivity "$1" "$CURHOST" || return

  weka_agent_service "$CURHOST"

  REMOTEDATE=$($SSH "$1" "date --utc '+%s'")
  diffdate "$REMOTEDATE" "$CURHOST"

  WEKACONSTATUS=$($SSH "$1" weka local ps --no-header -o name,running | grep -i default | awk '{print $2}')
	weka_container_status "$WEKACONSTATUS" "$CURHOST"

  RESULTS1=$($SSH "$1" df -m "$LOGSDIR1" | awk '{print $4}' | tail -n +2)
  RESULTS2=$($SSH "$1" df -m "$LOGSDIR2" | awk '{print $4}' | tail -n +2)
	freespace_backend "$RESULTS1" "$RESULTS2" "$CURHOST" || return

  UPGRADECONT=$($SSH "$1" "weka local ps --no-header -o name,running | awk '/upgrade/ {print $2}'")
	upgrade_container "$UPGRADECONT" "$CURHOST"

  MOUNTWEKA=$($SSH "$1" "mountpoint -qd /weka/")
	weka_mount "$MOUNTWEKA" "$CURHOST"
}

function clientloop() {
  local CURHOST REMOTEDATE WEKACONSTATUS RESULTS1 RESULTS2 UPGRADECONT MOUNTWEKA
    CURHOST=$(weka cluster host --no-header -o hostname,ips | grep -w "$1" | awk '{print $1}')
    NOTICE "VERIFYING SETTINGS ON CLIENTs HOST $CURHOST"
	  check_ssh_connectivity "$1" "$CURHOST" || return

    weka_agent_service "$CURHOST"

    REMOTEDATE=$($SSH "$1" "date --utc '+%s'")
    diffdate "$REMOTEDATE" "$CURHOST"

    WEKACONSTATUS=$($SSH "$1" weka local ps --no-header -o name,running | grep -i client | awk '{print $2}')
	  weka_container_status "$WEKACONSTATUS" "$CURHOST"

    RESULTS1=$($SSH "$1" df -m "$LOGSDIR1" | awk '{print $4}' | tail -n +2)
    RESULTS2=$($SSH "$1" df -m "$LOGSDIR2" | awk '{print $4}' | tail -n +2)
	  freespace_client "$RESULTS1" "$RESULTS2" "$CURHOST" || return

	  client_web_test

    UPGRADECONT=$($SSH "$1" "weka local ps --no-header -o name,running | awk '/upgrade/ {print $2}'")
	  upgrade_container "$UPGRADECONT" "$CURHOST"

    MOUNTWEKA=$($SSH "$1" "mountpoint -qd /weka/")
	  weka_mount "$MOUNTWEKA" "$CURHOST"
}

main() {
KHOST=$(weka cluster host -o ips,mode | grep -w "$RHOST" | awk '{print $2}')
if [ -z "$KHOST" ]; then
  BAD "IP Address invalid, enter an ip address of a known Weka client or host."
  exit 1
elif [[ "$RHOST" && "$KHOST" == "backend" ]]; then
  for ip in ${KHOST}; do
    backendloop "$RHOST" || continue
  done
  exit
fi

KHOST=$(weka cluster host -o ips,mode | grep -w "$RHOST" | awk '{print $2}')
if [ -z "$KHOST" ]; then
  BAD "IP Address invalid, enter an ip address of a known Weka client or host."
  exit 1
elif [[ "$RHOST" && "$KHOST" == "client" ]]; then
  for ip in ${KHOST}; do
    clientloop "$RHOST" || continue
  done
  exit
fi

for ip in ${BACKEND}; do
  backendloop "$ip" || continue
done

if [ "$SKPCL" == "true" ]; then
  NOTICE "SKIPPING CLIENTs UPGRADE CHECKs"
else
  for ip in ${CLIENT}; do
    clientloop "$ip" || continue
  done
fi
}

main "$@"

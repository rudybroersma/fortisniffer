#!/bin/bash
#
# CTNET Packet Capture Tee Script
#
# Author:  Rudy Broersma <r.broersma@ctnet.nl>
# Version: v1.1 - February 2024
#
# ChangeLog:
# 29-02-2024	Rudy	Removed default filter, as it prevented entering enter to capture without any filters
# 04-04-2024	Rudy	Add connection test
#
#
function jumpto
{
    label=$1
    cmd=$(sed -n "/$label:/{:a;n;p;ba};" $0 | grep -v ':$')
    eval "$cmd"
    exit
}

MYPID=$$
DEFAULTIP=10.255.255.151
DEFAULTUSER=CTNET
DEFAULTPASSWORD=''
#DEFAULTFILTER="diag sniffer packet any 'icmp'"
DEFAULTINTF=any
DEFAULTFILTER="icmp"
start=${1:-start}
jumpto "$start"  # GOTO start: by default

############ Test some shit and make soms preps
mkdir -p ~/complete
mkdir -p ~/sessions
if [ ! -f "/usr/bin/sshpass" ]; then
  echo "ERROR: sshpass is not installed. Please run 'apt-get update && apt-get install sshpass'"
  exit
fi
########### Done doing stuff

clear
echo ""
echo "CTNET Packet Capture Script"
echo ""
echo "Options:"
echo "1) Start new sniffer"
echo "2) Terminate running session"
echo "3) Live capture"
echo "4) Exit"
echo ""
#menuoption:
read -p "[1..4] ?: " MENUOPTION
echo ""
if   [ "${MENUOPTION}" = "1" ]; then jumpto ipaddress
elif [ "${MENUOPTION}" = "2" ]; then jumpto existingsessions
elif [ "${MENUOPTION}" = "3" ]; then jumpto capturesession
elif [ "${MENUOPTION}" = "4" ]; then exit
fi
jumpto menuoption

#ipaddress:
read -p "Enter FortiGate IP Address [$DEFAULTIP]: " FORTIIP
FORTIIP=${FORTIIP:-$DEFAULTIP}
if   [ "$DEFAULTIP" = "$FORTIIP" ]; then jumpto username; fi

#verifyip:
echo "You entered [$FORTIIP]. Is this correct? [y/n]"
read -n 1 -s TRUTHVALUE

if   [ "${TRUTHVALUE,,}" = "y" ]; then jumpto username
elif [ "${TRUTHVALUE,,}" = "n" ]; then jumpto ipaddress
fi
echo "Invalid input. Try again..."
jumpto verifyip

#username:
read -p "Enter username [$DEFAULTUSER]: " USERNAME
USERNAME=${USERNAME:-$DEFAULTUSER}
if   [ "$DEFAULTUSER" = "$USERNAME" ]; then jumpto password; fi

#verifyusername:
echo "You entered [$USERNAME]. Is this correct? [y/n]"
read -n 1 -s TRUTHVALUE

if   [ "${TRUTHVALUE,,}" = "y" ]; then jumpto password
elif [ "${TRUTHVALUE,,}" = "n" ]; then jumpto username
fi
echo "Invalid input. Try again..."
jumpto verifyusername

#password:
read -s -p "Enter password: " SSHPASS
echo ""

#interface:
read -p "Enter interface [$DEFAULTINTF]: " INTF
INTF=${INTF:-$DEFAULTINTF}
if   [ "$DEFAULTINTF" = "$INTF" ]; then jumpto filter; fi

#verifyinterface:
echo "You entered [$INTF]. Is this correct? [y/n]"
read -n 1 -s TRUTHVALUE

if   [ "${TRUTHVALUE,,}" = "y" ]; then jumpto filter
elif [ "${TRUTHVALUE,,}" = "n" ]; then jumpto interface
fi
echo "Invalid input. Try again..."
jumpto interface

#filter:
read -p "Enter filter (eg: icmp): " FILTER
#FILTER=${FILTER:-$DEFAULTFILTER}
#if   [ "$DEFAULTFILTER" = "$FILTER" ]; then jumpto startsniffer; fi

#verifyfilter:
echo "You entered [$FILTER]. Is this correct? [y/n]"
read -n 1 -s TRUTHVALUE

if   [ "${TRUTHVALUE,,}" = "y" ]; then jumpto testconnection
elif [ "${TRUTHVALUE,,}" = "n" ]; then jumpto filter
fi
echo "Invalid input. Try again..."
jumpto filter

#testconnection:
echo -n "Testing SSH connection... "
export SSHPASS
timeout 3 /usr/bin/sshpass -e ssh -o "StrictHostKeyChecking=no" $USERNAME@$FORTIIP "exit" 2>&1 > /dev/null
if [ $? -eq 0 ];
then
  echo "OK!"
  jumpto startsniffer
else
  echo "FAILED! Verify IP/hostname, credentials and if SSH access has been enabled on the FortiGate"
  exit
fi


#startsniffer:
echo "Starting sniffer in the background. Run this script again for status and live capture"
export SSHPASS
screen -S $MYPID -d -m bash -c "/usr/bin/sshpass -e ssh -o \"StrictHostKeyChecking=no\" $USERNAME@$FORTIIP \"diag sniffer packet '$INTF' '$FILTER' 6 0 1\" 2>&1 | tee ~/sessions/$MYPID.txtpcap; perl ~/fgt2eth.pl -in ~/sessions/$MYPID.txtpcap -out ~/complete/$MYPID.pcap"
if [ $? -eq 0 ];
then
  echo "Sniffer started succesfully"
  echo ""
  echo "Process ID is $MYPID. Keep this number for future reference."
else
  echo "Sniffer returned error. PANIEK!"
fi
exit


#existingsessions:
LIJST=`screen -list` 
RETVAL=$?

if [ $RETVAL -eq 0 ];
then
  echo "List of active processes (recent to old): "
  echo ""
  ls -1 "/run/screen/S-$USER" | awk -F '.' '{ print $2 }'
  echo "q (quit)"
  echo ""
  read -p "Enter process ID you wish to terminate or q to quit: " PIDSELECT
  #if [ "${PIDSELECT,,}" = "q" ]; then exit; fi
  echo ""
  echo "Terminating session $PIDSELECT. Your pcap will be stored in ~/complete/$PIDSELECT.pcap"
  echo "With a good terminal emulator (like SecureCRT) you can download the file using the command 'sz ~/complete/$PIDSELECT.pcap'"
  echo ""
  echo "Alternatively you can use an SCP tool like WinSCP"
  echo ""
  screen -S $PIDSELECT -p 0 -X stuff "^C" > /dev/null
  exit
else
  echo "No sessions running"
  sleep 2
  jumpto start
fi


#capturesession:
LIJST=`screen -list`
RETVAL=$?

if [ $RETVAL -eq 0 ];
then
  echo "List of active processes (recent to old): "
  echo ""
  ls -1 "/run/screen/S-$USER" | awk -F '.' '{ print $2 }'
  echo "q (quit)"
  echo ""
  read -p "Enter process ID you wish to terminate or q to quit: " PIDSELECT
  #if [ "${PIDSELECT,,}" = "q" ]; then exit; fi
  echo ""
  echo "Running tail on active session. Terminate with CTRL+C"
  echo -n "Starting in 4 seconds... "
  sleep 1; echo -n "4.. "
  sleep 1; echo -n "3.. "
  sleep 1; echo -n "2.. "
  sleep 1; echo -n "1.. "
  echo ""
  tail -f ~/sessions/$PIDSELECT.txtpcap
  exit
else
  echo "No sessions running"
  sleep 2
  jumpto start
fi



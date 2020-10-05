#!/bin/bash

STORM_ROOT_LOCATION=/usr/bin/storm
STORM_TMP_LOCATION=/tmp/storm
STORM_SERVICE_NAME=storm.service
STORM_PROCESS_NAME=storm

if pidof "$STORM_PROCESS_NAME" &> /dev/null; then
  
  echo "[!] IPStorm is running on your system."
  echo "# Cleaning machine from IPStorm..."
  sudo rm -rf "$STORM_ROOT_LOCATION" "$STORM_TMP_LOCATION"
  sudo systemctl stop storm.service &> /dev/null
  sudo pkill -9 "$STORM_PROCESS_NAME" &> /dev/null
  
  if pidof "$STORM_PROCESS_NAME"; then
	echo "# Error in killing IPStorm. Please contact Intezer for support"
  else
	echo "# Your machine is now clean from IPStrom malware. Make sure to harden your system."
 fi
 
 else
	echo "# IPStorm is not running on your system"
fi



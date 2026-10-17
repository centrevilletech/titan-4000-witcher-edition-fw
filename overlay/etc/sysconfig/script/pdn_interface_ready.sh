#!/bin/sh

if [ "$2" = "READY" ]; then
	echo ""
	echo "PDN $1 UP"
	echo ""
	if [ -x /etc/sysconfig/script/passthru-fix.sh ]; then
		/etc/sysconfig/script/passthru-fix.sh READY "$1"
	fi
fi

# libltesdk.so runs "pdn_interface_ready.sh <if> RELEASE" on PDN down.
# Stock script looked for RESET; accept both.
if [ "$2" = "RESET" ] || [ "$2" = "RELEASE" ]; then
	echo ""
	echo "PDN $1 DOWN"
	echo ""
	if [ -x /etc/sysconfig/script/passthru-fix.sh ]; then
		/etc/sysconfig/script/passthru-fix.sh RESET "$1"
	fi
fi

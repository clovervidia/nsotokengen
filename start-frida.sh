#! /system/bin/sh
echo starting frida-server
killall frida-server
nohup /data/local/tmp/frida-server > /dev/null 2>&1 &
echo frida-server started

echo nsotokengen > /sys/power/wake_lock

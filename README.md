# smasolarbluetoothdebugtool
Debug tool for comms with SMA Solar inverters

Run on Linux devices...
hcitool scan

Scanning ...
        00:80:25:1D:AC:53       SMA001d SN: 2120051742 SN2120051742


Then use bluetooth address and inverter passcode to connect and scan...

python SMASolarInverterPacketDebug.py 00:80:25:1D:AC:53 0000 > logfile

Contents of logfile hold the debug information

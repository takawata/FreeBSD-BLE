# FreeBSD Bluetooth low energy, LE, tools

This repository contains Bluetooth LE related userland tools for
FreeBSD. Kernel support was already committed to main trunk.

## Utilities available

* le_enable <br>
	Enable and scan Bluetooth LE device. If the Bluetooth address is given
	as argument, connect attribute channnel and fetch all
	attribute informations and value as long as it can.

* lepair <br>
	Pairing tool. Give the Bluetooth address as an argument. It negotiates
	pairing parameter with the device through Security Manager Protocol.
	And requests or displays the PIN number. If PIN code authentication is
	valid, show the encryption parameters: EDIV, Random number, 128bit key.

* lesecd <br>
	Bluetooth LE security daemon. Read the configuration file hcsecd.conf
	in current directory. It starts encryption for incoming BLE
	connection request.

* lehid <br>
	Bluetooth LE client program.
	lehid 11:22:33:44:55:66
	will try to connect peer BLE device that have public address
	11:22:33:44:55:66.
	With -s option, wait channel connection until encryption was
	successfully set up.
	With -r option it will trying to connect random address.
	Client program example is batt.c.
	It supports Bluetooth HOGP mouse. If you want to use it,
	you have to pair by lepair and configure and run lesecd.

## How to compile and install under FreeBSD
<pre>
make all
make install
</pre>
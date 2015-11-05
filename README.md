FreeBSD Bluetootl LE Tool

This is Bluetooth LE related userland tools for FreeBSD.
Kernel support was already committed to main trunk.

This consist of 3 programs.

le_enable
	Enable and scan Bluetooth LE device. If Bluetooth address is given as
	argument, connect attribute channnel and fetch all attribute
	informations and value as long as it can.
	With -s option, wait channel connection until encryption was
	successfully set up. For now, public address only supported.

lepair
	Pairing tool. Give Bluetooth address as argument. It negosiates
	pairling parameter with the device through Security Manager Protocol.
	And request or display PIN number. If PIN code authentication is
	valid, show encryption parameter: EDIV, Random number, 128bit key.

lesecd
	Bluetooth LE security Daemon. read configuration file hcsecd.conf
	in current directory. It starts encryption for incoming
	BLE connection request.
	


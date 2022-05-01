	
	LOAD OBJ FILE:
	- ip link set dev enp0s9 xdpgeneric obj xdp_pass_kern.o sec xdp

	SHOW INTERFACE INFO:
	- ip link show dev enp0s9

	REMOVE XDP PROG FROM INTERFACE:
	- ip link set dev enp0s9 xdpgeneric off

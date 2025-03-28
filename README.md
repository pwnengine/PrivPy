# PrivPy
Python Script That Takes Advantage of Windows Services For Privileged Escalation. 

https://i.ibb.co/XrDwTd2W/2025-03-28-13-39.png

## Why
I had the idea of a python script that can easily identify misconfigured Windows service binary permissions.
I wanted the script to not rely on any 3rd party modules and run with just python installed, but ultimately I caved and used pefile for binary injection.
This script allows you to list all services on a target and shows what the binary is run as, the path to the binary, and the permission you have to it.
It can automatically determine if the binary is exploitable and indicates as so in red text.
Outside of listing vulnerable service binaries it can be used to find code caves inside of any pe with the '''--find-caves''' flag along with the pathname to a pe and the minimum size of bytes.
With said found code caves you can inject shellcode payloads of your choosing in a service binary or any binary with the '''--write-shellcode''' flag along with the binary pathname.






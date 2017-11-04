This program could be run by first typing "make"

This will compile the program and you will be able to run it by typing: sudo ./bin/mydump <args>

<args> pretain to whatever arguments you would pass the program to run such as -i eth0 -r file.

*********Sometimes when using devices rather than files it might take up to two minutes for the program to start capturing packets. Maybe I wasn't receiving any packets during that time.

I used the getopt to parse the arguments. I used the built in linux structs for ip, tcp, udp and icmp headers which allowed me to get the required information for printing. As far as filtering packets based on the expression I simply created another function that god rid of unprintable characters by putting printiable characters into another buffer and then calling strstr on the new;y created buffer. The include file in the include folder contain all the functions that I used throughout the program.

Example output:

sudo ./bin/mydump -r ../hw1.pcap

2013-01-13 03:31:19.154432 C4:3D:C7:17:6F:9B -> 00:0C:29:E9:94:8E type: 0x800 len 207
92.240.68.152:17260 -> 192.168.0.200:80 TCP
00000   47 45 54 20 68 74 74 70  3a 2f 2f 65 63 78 2e 69    GET http://ecx.i
00016   6d 61 67 65 73 2d 61 6d  61 7a 6f 6e 2e 63 6f 6d    mages-amazon.com
00032   2f 69 6d 61 67 65 73 2f  49 2f 34 31 6f 5a 31 58    /images/I/41oZ1X
00048   73 69 4f 41 4c 2e 5f 53  4c 35 30 30 5f 41 41 33    siOAL._SL500_AA3
00064   30 30 5f 2e 6a 70 67 20  48 54 54 50 2f 31 2e 31    00_.jpg HTTP/1.1
00080   0a 55 73 65 72 2d 41 67  65 6e 74 3a 20 77 65 62    .User-Agent: web
00096   63 6f 6c 6c 61 67 65 2f  31 2e 31 33 35 61 0a 48    collage/1.135a.H
00112   6f 73 74 3a 20 65 63 78  2e 69 6d 61 67 65 73 2d    ost: ecx.images-
00128   61 6d 61 7a 6f 6e 2e 63  6f 6d 0a 0a 00             amazon.com...

2013-01-13 03:31:19.163445 00:0C:29:E9:94:8E -> C4:3D:C7:17:6F:9B type: 0x800 len 81
192.168.0.200:37605 -> 194.168.4.100:53 UDP
00000   45 00 00 43 00 00 40 00  40 11 b2 2d c0 a8 00 c8    E..C..@.@..-....
00016   c2 a8 04 64 92 e5 00 35  00 2f 4e 76 31 20 01 00    ...d...5./Nv1 ..
00032   00 01 00 00 00 00 00 00  03 65 63 78 0d 69 6d 61    .........ecx.ima
00048   67 65 73 2d 61 6d 61 7a  6f 6e 03 63 6f 6d 00 00    ges-amazon.com..
00064   01 00 01                                            ...




sudo ./bin/mydump -s icmp -r ../hw1.pcap

2013-01-14 17:42:31.752299 C4:3D:C7:17:6F:9B -> 00:0C:29:E9:94:8E type: 0x800 len 90
1.234.31.20 -> 192.168.0.200 ICMP
00000   45 00 00 4c eb 4a 00 00  2f 01 bd f8 01 ea 1f 14    E..L.J../.......
00016   c0 a8 00 c8 03 0a 95 2a  00 00 00 00 45 00 00 30    .......*....E..0
00032   00 00 40 00 2e 06 6a 5a  c0 a8 00 c8 01 ea 1f 14    ..@...jZ........
00048   00 50 7b 81 bd cd 09 c6  3a 35 22 b0 70 12 39 08    .P{.....:5".p.9.
00064   11 ab 00 00 02 04 05 b4  01 01 04 02                ............




sudo ./bin/mydump -i eth0

2017-10-16 03:56:28.158008 08:00:27:E9:63:1B -> 52:54:00:12:35:03 type: 0x800 len 66
10.0.2.15:44179 -> 10.0.2.3:53 UDP
00000   45 00 00 34 88 9c 40 00  40 11 9a 0b 0a 00 02 0f    E..4..@.@.......
00016   0a 00 02 03 ac 93 00 35  00 20 18 43 0d 55 01 00    .......5. .C.U..
00032   00 01 00 00 00 00 00 00  06 70 75 70 70 65 74 00    .........puppet.
00048   00 1c 00 01                                         ....

2017-10-16 03:56:28.171323 52:54:00:12:35:02 -> 08:00:27:E9:63:1B type: 0x800 len 66
10.0.2.3:53 -> 10.0.2.15:44179 UDP
00000   45 00 00 34 a3 a6 00 00  40 11 bf 01 0a 00 02 03    E..4....@.......
00016   0a 00 02 0f 00 35 ac 93  00 20 4b 9a 0d 55 81 80    .....5... K..U..
00032   00 01 00 00 00 00 00 00  06 70 75 70 70 65 74 00    .........puppet.
00048   00 1c 00 01                                         ....

2017-10-16 03:56:28.171517 08:00:27:E9:63:1B -> 52:54:00:12:35:02 type: 0x800 len 74
10.0.2.15:58239 -> 92.242.140.21:8140 TCP


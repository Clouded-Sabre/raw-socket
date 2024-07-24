# rawsocket
Golang Rawsocket implementation on Windows and macos mimicking net.IPConn on Linux.
Due to some critical limitations of official raw socket implementation on Windows and macos, net.IPConn does not really work on Windows and macos.
This raw socket implementation making use of Gopacket and creates similar net.IPConn function such as DialIP, Read, Write, SetReadDeadline, and Close so that you can use it in similar way as Linux net.IPConn.
Currently we've only implemented client side functions. Server side functions may be implemented in the future.
As required by Gopacket, you need to install Npcap on Windows and libpcap on macos.

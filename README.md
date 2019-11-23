# Project

## Files
```
README.md: This readme file
Vagrantfile: Vagrantfile for creating VMs
project/: Starter code
project/Makefile: Makefile to build your code
project/gen_graph.py: Example code to generate graph of unacked packets vs. time
project/src: C files for your transport protcol (CMU TCP) implementation
project/src/backend.c: Code for emulating packet buffering and sending
project/src/client.c: Code for the client side of CMU TCP
project/src/server.c: Code for the server side of CMU TCP
project/src/cmu_tcp.c: Code for reading, writing, opening, and closing CMU TCP sockets
project/src/cmu_packet.c: Code for creating and parsing CMU TCP packets
project/inc: Header files for CMU TCP imeplementation
project/inc/backend.h: Defines API for handing packet buffering and sending
project/inc/cmu_tcp.h: Defines API for CMU TCP scockets. DO NOT CHANGE THESE FUNCTION SIGNATURES.
project/inc/cmu_packet.h: Defines CMU TCP header format, CMU TCP packet data structure, and API for creating and buffering packets
project/inc/global.h: Defines some global variables as well as socket and window data structures
project/inc/grading.h: Defines variables the TA's will use to test your implementation
project/utils/: Utilities to help you with testing your code
project/utils/capture_packets.sh: A simple program showing how you can start and stop packet captures,as well as analyze packets using tshark.
project/utils/tcp.lua: A Lua plugin so Wireshark can dissect CMU TCP packets
project/test/: Example testing code
project/test/test_cp1.py: Code using pytest to test your CMU TCP implementation
project/test/testing_server.c: Code for starting a testing CMU TCP server that listens for data from initiator, and tries to send a file
project/test/test.pcap: Example pcap file that starter test code uses
project/test/random.input: You can generate this file by running make test to generate this random 1M file that you can use to test file transfers
```

## Install Vagrant & VirutalBox
If you are having trouble running Vagrant  make sure your versions of Vagrant and VirtualBox are up to date.


## Run VM
```
vagrant up
```

To ssh into the server machine:
```
vagrant ssh server
```

To ssh into the client machine:
```
vagrant ssh client
```

The starter code will be synced to the VMs in thier vagrant folder:
```
vagrant@server: cd /vagrant/project
```

## tcconfig
You can view the network settings on a vm by running
```
vagrant@server: tcshow enp0s8
```

See the tcconfig documentation for information on how to use tcconfig to modify the characteristics
for the network between the two VMs.

## gen_graph.py

To run gen_graph.py, use python 3:
```
python3 gen_graph.py
```

## capture_packets.sh
You can generate submit.pcap by running the following commands:

Start the server and the tcpdump:
```
vagrant@server:/vagrant/project$ make
vagrant@server:/vagrant/project$ utils/capture_packets.sh start submit.pcap
vagrant@server:/vagrant/project$ server
```

Start the client:
```
vagrant@client:/vagrant/project$ client
```

When the server and client finishes running, stop the packet capture on the server:
```
vagrant@server:/vagrant/project$ utils/capture_packets.sh stop submit.pcap
```

You can also use ```capture_packets.sh``` to generate a CSV describing packets in PCAP:
```
vagrant@server:/vagrant/project$: utils/capture_packets.sh analyze submit.pcap
```

## tcp.lua
```capture_packets.sh``` analyze functions shows how you can use this Lua plugin to
view CMU packets.

You can use tcp.lua to view packets in the Wireshark GUI by adding it to the Wireshark
plugins folder on your computer.


## Running pytest tests
Before running pytest you should generate submit.pcap, as the tests are run on the PCAP
file.

You can run pytest tests by running:
```
vagrant@server:/vagrant/project/ make test
```

All of the tests but the last one should pass on the starter code. 

These tests are an example of how you can test your code. Some of the tests do nothing.
YOU SHOULD EXPAND THESE TESTS! (Or write tests using your favorite testing tool!)
```make test``` must be able to run your test code.

## A note about CryptographyDeprecationWarning

When you run ```vagrant up``` or ``make test``` you will see this warning. The initial tests you're given
use a tool called fabric to run commands on the different VMs and it produces this warning. You can ignore it.

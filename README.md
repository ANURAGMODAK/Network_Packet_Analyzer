**Install Npcap:** Download and install Npcap from the official Npcap website (https://npcap.org/). Make sure to download the appropriate version for your system architecture (32-bit or 64-bit) and follow the installation instructions provided.
After installing Npcap, restart your system to ensure that the changes take effect properly.
As mentioned earlier, ensure that you run the command prompt or terminal as an administrator before executing the Python script. Right-click on the command prompt or terminal icon and select "Run as administrator".
Once you've installed Npcap and restarted your system, run your Python script, passing the network interface as an argument: **python packet_sniffer.py <interface>**
<interface> --> Your current network interface in use. To find so for Windows machine in cmd type "ipconfig" and for Linux machines type "ifconfig" in terminal.

For example if my <interface> is "Ethernet 2". The running script for the above should be: **python packet_sniffer.py "Ethernet 2"**

# Saddam-new
Saddam-new is a DRDoS tool based on [Saddam](https://github.com/OffensivePython/Saddam).

![image](http://upload.ouliu.net/i/201811071712128bkr1.jpeg)
### Compared with Saddam, there are several changes:

1. Support for CLDAP protocol.
2. After benchmark, you can save the still available IPs to a new txt file.
3. Command line options changed.
4. Some other changes in code.

### In addition, you need to pay attention to the following points:

1. `Pinject.py` has been placed in the same directory, so you don't need to download it anymore.
2. You need to have root privileges to run this tool. Of course, Saddam is also.
3. After testing, the tool seems to be used only in the case of a wired network connection. When using a wireless connection, the data packet will be corrected (forced to add a IP header), and I don't understand how to solve it at present. Do you have a solution?

**Thanks to Saddam and @OffensivePython.**

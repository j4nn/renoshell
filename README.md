# bindershell - temp root shell using CVE-2019-2215 for sony xperia xz1/xz1c/xzp phones

This is forked from [iovyroot by dosomder](https://github.com/dosomder/iovyroot.git),
replacing the kernel space read/write primitives with those from CVE-2019-2215 su98.c exploit.
The original su98.c did not properly patch security->sid and security->osid and did not include KASLR bypass.
To get the sid and osid patching, it was easier to port just the primitives from su98 here.
This code is compatible with several oreo firmwares of xperia xz1/xz1c/xzp phones (yoshino platform).

# renoshell - rename/notify temp root shell

A get root shell tool using remote arbitrary kernel space read and write api,
which needs to be provided by another tool with an actual kernel exploit.
This is forked from [iovyroot by dosomder](https://github.com/dosomder/iovyroot.git),
replacing dependency on a specific vulnerability with a remote arbitrary
kernel space read/write primitives.
The code was debugged, fixed and adapted to be compatible with 4.4.74 kernel
from xperia xz1c 47.1.A.2.324 android oreo firmware (includes selinux bypass).

dell-bmc-firmware
=================

Tools for extracting and modifying the firmware of the baseboard management controller (BMC) in
Dell PowerEdge servers.  Please note that these tools only apply to certain generations of Dell
PowerEdge servers which use a BMC -- more specifically, they should work on most Generation 8, 9,
and 10 servers.  Later generations use a "lifecycle controller" instead, which is not supported by
these tools.

See: http://en.wikipedia.org/wiki/List_of_Dell_PowerEdge_Servers

extract-bmc-firmware
--------------------

C program that extracts separate files that are stored in the compound firmware.
See the comments inside the code to understand what it does.

adjust-fan-thresholds
---------------------

Python script to adjust the lower critical fan thresholds hardcoded in the BMC.
This change allows the use of fans with lower RPM.

See: http://projects.nuschkys.net/2011/11/15/how-to-adjust-the-fan-thresholds-of-a-dell-poweredge/

*Disclaimer: I am not responsible for any damage you do to your system! If you flash a modified
firmware, you might render your PowerEdge server unusable. It might even be unrecoverable.
Additionally, badly set thresholds might cause overheating.*


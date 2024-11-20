# Universal DLL Injector & Shared Memory Buffer Driver
* KernelMode driver using shared memory buffer to communicate between usermode & kernelmode
* Designed to R/W protected process memory & bypass various anticheats
* Re-leaking - was made by leproxy

## Description
* Usable very well if you have more then 10 braincells and you can make it working for any anticheats without problems
* Root Logger : Robust kernel debugging with a Root Logger, allowing event logging to user mode even on anti-cheat systems (e.g., EAC EOS) that hook DbgPrintEx.
* Trace Flushing: Ensures seamless cleanup of traces and system modifications, including those left by the mapper, after user-mode exit or failure.
* Thread Hiding : Hides the communication thread by creating a gadget, unlinking, removing it from the CID table, and cloning attributes from a legitimate system thread.
* NMI Data Spoofing : Employs an NMI callback to spoof communication thread data, preventing anti-cheats from stack-walking the thread and identifying the driver in PsLoadedDriverList.
* Page Table (PT) Manager : Features advanced PT operations, including walking and caching entries, and finding free entries for page mapping, critical for injection tasks.

### Dependencies
* To Build: VS2022, WDK, SDK

## Disclaimer
* Im not responsible for any actions done by you, or this software, purely for educational purposes.

# Ghost

Ghost is a shellcode loader project designed to bypass multiple detection capabilities that are usually implemented by an EDR

## Detection 1 - kernel callbacks

kernel callbacks are implemented by an EDR to harness kernel level visiblity of events taking place on a system and that suggests that edrs can see whenever an execution attempt of a thread or a process is attempted

ghost makes use of Fiber threads to circumvent this detection technique, fiber threads are userland only execution units that does not alert any registered kernel callbacks 

## Detection 2 - stack unwinding 

stack unwinding is a technique implemented by EDRs to detect anomalous function calls including direct and indirect syscalls 

ghost makes use of 2 stack spoofing techniques to evade such detection 
  
  1 - the first one is Return Address Spoofing to hide normal function and indirect syscall invokations from the callstack
  2 - the second technique is using Function Hooking and switching between fiber threads to hide the entire beacon call stack during its sleeping period (all the fiber switching is also invisible to kernel)


## detection 3 - memory scanning

detection softwares often make use of memory scanning to identify malicious shellcode in a process' memory space

ghost implements a shellcode hiding technique originally implemented by *roshtyak* by allocating a very large memory space , filling this memory with random cryptographic data using SystemFunction036 (RtlGenRandom) and placing the shellcode in a random place between all the cryptographic data making it harder to detect during both manual and automated scanning


## other more minor evasion techniques are implemented such as

- making use of suspended processes and indirect syscalls to remove any function hooks installed by an EDR

- stopping ETW by patching its core functions in memory

- custom API hashing for resolving functions and system service numbers (SSNs)

- putting shellcode in resources (this was shockingly effective xD)


### Note

Ghost heavily relies on understanding how your beacon sleeps , in case of cobalt strike the kernel32!Sleep function is hooked and replaced with fiber calls to allow switching and hiding the beacon callstack 

if you want to use it with other C2 beacons you will need to use a tool like apimonitor to intercept api calls for your "beacon" , detect the api called on sleep and replacing it in Ghost.cpp to hook it , for example for MDSec's NightHawk one of the CreateThreadPool APIs needs to be hooked 



### build

To build the binary use the python `build.py` script providing the shellcode

ex: `python3 build.py -i shellcode.bin` 

the compilation is done on linux using the MinGW suite





<img src=image/image.png>


*above is an example of a beacons stack gets hidden during its sleep time*


### Resources 
- https://github.com/Kudaes/Fiber
- https://github.com/LloydLabs/shellcode-plain-sight
- https://decoded.avast.io/janvojtesek/raspberry-robins-roshtyak-a-little-lesson-in-trickery/

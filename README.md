# libstfu (STarlet For Unicorn)
An emulator for the "Starlet" ARM core in the Nintendo Wii, implemented with
the [Unicorn Engine](https://github.com/unicorn-engine/unicorn).

**NOTE:** I'm not working on this project anymore. You can find more up-to-date
work on this space in [eigenform/ironic](https://github.com/eigenform/ironic) instead.

## About
The rationale behind this project is multi-faceted, although it was originally
started in order to create a harness for fuzzing/analyzing the first and
second-stage bootloaders.

A summary of our goals is roughly:

- Have fun writing an accurate emulator
- Have a readable codebase that actually behaves like the platform
- Provide some tools for debugging/analyzing code running on the platform

Linking against Unicorn allows us to [mostly] ignore details about actually
emulating a CPU, and instead focus on properly emulating things that are
particular to the platform. 

The implementation of various I/O features is guided by marcan's 
[and other Team Twiizers members'] implementation of various things in 
[skyeye-starlet](https://github.com/marcan/skyeye-starlet). This project will 
probably be _even hackier_ than `skyeye-starlet` for a long time.


## Building
You will probably need to build [Unicorn](https://github.com/unicorn-engine/unicorn)
from source in order to deal with this. `libstfu` will probably fall in-and-out of 
compatibility with upstream Unicorn. You may need to build from 
[hosaka-corp/unicorn](https://github.com/hosaka-corp/unicorn) if some features do not 
exist upstream [yet].

In order to build the libraries and test binaries, move into the project root and 
run `make`. Note that I'm not interested in supported platforms other than Linux.

## Usage
We're confined to playing with the binaries in `tests/` right now.
`tests/stfu.c` attempts to run the platform indefinitely. In order to run these,
you will need the following (read the code for more details):

- A dump of the boot ROM (`boot0`)
- A dump of your Wii's EFUSE/OTP (one-time programmable) memory
- A NAND dump from your Wii (you technically don't need a full dump if you're
  trying to examine the boot process, just the first 0x200 pages or so)


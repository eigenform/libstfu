# libstfu (STarlet For Unicorn)
An emulator for the "Starlet" ARM core in the Nintendo Wii, implemented with
the [Unicorn Engine](https://github.com/unicorn-engine/unicorn).

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
particular to the platform. The implementation of various I/O features is 
guided by marcan's [and other Team Twiizers members'] implementation of 
various things in [skyeye-starlet](https://github.com/marcan/skyeye-starlet). 
This project will probably be _even hackier_ than `skyeye-starlet` for a long 
time.

## Building
Move into the project root and run `make`. This will build the libraries and
some test binaries.

I'm not interested in supported platforms other than Linux.

## Usage
Right now there are basically two cases - either you want to run emulation 
through the entire boot process, or you want to start execution directly in
some other binary (i.e. one of the bootloaders). For example, the tests require
the following:

- A dump of the boot ROM (`boot0`)
- A dump of your Wii's EFUSE/OTP (one-time programmable) memory
- A NAND dump from your Wii (you technically don't need a full dump if you're
  trying to examine the boot process, just the first 0x200 pages or so)


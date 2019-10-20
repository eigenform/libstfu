# libstfu (STarlet For Unicorn)
An emulator for the "Starlet" ARM core in the Nintendo Wii, implemented with
the [Unicorn Engine](https://github.com/unicorn-engine/unicorn).

## About
The rationale behind this project is multi-faceted, although it was originally
started in order to create a harness for fuzzing/analyzing the first and
second-stage bootloaders.

The implementation of various I/O features is guided by marcan's [and other
Team Twiizers members'] implementation of various things in 
[skyeye-starlet](https://github.com/marcan/skyeye-starlet). 
This project will probably be _even hackier_ than `skyeye-starlet` for a
long time.


This Ghidra extension enables you to run symbolic execution on the binary you are analysing in Ghidra.

This symbolic execution works by sending the Pcode from Ghdira to your system's python3 interpreter using the [ghidra bridge](https://github.com/justfoxing/ghidra_bridge).

Your python3 interpreter will then use [Angr](https://github.com/angr/angr) to perform the symbolic execution.

# Dependencies
1. [ghidra bridge](https://github.com/justfoxing/ghidra_bridge) - Follow the install instruction in the ghidra bridge repo
2. [Angr](https://github.com/angr/angr) - For the moment, you will have to install angr in your system python installation instead of a virtualenv. I'll work on changing this so that a virtualenv installation works in the future.

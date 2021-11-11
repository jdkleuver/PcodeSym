This Ghidra extension enables you to run symbolic execution on the binary you are analysing in Ghidra.

# Setup guide (Linux):

1. Install Python 3 on your computer (you can use PyPy which may have better performance)
2. Create a python 3 virtualenv, e.g: `python3 -m venv ~/pcode_venv`
3. Activate the virtualenv, e.g: `source ~/pcode_venv/bin/activate`
4. Use pip to install python dependencies: `pip install angr pypcode ghidra_bridge` 
5. Install the ghidra bridge: `python -m ghidra_bridge.install_server ~/ghidra_scripts`

# Build steps

For already built releases, please see the [Releases page](https://github.com/jdkleuver/PcodeSym/releases)

The recommended way to build the extension is using the GhidraDev eclipse plugin, but you can also build from the command line:

Install gradle using your package manager. I've successfully built with gradle version 6.8.3 and 7.2, other versions aren't tested.

1. `GHIDRA_INSTALL_DIR=/path/to/ghidra gradle`
Replace `/path/to/ghidra` with the directory containing your ghidra installation
2. The extension will be placed in the `dist/` directory as a zip file

# Usage guide
1. Start ghidra using the `ghidraRun` script
2. Click on `File->Install Extensions...`
3. Install the extension zip file, if you built it then it will be in the `dist/` directory
4. Restart Ghidra
5. Open the CodeBrowser tool by selecting a file, you will be prompted: "New extension plugins detected. Would you like to configure them?"
6. Select "Yes", then tick the box next to "PcodeSym" plugin, then click ok
7. In the CodeBrowser window, navigate to `Tools->PcodeSym->Set python3 interpreter` and select the location of your python 3 interpreter (e.g `~/pcode_venv/bin/python`)
8. Select the location to start the symbolic exectution in the code listing, right click select `PcodeSym->Set->Source Address`
9. Select the location to stop the symbolic execution in the code listing, right click select `PcodeSym->Set->Sink Address`
10. For any addresses that you wish to avoid during symbolic executions, right click them and select `PcodeSym->Add->Avoid Address` 
11. Run the symbolic execution by starting the "RunSolve.py" script in the Ghidra script manager

# How it works

This symbolic execution works by sending the P-code from Ghidra to the python3 interpreter using the [ghidra bridge](https://github.com/justfoxing/ghidra_bridge).

Your python3 interpreter will then use the P-code engine in [Angr](https://github.com/angr/angr) to perform the symbolic execution.

#Run angr solver using given parameters
#@author jackdekleuver
#@category Concolic
#@keybinding
#@menupath Tools.Concolic Execution.Run
#@toolbar

import argparse


def run_script(server_host, server_port):
    import ghidra_bridge

    # load something ghidra doesn't have
    import angr
    from angr.engines.pcode.lifter import IRSB, PcodeBasicBlockLifter, ExitStatement, IRSB_MAX_SIZE, IRSB_MAX_INST, MAX_INSTRUCTIONS, MAX_BYTES
    import claripy
    import sys
    import pypcode
    import archinfo
    import time

    print("Running inside the bridge!")

    # create the bridge and load the flat API/ghidra modules into the namespace
    with ghidra_bridge.GhidraBridge(connect_to_host=server_host, connect_to_port=server_port, namespace=globals()) as bridge:
        def is_successful(state):
            if(state.ip.args[0] == sink):
                return True
            return False
        
        def get_func_address(funcName):
            return int(getFunction(funcName).getBody().getMinAddress().toString(), 16)

        def get_function_containing_address(address):
            return currentProgram.getFunctionManager().getFunctionContaining(getAddressFactory().getAddress(address))

        def get_library_name(function):
            if not function.isThunk():
                print("Can't find library name for a non-Thunk function")
                return None
            thunked_function = function.getThunkedFunction(True)
            if not thunked_function.isExternal():
                print("Can't get library name for function that is not external")
                return None
            return thunked_function.getExternalLocation().getLibraryName()

        def get_function_name(function):
            return function.getName()

        def get_external_program(library_name):
            libraryPath = currentProgram.getExternalManager().getExternalLibrary(library_name).getAssociatedProgramPath()
            libraryFile = state.getProject().getProjectData().getFile(libraryPath)
            libraryProgram = libraryFile.getImmutableDomainObject(java.lang.Object(), ghidra.framework.model.DomainFile.DEFAULT_VERSION, None)
            return libraryProgram

        def get_pcode_of_external_function(program, function_name):
            functionManager = program.getFunctionManager()
            for fn in functionManager.getFunctions(True):
                if fn.getName() == function_name:
                    function = fn
                    break
            if function is None:
                return None
            firstInstruction = program.getListing().getInstructionAt(function.getBody().getMinAddress())
            lastInstruction = program.getListing().getInstructionAt(function.getBody().getMaxAddress())
            currentInstruction = firstInstruction
            pcode = []
            pcode += currentInstruction.getPcode()
            while True:
                currentInstruction = currentInstruction.getNext()
                pcode += currentInstruction.getPcode()
                if currentInstruction == lastInstruction.getNext():
                    # Reached the end of the function
                    break
            print("Min address:", function.getBody().getMinAddress()) 
            print("Max address:", function.getBody().getMaxAddress()) 
            print("Pcodes:", pcode)
            return pcode

        def get_sink_address():
            sink_addr = ghidra.concolic.ConcolicAnalyzer.getSink()
            if sink_addr is None:
                print('Please set the Sink address before running the script!')
                sys.exit(1)
            return int(sink_addr.toString(), 16)

        def get_avoid_addresses():
            avoid_addrs = [int(address.toString(), 16) for address in ghidra.concolic.ConcolicAnalyzer.getAvoidAddresses()]
            if len(avoid_addrs) == 0:
                print('WARN: list of avoid addresses is empty')
            return avoid_addrs

        def get_source_address():
            source_addr = ghidra.concolic.ConcolicAnalyzer.getSource()
            if source_addr is None:
                print('Please set the Source address before running the script!')
                sys.exit(1)
            return int(source_addr.toString(), 16)

        ############ Setup state ##########
        start_time = time.time()

        # Get program name from ghidra
        filename = getCurrentProgram().getExecutablePath()
        base_address = getCurrentProgram().getImageBase().getOffset()

        project = angr.Project(filename, load_options={'main_opts':{'base_addr': base_address},'auto_load_libs':False})
        
        sink = get_sink_address()
        avoids = get_avoid_addresses()
        start = get_source_address()
        
        stdin_args = []
        for buff in ghidra.concolic.ConcolicAnalyzer.getStdin():
            if buff.getSymbolic():
                stdin_args.append(claripy.BVS('arg' + str(len(stdin_args)), len(buff.getValue())*8)) 
            else:
                # process string with escape characters into a bytestring
                value = buff.getValue().encode('utf-8').decode('unicode-escape').encode('utf-8')
                stdin_args.append(claripy.BVV(value))
        stdin_arg = angr.SimFileStream(name='stdin', content=claripy.Concat(*stdin_args), has_end=False)

        func_args = []
        for arg in ghidra.concolic.ConcolicAnalyzer.getArgs():
            array_elems = []
            for elem in arg.getValues():
                if arg.getSymbolic():
                    array_elems.append(claripy.BVS('arg'+str(len(func_args)), len(elem)*8))
                else:
                    # process string with escape characters into a bytestring
                    value = elem.encode('utf-8').decode('unicode-escape').encode('utf-8')
                    array_elems.append(claripy.BVV(value))
            if arg.getArray():
                func_args.append([angr.PointerWrapper(e) for e in array_elems])
            else:
                func_args.append(array_elems[0])
 
        call_state = project.factory.call_state(start, *func_args, stdin=stdin_arg, add_options={angr.options.LAZY_SOLVES,
                                              angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY, angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS})

        simulation = project.factory.simgr(call_state)

        ######### Do symbolic execution ########

        simulation.explore(find=is_successful, avoid=avoids)

        ######## Post run analysis #########
        
        if len(simulation.found) > 0:
            for solution_state in simulation.found:
                for i, arg in enumerate(func_args):
                    if isinstance(arg, list):
                        print("[>>] arg {}:".format(i+1))
                        for k, elem in enumerate(arg):
                            print("\t{}: {!r}".format(k+1, solution_state.solver.eval(elem.value, cast_to=bytes).split(b"\0")[0]))
                    else:
                        print("[>>] arg {}: {!r}".format(i+1, solution_state.solver.eval(arg, cast_to=bytes).split(b"\0")[0]))
                print("stdin: {}".format(solution_state.posix.dumps(0)))
        else:
            print("[>>>] no solution found :(") 

        print("Script ran in {} seconds".format(time.time() - start_time))

if __name__ == "__main__":

    in_ghidra = False
    try:
        import ghidra
        # we're in ghidra!
        in_ghidra = True
    except ModuleNotFoundError:
        # not ghidra
        pass

    if in_ghidra:
        import ghidra_bridge_server
        script_file = getSourceFile().getAbsolutePath()
        # spin up a ghidra_bridge_server and spawn the script in external python to connect back to it
        python_path = ghidra.concolic.ConcolicAnalyzer.getPython()
        ghidra_bridge_server.GhidraBridgeServer.run_script_across_ghidra_bridge(script_file, python=python_path)
    else:
        # we're being run outside ghidra! (almost certainly from spawned by run_script_across_ghidra_bridge())

        parser = argparse.ArgumentParser(
            description="Example py3 script that's expected to be called from ghidra with a bridge")
        # the script needs to handle these command-line arguments and use them to connect back to the ghidra server that spawned it
        parser.add_argument("--connect_to_host", type=str, required=False,
                            default="127.0.0.1", help="IP to connect to the ghidra_bridge server")
        parser.add_argument("--connect_to_port", type=int, required=True,
                            help="Port to connect to the ghidra_bridge server")

        args = parser.parse_args()

        run_script(server_host=args.connect_to_host,
                   server_port=args.connect_to_port)


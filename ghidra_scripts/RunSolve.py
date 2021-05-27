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
    import claripy
    import sys

    print("Running inside the bridge!")

    # create the bridge and load the flat API/ghidra modules into the namespace
    with ghidra_bridge.GhidraBridge(connect_to_host=server_host, connect_to_port=server_port, namespace=globals()):
        def is_successful(state):
            if(state.ip.args[0] == addrGoodFunc):
                return True
            return False
        
        def getFuncAddress(funcName):
            return int(getFunction(funcName).getBody().getMinAddress().toString(), 16)
        
        # Get program name from ghidra
        filename = getCurrentProgram().getExecutablePath()
        base_address = getCurrentProgram().getMinAddress().getOffset()
        
        project = angr.Project(filename, load_options={'main_opts':{'base_addr': base_address},'auto_load_libs':False}, engine=angr.engines.UberEnginePcode)
        
        addrGoodFunc = getFuncAddress('win')
        addrBadFunc = getFuncAddress('lose')
        
        argv = [filename]
        argv.append(claripy.BVS('sym_arg',8*32))
        
        initial_state = project.factory.entry_state(args=argv, add_options={angr.options.LAZY_SOLVES,
                                              angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY, angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS})
        
        simulation = project.factory.simgr(initial_state)
        simulation.explore(find=is_successful, avoid=(addrBadFunc,))
        
        if len(simulation.found) > 0:
            for solution_state in simulation.found:
                print("[>>] {!r}".format(solution_state.solver.eval(argv[1], cast_to=bytes).split(b"\0")[0]))
        else:
            print("[>>>] no solution found :(") 

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
        ghidra_bridge_server.GhidraBridgeServer.run_script_across_ghidra_bridge(script_file)
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


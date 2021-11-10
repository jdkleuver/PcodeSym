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
        class MemoryMapping():
            def __init__(self, program, startAddress):
                self.program = program
                self.startAddress = startAddress

        # when calling an external function, we need to remember which function and library it is that we call
        next_function = ""
        next_library = ""

        class MySpace():
            def __init__(self, name):
                self.name = name

        class MyAddress(pypcode.Address):
            def __init__(self, ctx, space, offset, ghidra_address):
                super().__init__(ctx, space, offset)
                self.ghidra_address = ghidra_address

            @property
            def is_constant(self):
                return self.ghidra_address.isConstantAddress()

        class MyVarnode(pypcode.Varnode):
            def __init__(self, ctx, space, offset, size, ghidra_varnode):
                super().__init__(ctx, space, offset, size)
                program = getCurrentProgram()
                language = program.getLanguage()
                programContext = bridge.get_ghidra_api().program.util.ProgramContextImpl(language)
                spaceContext = bridge.get_ghidra_api().program.util.ProgramContextImpl(language)
                self.vcontext = bridge.get_ghidra_api().program.util.VarnodeContext(program, programContext, spaceContext)
                self.ghidra_varnode = ghidra_varnode

            def get_register_name(self):
                return self.vcontext.getRegister(self.ghidra_varnode).getName()

            def get_space_from_const(self):
                # self.ghidra_varnode.getAddress().getAddressSpace().getName() returns const, but for some reason that won't work
                return MySpace("mem") # if the name of the address space is "const" then it expects this to return an addres space with a name of either "ram" or "mem", not sure exactly the consequences of faking this out are

            def get_addr(self):
                return MyAddress(self.ctx, self.space, self.offset, self.ghidra_varnode.getAddress())

        class GhidraPcodeBlockLifter(PcodeBasicBlockLifter):
            def __init__(self, arch):
                super().__init__(arch)
            '''
            Mostly copied this whole function from PcodeBasicBlockLifter
            just changed the line that calls out to pypcode translate to
            do a direct mapping from pcode to TranslationResult instead
            '''
            def lift(self,
                     irsb,
                     program,
                     baseaddr,
                     adjusted_address,
                     pcodes,
                     bytes_offset = 0,
                     max_bytes = None,
                     max_inst = None):

                if max_bytes is None or max_bytes > MAX_BYTES:
                    max_bytes = min(len(pcodes), MAX_BYTES)
                if max_inst is None or max_inst > MAX_INSTRUCTIONS:
                    max_inst = MAX_INSTRUCTIONS

                irsb.behaviors = self.behaviors # FIXME

                # Translate
                addr = baseaddr + bytes_offset

                ##### Start of modified block ######

                pcode_array = []
                for pcode in pcodes:
                    inputs_varnodes = []
                    # convert pcode input Varnodes to pypcode Varnodes
                    for inp in pcode.inputs:
                        inputs_varnodes.append(MyVarnode(self.context, inp.getAddress().getAddressSpace(), inp.offset, inp.size, inp))
                    # convert pcode output Varnode to pypcode Varnode
                    if pcode.output is not None:
                        output_varnode = MyVarnode(self.context, pcode.output.getAddress().getAddressSpace(), pcode.output.offset, pcode.output.size, pcode.output)
                    else:
                        output_varnode = None
                    # Convert Ghidra raw Pcode to pypcode PcodeOp 
                    pcode_array.append(pypcode.PcodeOp(self.context, pcode.seqnum, pypcode.OpCode(pcode.opcode), inputs_varnodes, output_varnode))

                translations = []
                addrspace = getAddressFactory().getAddress(hex(baseaddr)).getAddressSpace()
                address = pypcode.Address(self.context, addrspace, baseaddr)
                instruction = program.getListing().getInstructionAt(getAddressFactory().getAddress(adjusted_address))
                # Convert PcodeOps to Translations
                translation = pypcode.Translation(
                        ctx = self.context,
                        address = address,
                        length = instruction.getLength(),
                        asm_mnem = instruction.getMnemonicString(),
                        asm_body = instruction.toString().split(instruction.getMnemonicString())[1],
                        ops = pcode_array
                )
                translations.append(translation)

                ##### End modified block #####
                
                irsb._instructions = translations

                # Post-process block to mark exits and next block
                next_block = None
                for insn in irsb._instructions:
                    for op in insn.ops:
                        if (op.opcode in [pypcode.OpCode.BRANCH, pypcode.OpCode.CBRANCH]
                            and op.inputs[0].get_addr().is_constant):
                                print('Block contains relative p-code jump at '
                                          'instruction {}:{}, which is not emulated '
                                          'yet.'.format(op.seq.getTarget().getOffset(), op.seq.getTime()))
                        if op.opcode == pypcode.OpCode.CBRANCH:
                            irsb._exit_statements.append((
                                op.seq.getTarget().getOffset(), op.seq.getTime(),
                                ExitStatement(op.inputs[0].offset, 'Ijk_Boring')))
                        elif op.opcode == pypcode.OpCode.BRANCH:
                            next_block = (op.inputs[0].offset, 'Ijk_Boring')
                        elif op.opcode == pypcode.OpCode.BRANCHIND:
                            next_block = (None, 'Ijk_Boring')
                        elif op.opcode == pypcode.OpCode.CALL:
                            next_block = (op.inputs[0].offset, 'Ijk_Call')
                        elif op.opcode == pypcode.OpCode.CALLIND:
                            next_block = (None, 'Ijk_Call')
                        elif op.opcode == pypcode.OpCode.RETURN:
                            next_block = (None, 'Ijk_Ret')

                if len(irsb._instructions) > 0:
                    last_insn = irsb._instructions[-1]
                    fallthru_addr = last_insn.address.offset + last_insn.length
                else:
                    fallthru_addr = addr

                if next_block is None:
                    next_block = (fallthru_addr, 'Ijk_Boring')

                irsb.next, irsb.jumpkind = next_block
        
        def is_successful(state):
            if(state.ip.args[0] == sink):
                return True
            return False
        
        def get_func_address(funcName):
            return int(getFunction(funcName).getBody().getMinAddress().toString(), 16)

        def get_pcode_at_address(address):
            # Fails when trying to get pcode of an external thunk-ed function
            try:
                return getCurrentProgram().getListing().getInstructionAt(getAddressFactory().getAddress(address)).getPcode(), getCurrentProgram(), address
            except AttributeError:
                # The address doesn't exist in the main program, check if globals are set
                global next_library
                global next_function
                if next_library != "" and next_function != "":
                    external_program = get_external_program(next_library)
                    functionManager = external_program.getFunctionManager()
                    for fn in functionManager.getFunctions(True):
                        if fn.getName() == next_function:
                            function = fn
                            break
                    if function is None:
                        # couldn't find the function in external program, propagate exception
                        print("Couldn't find function {} in {}".format(next_function, next_library))
                        raise
                    functionAddress = function.getBody().getMinAddress().getOffset()
                    memory_start = int(address, 16) - (functionAddress - external_program.getImageBase().getOffset()) # find the address where this library is mapped in memory 
                    address_in_program = hex(int(address, 16) - memory_start + external_program.getImageBase().getOffset())
                    print("Address {} is at {} in program {}".format(address, address_in_program, next_library))
                    next_library = ""
                    next_function = ""
                    return external_program.getListing().getInstructionAt(getAddressFactory().getAddress(address_in_program)).getPcode(), external_program, address_in_program 
                else:
                    raise

        def successor_func(state, **run_args):
            currentAddress = state.ip.args[0]
            containingFunction = get_function_containing_address(hex(currentAddress))
            print("current address in state:", hex(currentAddress))
            # figure out if we are about to make a call to an external program
            if containingFunction is not None and containingFunction.isThunk():
                externalLibraryName = get_library_name(containingFunction)
                print("Preparing for external function call to {} in {}".format(get_function_name(containingFunction), externalLibraryName))
                # prepare to get the function in the external program
                global next_library
                global next_function
                next_library = externalLibraryName
                next_function = get_function_name(containingFunction)
            try:
                current_pcode, program, adjusted_address = get_pcode_at_address(hex(currentAddress))
            except AttributeError:
                print("Couldn't get pcode at address:", hex(currentAddress), "falling back to pypcode lifter")
                # fallback to original lifter for external function
                return state.project.factory.successors(state, **run_args)
            irsb = IRSB.empty_block(archinfo.ArchAMD64, currentAddress, None, None, None, None, None, None)
            block_lifter.lift(irsb, program, currentAddress, adjusted_address, current_pcode, 0, None, None)
            return state.project.factory.successors(state, irsb=irsb, **run_args)

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
        engine = ghidra.concolic.ConcolicAnalyzer.getEngine()
        print(engine)

        if engine == ghidra.concolic.ConcolicAnalyzer.Engine.PYPCODE or engine == ghidra.concolic.ConcolicAnalyzer.Engine.PCODESYM:
            project = angr.Project(filename, load_options={'main_opts':{'base_addr': base_address},'auto_load_libs':False}, engine=angr.engines.UberEnginePcode)
        else:
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

        block_lifter = GhidraPcodeBlockLifter(archinfo.ArchAMD64)

        ######### Do symbolic execution ########

        if engine == ghidra.concolic.ConcolicAnalyzer.Engine.PCODESYM:
            simulation.explore(find=is_successful, avoid=avoids, successor_func=successor_func)
        else:
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


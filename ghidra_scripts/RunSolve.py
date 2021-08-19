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
    from angr.engines.pcode.lifter import IRSB, PcodeBasicBlockLifter
    import claripy
    import sys
    import pypcode
    import archinfo

    print("Running inside the bridge!")

    # copying these constants from angr pcode lifter
    IRSB_MAX_SIZE = 400
    IRSB_MAX_INST = 99
    MAX_INSTRUCTIONS = 99999
    MAX_BYTES = 5000

    # create the bridge and load the flat API/ghidra modules into the namespace
    with ghidra_bridge.GhidraBridge(connect_to_host=server_host, connect_to_port=server_port, namespace=globals()):
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
                     baseaddr,
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
                #replace this translation with mapping from ghidra PcodeOp to pypcode.TranslationResult
                #result = self.context.translate(data[bytes_offset:], addr, max_inst, max_bytes, True)
                pcode_array = []
                for pcode in pcodes:
                    inputs_varnodes = []
                    for inp in pcode.inputs:
                        inputs_varnodes.append(pypcode.Varnode(self.context, inp.getAddress().getAddressSpace(), inp.offset, inp.size))
                    if pcode.output is not None:
                        output_varnode = pypcode.Varnode(self.context, pcode.output.getAddress().getAddressSpace(), pcode.output.offset, pcode.output.size)
                    else:
                        output_varnode = None
                    pcode_array.append(pypcode.PcodeOp(self.context, pcode.seqnum, pypcode.OpCode(pcode.opcode), inputs_varnodes, output_varnode))

                translations = []
                addrspace = getAddressFactory().getAddress(hex(baseaddr)).getAddressSpace()
                address = pypcode.Address(self.context, addrspace, baseaddr)
                instruction = currentProgram.getListing().getInstructionAt(getAddressFactory().getAddress(hex(baseaddr)))
                translation = pypcode.Translation(
                        ctx = self.context,
                        address = address,
                        length = instruction.getLength(),
                        asm_mnem = instruction.getMnemonicString(),
                        asm_body = instruction.toString().split(instruction.getMnemonicString())[1],
                        ops = pcode_array
                )
                translations.append(translation)
                
                irsb._instructions = translations

                # Post-process block to mark exits and next block
                next_block = None
                for insn in irsb._instructions:
                    for op in insn.ops:
                        if (op.opcode in [pypcode.OpCode.BRANCH, pypcode.OpCode.CBRANCH]
                            and op.inputs[0].get_addr().is_constant):
                                l.warning('Block contains relative p-code jump at '
                                          'instruction %#x:%d, which is not emulated '
                                          'yet.', op.seq.pc.offset, op.seq.uniq)
                        if op.opcode == pypcode.OpCode.CBRANCH:
                            irsb._exit_statements.append((
                                op.seq.pc.offset, op.seq.uniq,
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
        
        class MyVarnode(pypcode.Varnode):
            def get_register_name():
                

        def is_successful(state):
            if(state.ip.args[0] == addrGoodFunc):
                return True
            return False
        
        def get_func_address(funcName):
            return int(getFunction(funcName).getBody().getMinAddress().toString(), 16)

        def get_pcode_at_address(address):
            return currentProgram.getListing().getInstructionAt(getAddressFactory().getAddress(address)).getPcode()
        
        ############ Setup state ##########

        # Get program name from ghidra
        filename = getCurrentProgram().getExecutablePath()
        base_address = getCurrentProgram().getMinAddress().getOffset()
        
        project = angr.Project(filename, load_options={'main_opts':{'base_addr': base_address},'auto_load_libs':False}, engine=angr.engines.UberEnginePcode)
        
        addrGoodFunc = get_func_address('win')
        addrBadFunc = get_func_address('lose')
        startAddress = get_func_address('start')
        
        bv = claripy.BVS('sym_arg',8*32)
        
        call_state = project.factory.call_state(startAddress, bv, add_options={angr.options.LAZY_SOLVES,
                                              angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY, angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS})
        
        
        simulation = project.factory.simgr(call_state)

        block_lifter = GhidraPcodeBlockLifter(archinfo.ArchAMD64)

        ######### Do symbolic execution ########

        #simulation.explore(find=is_successful, avoid=(addrBadFunc,))

        current_pcode = get_pcode_at_address(hex(startAddress))
        irsb = IRSB.empty_block(archinfo.ArchAMD64, startAddress, None, None, None, None, None, None)
        block_lifter.lift(irsb, startAddress, current_pcode, 0, None, None)
        simulation.step(irsb=irsb)


        ######## Post run analysis #########
        
        print(project.analyses.CFGEmulated())
        
        #if len(simulation.found) > 0:
        #    for solution_state in simulation.found:
        #        print("[>>] {!r}".format(solution_state.solver.eval(bv, cast_to=bytes).split(b"\0")[0]))
        #else:
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


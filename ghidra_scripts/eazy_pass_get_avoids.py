#TODO write a description for this script
#@author 
#@category _NEW_
#@keybinding 
#@menupath 
#@toolbar 
import ghidra.concolic.ConcolicAnalyzer as ConcolicAnalyzer

startAddress = askString("0xdeadbeef", "Please enter the first address")
lastAddress = askString("0xcafebabe", "Please enter the last address")
currentInstruction = getCurrentProgram().getListing().getInstructionAt(getAddressFactory().getAddress(startAddress))
lastInstruction = getCurrentProgram().getListing().getInstructionAt(getAddressFactory().getAddress(lastAddress))
while(currentInstruction != lastInstruction):
    if(currentInstruction.getMnemonicString() == "JNZ"):
        ConcolicAnalyzer.addAvoidAddress(currentInstruction.getOpObjects(0)[0])
    currentInstruction = currentInstruction.getNext() 


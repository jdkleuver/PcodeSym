package ghidra.concolic;

public class FunctionArgument {
    String value;
    boolean symbolic;
    boolean pointer;

    public FunctionArgument(String value, boolean symbolic, boolean pointer) {
            this.value = value;
            this.symbolic = symbolic;
            this.pointer = pointer;
    }

    public String toString() {
        return "Value: " + value + "\nSymbolic: " + symbolic + "\nPointer: " + pointer + "\n";
    }
}

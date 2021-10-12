package ghidra.concolic;

public class FunctionArgument {
    public String value;
    public boolean symbolic;
    public boolean pointer;

    public FunctionArgument(String value, boolean symbolic, boolean pointer) {
            this.value = value;
            this.symbolic = symbolic;
            this.pointer = pointer;
    }

    public String toString() {
        return "Value: " + value + "\nSymbolic: " + symbolic + "\nPointer: " + pointer + "\n";
    }

    public String getValue() {
        return value;
    }

    public boolean getSymbolic() {
        return symbolic;
    }

    public boolean getPointer() {
        return pointer;
    }
}

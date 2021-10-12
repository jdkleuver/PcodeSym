package ghidra.concolic;

public class StdinPart {
    public String value;
    public boolean symbolic;

    public StdinPart(String value, boolean symbolic) {
        this.value = value;
        this.symbolic = symbolic;
    }

    public String toString() {
        return "Value: " + value + "\nSymbolic: " + symbolic + "\n";
    }

    public String getValue() {
        return value;
    }

    public boolean getSymbolic() {
        return symbolic;
    }
}

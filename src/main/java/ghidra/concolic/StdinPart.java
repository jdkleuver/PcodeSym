package ghidra.concolic;

public class StdinPart {
    String value;
    boolean symbolic;

    public StdinPart(String value, boolean symbolic) {
        this.value = value;
        this.symbolic = symbolic;
    }

    public String toString() {
        return "Value: " + value + "\nSymbolic: " + symbolic + "\n";
    }
}

package ghidra.concolic;
import java.util.List;

public class FunctionArgument {
    public List<String> values;
    public boolean symbolic;
    public boolean array;

    public FunctionArgument(List<String> values, boolean symbolic, boolean array) {
            this.values = values;
            this.symbolic = symbolic;
            this.array = array;
    }

    public String toString() {
        return "Values: " + values + "\nSymbolic: " + symbolic + "\nArray: " + array + "\n";
    }

    public List<String> getValues() {
        return values;
    }

    public boolean getSymbolic() {
        return symbolic;
    }

    public boolean getArray() {
        return array;
    }
}

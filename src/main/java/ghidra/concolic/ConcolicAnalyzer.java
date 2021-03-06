/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package ghidra.concolic;

import java.util.List;
import java.util.ArrayList;

import javax.swing.JOptionPane;
import ghidra.program.model.address.Address;

/**
 * TODO: Provide class-level documentation that describes what this analyzer does.
 */
public class ConcolicAnalyzer {

    public enum Engine {
        PYPCODE,
        VEX,
        PCODESYM
    }

    public static List<Address> avoidAddresses = new ArrayList<>();
    public static Address sinkAddress = null;
    public static Address sourceAddress = null;
    public static String pythonPath = "python3"; // Default to "python3" interpreter, unless another one is selected
    public static List<FunctionArgument> funcArgs = null;
    public static List<StdinPart> stdin = null;
    static final String scriptName = "RunSolve.py";
    public static Engine symEngine = Engine.VEX; // Default to Vex engine since it performs best at the moment


    private ConcolicAnalyzer() {
    }
    
    public static void setSink(Address address) {
        sinkAddress = address;
        return;
    }

    public static void unSetSink() {
        sinkAddress = null;
        return;
    }

    public static void setEngine(Engine engine) {
        symEngine = engine;
    }

    public static Engine getEngine() {
        return symEngine;
    }
    
    public static void setSource(Address address) {
        sourceAddress = address;
        return;
    }
    
    public static void setArgs(List<FunctionArgument> functionArgs) {
        // if the start point is a function call, allow the function arguments to be specified as concrete or symbolic bitvectors
        funcArgs = functionArgs;
    }

    public static List<FunctionArgument> getArgs() {
        return funcArgs;
    }

    public static void setStdin(List<StdinPart> stdinParts) {
        // allow stdin to be treated as an array of concrete or symbolic bitvectors, when symbolic execution happens all of these bitvectors will be concatenated
        stdin = stdinParts;
    }

    public static List<StdinPart> getStdin() {
        return stdin;
    }

    public static void unSetSource() {
        sourceAddress = null;
        return;
    }
    
    public static void addAvoidAddress(Address address) {
        avoidAddresses.add(address);
        return;
    }
    
    public static boolean removeAvoidAddress(Address address) {
        if(avoidAddresses.contains(address)) {
            avoidAddresses.remove(address);
            return true;
        }
        return false;
    }

    public static void removeAllAvoidAddresses() {
        avoidAddresses.clear();
    }
    
    public static  void solve() {
        JOptionPane.showMessageDialog(null, "This button doesn't work currently, please manually run the '" + scriptName + "' from the script manager", "Not yet implemented", JOptionPane.INFORMATION_MESSAGE);
    }
    
    public static Address getSource() {
        return sourceAddress;
    }
    
    public static List<Address> getAvoidAddresses() {
        return avoidAddresses;
    }
    
    public static Address getSink() {
        return sinkAddress;
    }

    public static void setPython(String path) {
        pythonPath = path;
    }

    public static String getPython() {
        return pythonPath;
    }
    
}

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
package concolic;

import java.util.List;

import javax.swing.JOptionPane;
import ghidra.program.model.address.Address;

/**
 * TODO: Provide class-level documentation that describes what this analyzer does.
 */
public class ConcolicAnalyzer {

    static List<Address> avoidAddresses;
    static List<Address> sinks;
    static Address currentSinkAddress = null;
    static final String scriptName = "RunSolve.py";

	public ConcolicAnalyzer() {
	}
	
	public void setSink(Address address) {
		currentSinkAddress = address;
		return;
	}

	public void unSetSink() {
		currentSinkAddress = null;
		return;
	}
	
	public void addAvoidAddress(Address address) {
		avoidAddresses.add(address);
		return;
	}
	
	public boolean removeAvoidAddress(Address address) {
        if(avoidAddresses.contains(address)) {
            avoidAddresses.remove(address);
            return true;
        }
        return false;
	}
	
	public void solve() {
		JOptionPane.showMessageDialog(null, "This button doesn't work currently, please manually run the '" + scriptName + "' from the script manager", "Not yet implemented", JOptionPane.INFORMATION_MESSAGE);
	}
}

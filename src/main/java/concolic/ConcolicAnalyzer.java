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

import java.io.PrintWriter;
import java.util.List;

import javax.swing.JOptionPane;

import generic.jar.ResourceFile;
import ghidra.app.script.GhidraScript;
import ghidra.app.script.GhidraScriptProvider;
import ghidra.app.script.GhidraScriptUtil;
import ghidra.app.services.ConsoleService;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;

/**
 * TODO: Provide class-level documentation that describes what this analyzer does.
 */
public class ConcolicAnalyzer {

    static List<Address> avoidAddresses;
    static List<Address> sinks;
    static Address currentSinkAddress = null;
    static final String scriptName = "python_basics.py";
    private PluginTool tool;
	
	public ConcolicAnalyzer(PluginTool tool) {
		this.tool = tool;
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
		JOptionPane.showMessageDialog(null, GhidraScriptUtil.getProviders().toString(), "script source directories", JOptionPane.INFORMATION_MESSAGE);
		ResourceFile sourceFile = GhidraScriptUtil.findScriptByName(scriptName);
		if(sourceFile == null) {
			JOptionPane.showMessageDialog(null, "Couldn't find" + scriptName, "Error", JOptionPane.ERROR_MESSAGE);
			return;
		}
	    GhidraScriptProvider provider = GhidraScriptUtil.getProvider(sourceFile);
	    if(provider == null) {
	    	JOptionPane.showMessageDialog(null, "Couldn't find script provider for " + scriptName, "Error", JOptionPane.ERROR_MESSAGE);
	    	return;
	    }
	    PrintWriter writer = getOutputMsgStream(tool);
	    String[] scriptArguments = {"foo", "bar"};
	    GhidraScript script = null;
		try {
			script = provider.getScriptInstance(sourceFile, writer);
		} catch (Exception e) {
			JOptionPane.showMessageDialog(null, e.getMessage(), "Error", JOptionPane.ERROR_MESSAGE);
			return;
		}
	    try {
			script.runScript(scriptName, scriptArguments);
		} catch (Exception e) {
			JOptionPane.showMessageDialog(null, e.getMessage(), "Error", JOptionPane.ERROR_MESSAGE);
			return;
		}
		return;
	}

	private PrintWriter getOutputMsgStream(PluginTool ptool) {
		if (ptool != null) {
			ConsoleService console = ptool.getService(ConsoleService.class);
			if (console != null) {
				return console.getStdOut();
			}
		}
		return new PrintWriter(System.out);
	}

}

package concolic;
import ghidra.app.context.ListingContextAction;
import ghidra.app.context.ListingActionContext;
import ghidra.framework.plugintool.*;
import docking.action.MenuData;
import javax.swing.JOptionPane;

public class ConcolicMenu extends ListingContextAction {
    public final String MenuName = "Concolic Execution";
    public final String GroupName = "concolic";


    static PluginTool tool;
    private ConcolicAnalyzer analyzer;

    public ConcolicMenu(ConcolicPlugin plugin, ConcolicAnalyzer analyzer) {
        super("ConcolicPlugin", plugin.getName());
        tool = plugin.getTool();
        this.analyzer = analyzer;
        createMenus();
    }

    public void createMenus() {

        tool.setMenuGroup(new String[] {
            MenuName
        }, GroupName);

        ListingContextAction SetSink = new ListingContextAction("Set Sink Address", getName()) {
            @Override
            protected void actionPerformed(ListingActionContext context) {
                analyzer.setSink(context.getLocation().getAddress());
            }
        };

        SetSink.setPopupMenuData(new MenuData(new String[] {
            MenuName,
            "Set",
            "Sink Address"
        }, null, GroupName));
        tool.addAction(SetSink);

        ListingContextAction UnSetSink = new ListingContextAction("Unset Sink Address", getName()) {
            @Override
            protected void actionPerformed(ListingActionContext context) {
                analyzer.unSetSink();
            }
        };

        UnSetSink.setPopupMenuData(new MenuData(new String[] {
            MenuName,
            "Unset",
            "Sink Address"
        }, null, GroupName));
        tool.addAction(UnSetSink);

        ListingContextAction addAvoidAddress = new ListingContextAction("Add address to avoid", getName()) {
            @Override
            protected void actionPerformed(ListingActionContext context) {
                analyzer.addAvoidAddress(context.getLocation().getAddress());
            }
        };

        addAvoidAddress.setPopupMenuData(new MenuData(new String[] {
            MenuName,
            "Add",
            "Avoid Address"
        }, null, GroupName));
        tool.addAction(addAvoidAddress);

        ListingContextAction removeAvoidAddress = new ListingContextAction("Remove address from list to avoid", getName()) {
            @Override
            protected void actionPerformed(ListingActionContext context) {
                if(!analyzer.removeAvoidAddress(context.getLocation().getAddress()))
                	JOptionPane.showMessageDialog(null, "Address was not found in the list", "Warning", JOptionPane.WARNING_MESSAGE);
            }
        };

        removeAvoidAddress.setPopupMenuData(new MenuData(new String[] {
            MenuName,
            "Remove",
            "Avoid Address"
        }, null, GroupName));
        tool.addAction(removeAvoidAddress);

        ListingContextAction solve = new ListingContextAction("Run angr to solve", getName()) {
            @Override
            protected void actionPerformed(ListingActionContext context) {
            	if(!analyzer.solve())
            		JOptionPane.showMessageDialog(null, "Failed to run solver", "Error", JOptionPane.ERROR_MESSAGE);
            }
        };
        solve.setMenuBarData(new MenuData(new String[] {
            "Tools",
            "Concolic Execution",
            "Solve"
        }, null, GroupName));
        tool.addAction(solve);
    }
}

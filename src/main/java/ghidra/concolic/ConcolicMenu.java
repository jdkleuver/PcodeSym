package ghidra.concolic;
import ghidra.app.context.ListingContextAction;
import ghidra.app.context.ListingActionContext;
import ghidra.framework.plugintool.*;
import docking.action.MenuData;
import javax.swing.JOptionPane;

public class ConcolicMenu extends ListingContextAction {
    public final String MenuName = "Concolic Execution";
    public final String GroupName = "concolic";


    static PluginTool tool;

    public ConcolicMenu(ConcolicPlugin plugin) {
        super("ConcolicPlugin", plugin.getName());
        tool = plugin.getTool();
        createMenus();
    }

    public void createMenus() {

        tool.setMenuGroup(new String[] {
            MenuName
        }, GroupName);

        ListingContextAction SetSink = new ListingContextAction("Set Sink Address", getName()) {
            @Override
            protected void actionPerformed(ListingActionContext context) {
                ConcolicAnalyzer.setSink(context.getLocation().getAddress());
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
            	ConcolicAnalyzer.unSetSink();
            }
        };

        UnSetSink.setPopupMenuData(new MenuData(new String[] {
            MenuName,
            "Unset",
            "Sink Address"
        }, null, GroupName));
        tool.addAction(UnSetSink);
        
        ListingContextAction SetSource = new ListingContextAction("Set Source Address", getName()) {
            @Override
            protected void actionPerformed(ListingActionContext context) {
                ConcolicAnalyzer.setSource(context.getLocation().getAddress());
            }
        };

        SetSource.setPopupMenuData(new MenuData(new String[] {
            MenuName,
            "Set",
            "Source Address"
        }, null, GroupName));
        tool.addAction(SetSource);

        ListingContextAction UnSetSource = new ListingContextAction("Unset Source Address", getName()) {
            @Override
            protected void actionPerformed(ListingActionContext context) {
            	ConcolicAnalyzer.unSetSource();
            }
        };

        UnSetSink.setPopupMenuData(new MenuData(new String[] {
            MenuName,
            "Unset",
            "Source Address"
        }, null, GroupName));
        tool.addAction(UnSetSource);

        ListingContextAction addAvoidAddress = new ListingContextAction("Add address to avoid", getName()) {
            @Override
            protected void actionPerformed(ListingActionContext context) {
            	ConcolicAnalyzer.addAvoidAddress(context.getLocation().getAddress());
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
                if(!ConcolicAnalyzer.removeAvoidAddress(context.getLocation().getAddress()))
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
            	ConcolicAnalyzer.solve();
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

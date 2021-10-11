package ghidra.concolic;
import ghidra.app.context.ListingContextAction;
import ghidra.app.context.ListingActionContext;
import ghidra.framework.plugintool.*;
import docking.action.MenuData;
import javax.swing.*;
import javax.swing.border.EmptyBorder;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.ArrayList;

public class ConcolicMenu extends ListingContextAction {
    public final String MenuName = "PcodeSym";
    public final String GroupName = "PcodeSym";


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
                // Create dialog box for the concrete/symbolic inputs
                ArrayList<JPanel> functionArgs = new ArrayList<>();
                ArrayList<JPanel> stdin = new ArrayList<>();
                JPanel mainPanel = new JPanel();
                
                JPanel funcArgsContainer = new JPanel();
                funcArgsContainer.setLayout(new BoxLayout(funcArgsContainer, BoxLayout.Y_AXIS));

                JButton addFuncArg = new JButton("Add Function Argument");
                funcArgsContainer.add(addFuncArg);
                
                JButton addStdin = new JButton("Add to stdin");
                
                JPanel stdinContainer = new JPanel();
                stdinContainer.setLayout(new BoxLayout(stdinContainer, BoxLayout.Y_AXIS));
                stdinContainer.add(addStdin);
                
                mainPanel.setLayout(new BoxLayout(mainPanel, BoxLayout.Y_AXIS));
                mainPanel.setBorder(new EmptyBorder(new Insets(20, 20, 20, 20)));
                mainPanel.add(funcArgsContainer);
                mainPanel.add(new JPanel()); // Padding
                mainPanel.add(new JSeparator());
                mainPanel.add(new JPanel()); // Padding
                mainPanel.add(stdinContainer);

                JOptionPane pane = new JOptionPane(mainPanel, JOptionPane.PLAIN_MESSAGE, JOptionPane.OK_CANCEL_OPTION);
                JDialog dialog = pane.createDialog(null, "Add inputs");

                addFuncArg.addActionListener(new ActionListener() {
                    public void actionPerformed(ActionEvent e) {
                        JPanel newPanel = new JPanel();
                        newPanel.setLayout(new GridLayout(0, 3));
                        JRadioButton r1 = new JRadioButton("Concrete");
                        JRadioButton r2 = new JRadioButton("Symbolic");
                        ButtonGroup bg = new ButtonGroup();
                        bg.add(r1);
                        bg.add(r2);
                        JLabel argLabel = new JLabel("Argument " + (functionArgs.size()+1));
                        JTextField tf = new JTextField("Value");
                        JCheckBox pointer = new JCheckBox("Pointer");
                        newPanel.add(argLabel);
                        newPanel.add(r1);
                        newPanel.add(new JPanel()); // Padding
                        newPanel.add(tf);
                        newPanel.add(r2);
                        newPanel.add(pointer);
                        r2.setSelected(true);
                        functionArgs.add(newPanel);
                        funcArgsContainer.removeAll();
                        for(JPanel panel: functionArgs) {
                            funcArgsContainer.add(new JSeparator());
                            funcArgsContainer.add(panel);
                        }
                        funcArgsContainer.add(addFuncArg);
                        stdinContainer.revalidate();
                        funcArgsContainer.revalidate();
                        mainPanel.revalidate();
                        dialog.pack();
                    }
                });

                addStdin.addActionListener(new ActionListener() {
                    public void actionPerformed(ActionEvent e) {
                        JPanel newPanel = new JPanel();
                        newPanel.setLayout(new GridLayout(0, 2));
                        JRadioButton r1 = new JRadioButton("Concrete");
                        JRadioButton r2 = new JRadioButton("Symbolic");
                        ButtonGroup bg = new ButtonGroup();
                        bg.add(r1);
                        bg.add(r2);
                        JLabel argLabel = new JLabel("Part " + (stdin.size()+1));
                        JTextField tf = new JTextField("Value");
                        newPanel.add(argLabel);
                        newPanel.add(r1);
                        newPanel.add(tf);
                        newPanel.add(r2);
                        r2.setSelected(true);
                        stdin.add(newPanel);
                        stdinContainer.removeAll();
                        stdinContainer.add(addStdin);
                        for(JPanel panel: stdin) {
                            stdinContainer.add(panel);
                            stdinContainer.add(new JSeparator());
                        }
                        stdinContainer.revalidate();
                        funcArgsContainer.revalidate();
                        mainPanel.revalidate();
                        dialog.pack();
                    }
                });

                dialog.show();

                ArrayList<FunctionArgument> funcArgs = new ArrayList<>();

                for(JPanel panel: functionArgs) {
                    JTextField value = (JTextField) panel.getComponents()[3];
                    JRadioButton symbolic = (JRadioButton) panel.getComponents()[4];
                    JCheckBox pointer = (JCheckBox) panel.getComponents()[5];
                    funcArgs.add(new FunctionArgument(value.getText(), symbolic.isSelected(), pointer.isSelected()));
                }

                ArrayList<StdinPart> stdinParts = new ArrayList<>();

                for(JPanel panel: stdin) {
                    JTextField value = (JTextField) panel.getComponents()[2];
                    JRadioButton symbolic = (JRadioButton) panel.getComponents()[3];
                    stdinParts.add(new StdinPart(value.getText(), symbolic.isSelected()));
                }

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

        UnSetSource.setPopupMenuData(new MenuData(new String[] {
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
            "PcodeSym",
            "Solve"
        }, null, GroupName));
        tool.addAction(solve);

        ListingContextAction setPython = new ListingContextAction("Set the path of the Python 3 interpreter to use (virtualenv recommended, needs to have angr, pypcode and ghidra_bridge installed)", getName()) {
            @Override
            protected void actionPerformed(ListingActionContext context) {
                JFileChooser fc = new JFileChooser();
                fc.setMultiSelectionEnabled(false);
                int retVal = fc.showOpenDialog(null);
                if (retVal == JFileChooser.APPROVE_OPTION) {
                    String pythonPath = fc.getSelectedFile().getAbsolutePath();
                    ConcolicAnalyzer.setPython(pythonPath);
                }
            }
        };
        setPython.setMenuBarData(new MenuData(new String[] {
            "Tools",
            "PcodeSym",
            "Set python 3 interpreter"
        }, null, GroupName));
        tool.addAction(setPython);
    }
}

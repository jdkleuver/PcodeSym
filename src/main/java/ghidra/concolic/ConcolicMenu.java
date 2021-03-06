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
import java.awt.event.ItemEvent;
import java.awt.event.ItemListener;
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
                        newPanel.setLayout(new BoxLayout(newPanel, BoxLayout.X_AXIS));
                        JRadioButton r1 = new JRadioButton("Concrete");
                        JRadioButton r2 = new JRadioButton("Symbolic");
                        ButtonGroup bg = new ButtonGroup();
                        bg.add(r1);
                        bg.add(r2);
                        JPanel buttonPanel = new JPanel();
                        buttonPanel.setLayout(new BoxLayout(buttonPanel, BoxLayout.Y_AXIS));
                        buttonPanel.add(r1);
                        buttonPanel.add(r2);
                        JLabel argLabel = new JLabel("Argument " + (functionArgs.size()+1));
                        JTextField tf = new JTextField("Element");
                        JCheckBox array = new JCheckBox("Array");
                        JButton addArrayElem = new JButton("Add array element");
                        addArrayElem.setVisible(false);
                        addArrayElem.addActionListener(new ActionListener() {
                            public void actionPerformed(ActionEvent e) {
                                    newPanel.add(new JTextField("Element"));
                                    newPanel.revalidate();
                                    dialog.pack();
                            }
                        });
                        array.addItemListener(new ItemListener() {
                            public void itemStateChanged(ItemEvent e) {
                                if(e.getStateChange() == ItemEvent.SELECTED) {
                                   addArrayElem.setVisible(true); 
                                   newPanel.revalidate();
                                   dialog.pack();
                                }
                                else {
                                   addArrayElem.setVisible(false);
                                   newPanel.removeAll();
                                   newPanel.add(argLabel);
                                   newPanel.add(buttonPanel);
                                   newPanel.add(array);
                                   newPanel.add(addArrayElem);
                                   newPanel.add(tf);
                                   newPanel.revalidate();
                                   dialog.pack();
                                }
                            }
                        });
                        newPanel.add(argLabel);
                        newPanel.add(buttonPanel);
                        newPanel.add(array);
                        newPanel.add(addArrayElem);
                        newPanel.add(tf);
                        r2.setSelected(true);
                        functionArgs.add(newPanel);
                        funcArgsContainer.removeAll();
                        for(JPanel panel: functionArgs) {
                            funcArgsContainer.add(new JSeparator());
                            funcArgsContainer.add(panel);
                        }
                        funcArgsContainer.add(new JSeparator());
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

                dialog.setVisible(true);
                int response;
                if(pane.getValue() instanceof Integer)
                    response = ((Integer) pane.getValue()).intValue();
                else
                    response = -1;
                if(response == JOptionPane.OK_OPTION) {
                    ConcolicAnalyzer.setSource(context.getLocation().getAddress());
                    ArrayList<FunctionArgument> funcArgs = new ArrayList<>();

                    for(JPanel panel: functionArgs) {
                        JPanel buttonPanel = (JPanel) panel.getComponents()[1];
                        JRadioButton symbolic = (JRadioButton) buttonPanel.getComponents()[1];
                        JCheckBox array = (JCheckBox) panel.getComponents()[2];
                        ArrayList<String> values = new ArrayList<>();
                        for(int i=4; i<panel.getComponents().length; i++) {
                            values.add(((JTextField) panel.getComponents()[i]).getText());
                        }
                        funcArgs.add(new FunctionArgument(values, symbolic.isSelected(), array.isSelected()));
                    }
                    ConcolicAnalyzer.setArgs(funcArgs);

                    ArrayList<StdinPart> stdinParts = new ArrayList<>();

                    for(JPanel panel: stdin) {
                        JTextField value = (JTextField) panel.getComponents()[2];
                        JRadioButton symbolic = (JRadioButton) panel.getComponents()[3];
                        stdinParts.add(new StdinPart(value.getText(), symbolic.isSelected()));
                    }
                    ConcolicAnalyzer.setStdin(stdinParts);
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

        ListingContextAction removeAllAvoidAddress = new ListingContextAction("Remove all addresses from list to avoid", getName()) {
            @Override
            protected void actionPerformed(ListingActionContext context) {
                ConcolicAnalyzer.removeAllAvoidAddresses();
            }
        };

        removeAllAvoidAddress.setPopupMenuData(new MenuData(new String[] {
            MenuName,
            "Remove",
            "All Avoid Address"
        }, null, GroupName));
        tool.addAction(removeAllAvoidAddress);

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

    ListingContextAction setEngine = new ListingContextAction("Choose which symbolic execution engine to use with angr", getName()) {
            @Override
            protected void actionPerformed(ListingActionContext context) {
                String[] engineOptions = {"PcodeSym", "PyPcode", "Vex (recommended for now)"};

                String engineChoice = (String) JOptionPane.showInputDialog(
                                null,
                                "Which engine would you like to use?",
                                "Select Symbolic Execution Engine",
                                JOptionPane.QUESTION_MESSAGE,
                                null,
                                engineOptions,
                                engineOptions[2]);

                if(engineChoice.equals(engineOptions[0])) {
                    ConcolicAnalyzer.setEngine(ConcolicAnalyzer.Engine.PCODESYM);
                }
                else if(engineChoice.equals(engineOptions[1])) {
                    ConcolicAnalyzer.setEngine(ConcolicAnalyzer.Engine.PYPCODE);
                }
                else {
                    ConcolicAnalyzer.setEngine(ConcolicAnalyzer.Engine.VEX);
                }
            }
        };
        setEngine.setMenuBarData(new MenuData(new String[] {
            "Tools",
            "PcodeSym",
            "Set symbolic execution engine"
        }, null, GroupName));
        tool.addAction(setEngine);
    }
}

/* ###
 * ContextUEFI dependency graph for Ghidra.
 *
 * Load a ContextUEFI "*-context.json" file and draw the module dependency
 * graph using Ghidra's native graph display.
 */
//@category ContextUEFI

import java.awt.Color;
import java.awt.Dialog;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.Frame;
import java.awt.KeyboardFocusManager;
import java.awt.event.InputEvent;
import java.awt.event.KeyEvent;
import java.awt.geom.Point2D;
import java.io.File;
import java.io.FileReader;
import java.io.Reader;
import java.lang.reflect.Field;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import javax.swing.BorderFactory;
import javax.swing.DefaultListModel;
import javax.swing.JButton;
import javax.swing.JComponent;
import javax.swing.JDialog;
import javax.swing.JLabel;
import javax.swing.JList;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextField;
import javax.swing.ListSelectionModel;
import javax.swing.SwingUtilities;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;

import com.google.gson.Gson;
import com.google.gson.JsonElement;
import com.google.gson.JsonParser;

import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.KeyBindingData;
import docking.action.MenuData;
import ghidra.app.script.GhidraScript;
import ghidra.app.services.GraphDisplayBroker;
import ghidra.framework.plugintool.PluginTool;
import ghidra.service.graph.AttributedEdge;
import ghidra.service.graph.AttributedGraph;
import ghidra.service.graph.AttributedVertex;
import ghidra.service.graph.GraphDisplay;
import ghidra.service.graph.GraphDisplayListener;
import ghidra.service.graph.GraphDisplayOptions;
import ghidra.service.graph.GraphDisplayOptionsBuilder;
import ghidra.service.graph.GraphType;
import ghidra.service.graph.GraphTypeBuilder;
import ghidra.service.graph.VertexShape;
import ghidra.util.exception.CancelledException;
import org.jungrapht.visualization.VisualizationViewer;
import org.jungrapht.visualization.control.CrossoverScalingControl;
import org.jungrapht.visualization.control.ScalingControl;

public class ContextUefiDependencyGraph extends GhidraScript {

	private static final String FULL_GRAPH_MODE = "Full graph";
	private static final String FOCUS_MODULE_MODE = "Focus one module";
	private static final String FOCUS_MODULES_MODE = "Focus some modules";

	private static final String PROVIDER_VERTEX = "Protocol Provider";
	private static final String CLIENT_VERTEX = "Protocol Client";
	private static final String PROVIDER_AND_CLIENT_VERTEX = "Provider And Client";
	private static final String FOCUS_VERTEX = "Focused Module";
	private static final String EDGE_TYPE = "Protocol Dependency";
	private static final String WHEEL_ZOOM_INSTALLED_PROPERTY =
		"ContextUEFI.wheelZoomInstalled";
	private static final double WHEEL_ZOOM_STEP = 1.12;

	private static final Set<String> PROVIDER_SERVICES = Set.of(
		"InstallProtocolInterface",
		"InstallMultipleProtocolInterfaces"
	);

	private static final Set<String> CLIENT_SERVICES = Set.of(
		"LocateProtocol",
		"OpenProtocol"
	);

	private static class ModuleInfo {
		String module_name;
		List<ProtocolInfo> protocols;
	}

	private static class ProtocolInfo {
		String service;
		String protocol_name;
		String guid;
	}

	private static class ProviderInfo {
		String moduleName;
		String protocolName;
		String guid;
		String service;
	}

	private static class Dependency {
		String providerModule;
		String clientModule;
		String protocolName;
		String guid;
		String providerService;
	}

	@Override
	protected void run() throws Exception {
		File jsonFile = askFile("Select ContextUEFI context JSON", "Open");
		ModuleInfo[] modules = loadModules(jsonFile);
		String mode = askChoice(
			"ContextUEFI graph mode",
			"Graph mode",
			List.of(FOCUS_MODULE_MODE, FOCUS_MODULES_MODE, FULL_GRAPH_MODE),
			FOCUS_MODULE_MODE
		);

		Map<String, List<ProviderInfo>> providersByGuid = new LinkedHashMap<>();
		Map<String, Set<String>> clientsByGuid = new LinkedHashMap<>();
		Set<String> providerModules = new LinkedHashSet<>();
		Set<String> clientModules = new LinkedHashSet<>();
		Set<String> allModules = new LinkedHashSet<>();

		for (ModuleInfo module : modules) {
			if (module == null || module.module_name == null || module.protocols == null) {
				continue;
			}
			allModules.add(module.module_name);
			for (ProtocolInfo protocol : module.protocols) {
				if (protocol == null || protocol.service == null || protocol.guid == null) {
					continue;
				}
				if (PROVIDER_SERVICES.contains(protocol.service)) {
					ProviderInfo provider = new ProviderInfo();
					provider.moduleName = module.module_name;
					provider.protocolName = protocol.protocol_name;
					provider.guid = protocol.guid;
					provider.service = protocol.service;
					providersByGuid.computeIfAbsent(protocol.guid, k -> new ArrayList<>()).add(provider);
					providerModules.add(module.module_name);
				}
				if (CLIENT_SERVICES.contains(protocol.service)) {
					clientsByGuid.computeIfAbsent(protocol.guid, k -> new LinkedHashSet<>()).add(module.module_name);
					clientModules.add(module.module_name);
				}
			}
		}

		List<Dependency> dependencies = buildDependencies(providersByGuid, clientsByGuid);
		Set<String> initialFocus = chooseInitialFocus(mode, allModules);
		GraphNavigator navigator = new GraphNavigator(dependencies, providerModules, clientModules);
		navigator.render(initialFocus, false);
		println("ContextUEFI graph loaded from " + jsonFile.getAbsolutePath());
		println("Modules in JSON: " + modules.length);
		if (initialFocus != null && !initialFocus.isEmpty()) {
			println("Focused modules: " + initialFocus);
		}
		println("Provider GUIDs: " + providersByGuid.size());
		println("Client GUIDs: " + clientsByGuid.size());
		println("Dependency edges: " + dependencies.size());
	}

	private Set<String> chooseInitialFocus(String mode, Set<String> allModules) throws Exception {
		if (FULL_GRAPH_MODE.equals(mode)) {
			return null;
		}

		List<String> choices = new ArrayList<>(allModules);
		Collections.sort(choices);
		if (choices.isEmpty()) {
			return null;
		}

		if (FOCUS_MODULES_MODE.equals(mode)) {
			List<String> selected = askModuleChoices(choices);
			if (selected.isEmpty()) {
				throw new CancelledException("No modules selected");
			}
			return new LinkedHashSet<>(selected);
		}

		String selected = askChoice(
			"ContextUEFI focus module",
			"Module",
			choices,
			currentProgram != null && choices.contains(currentProgram.getName())
				? currentProgram.getName()
				: choices.get(0)
		);
		return new LinkedHashSet<>(List.of(selected));
	}

	private List<String> askModuleChoices(List<String> choices) throws Exception {
		List<List<String>> resultHolder = new ArrayList<>();

		SwingUtilities.invokeAndWait(() -> {
			Set<String> selectedModules = new LinkedHashSet<>();
			DefaultListModel<String> model = new DefaultListModel<>();
			JList<String> moduleList = new JList<>(model);
			JTextField filterField = new JTextField();
			JLabel selectionLabel = new JLabel("Selected: 0");
			boolean[] refreshing = new boolean[] { false };

			JDialog dialog = createModuleChooserDialog();
			moduleList.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION);
			moduleList.setVisibleRowCount(24);

			Runnable updateSelectionLabel = () ->
				selectionLabel.setText("Selected: " + selectedModules.size());

			Runnable refreshList = () -> {
				refreshing[0] = true;
				try {
					String query = filterField.getText().trim().toLowerCase();
					model.clear();
					for (String choice : choices) {
						if (query.isEmpty() || choice.toLowerCase().contains(query)) {
							model.addElement(choice);
						}
					}

					List<Integer> selectedIndices = new ArrayList<>();
					for (int i = 0; i < model.size(); i++) {
						if (selectedModules.contains(model.getElementAt(i))) {
							selectedIndices.add(i);
						}
					}
					moduleList.setSelectedIndices(
						selectedIndices.stream().mapToInt(Integer::intValue).toArray()
					);
				}
				finally {
					refreshing[0] = false;
					updateSelectionLabel.run();
				}
			};

			moduleList.addListSelectionListener(event -> {
				if (event.getValueIsAdjusting() || refreshing[0]) {
					return;
				}
				for (int i = 0; i < model.size(); i++) {
					selectedModules.remove(model.getElementAt(i));
				}
				selectedModules.addAll(moduleList.getSelectedValuesList());
				updateSelectionLabel.run();
			});

			filterField.getDocument().addDocumentListener(new DocumentListener() {
				@Override
				public void insertUpdate(DocumentEvent event) {
					refreshList.run();
				}

				@Override
				public void removeUpdate(DocumentEvent event) {
					refreshList.run();
				}

				@Override
				public void changedUpdate(DocumentEvent event) {
					refreshList.run();
				}
			});

			JButton selectVisibleButton = new JButton("Select Visible");
			selectVisibleButton.addActionListener(event -> {
				for (int i = 0; i < model.size(); i++) {
					selectedModules.add(model.getElementAt(i));
				}
				refreshList.run();
			});

			JButton clearVisibleButton = new JButton("Clear Visible");
			clearVisibleButton.addActionListener(event -> {
				for (int i = 0; i < model.size(); i++) {
					selectedModules.remove(model.getElementAt(i));
				}
				refreshList.run();
			});

			JButton clearAllButton = new JButton("Clear All");
			clearAllButton.addActionListener(event -> {
				selectedModules.clear();
				refreshList.run();
			});

			JButton okButton = new JButton("OK");
			okButton.addActionListener(event -> {
				resultHolder.add(new ArrayList<>(selectedModules));
				dialog.dispose();
			});

			JButton cancelButton = new JButton("Cancel");
			cancelButton.addActionListener(event -> dialog.dispose());

			JPanel topPanel = new JPanel(new java.awt.BorderLayout(8, 8));
			topPanel.setBorder(BorderFactory.createEmptyBorder(8, 8, 4, 8));
			topPanel.add(new JLabel("Filter modules:"), java.awt.BorderLayout.WEST);
			topPanel.add(filterField, java.awt.BorderLayout.CENTER);

			JPanel actionPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
			actionPanel.add(selectionLabel);
			actionPanel.add(selectVisibleButton);
			actionPanel.add(clearVisibleButton);
			actionPanel.add(clearAllButton);

			JPanel bottomPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT));
			bottomPanel.add(okButton);
			bottomPanel.add(cancelButton);

			JPanel northPanel = new JPanel(new java.awt.BorderLayout());
			northPanel.add(topPanel, java.awt.BorderLayout.NORTH);
			northPanel.add(actionPanel, java.awt.BorderLayout.SOUTH);

			JPanel content = new JPanel(new java.awt.BorderLayout(8, 8));
			content.add(northPanel, java.awt.BorderLayout.NORTH);
			content.add(new JScrollPane(moduleList), java.awt.BorderLayout.CENTER);
			content.add(bottomPanel, java.awt.BorderLayout.SOUTH);

			dialog.setContentPane(content);
			dialog.setPreferredSize(new Dimension(680, 620));
			dialog.getRootPane().setDefaultButton(okButton);
			refreshList.run();
			dialog.pack();
			dialog.setLocationRelativeTo(dialog.getOwner());
			dialog.setVisible(true);
		});

		if (resultHolder.isEmpty()) {
			return Collections.emptyList();
		}
		return resultHolder.get(0);
	}

	private JDialog createModuleChooserDialog() {
		java.awt.Window owner =
			KeyboardFocusManager.getCurrentKeyboardFocusManager().getActiveWindow();
		if (owner instanceof Frame) {
			return new JDialog((Frame) owner, "ContextUEFI focus modules", true);
		}
		if (owner instanceof Dialog) {
			return new JDialog((Dialog) owner, "ContextUEFI focus modules", true);
		}
		return new JDialog((Frame) null, "ContextUEFI focus modules", true);
	}

	private List<Dependency> buildDependencies(
			Map<String, List<ProviderInfo>> providersByGuid,
			Map<String, Set<String>> clientsByGuid) {
		List<Dependency> dependencies = new ArrayList<>();
		Set<String> seenEdges = new LinkedHashSet<>();

		for (Map.Entry<String, List<ProviderInfo>> entry : providersByGuid.entrySet()) {
			String guid = entry.getKey();
			Set<String> clients = clientsByGuid.get(guid);
			if (clients == null || clients.isEmpty()) {
				continue;
			}
			for (ProviderInfo provider : entry.getValue()) {
				for (String clientModule : clients) {
					String edgeKey = provider.moduleName + "\n" + clientModule + "\n" + guid;
					if (!seenEdges.add(edgeKey)) {
						continue;
					}
					Dependency dependency = new Dependency();
					dependency.providerModule = provider.moduleName;
					dependency.clientModule = clientModule;
					dependency.protocolName = provider.protocolName;
					dependency.guid = guid;
					dependency.providerService = provider.service;
					dependencies.add(dependency);
				}
			}
		}
		return dependencies;
	}

	private class GraphNavigator {
		private final List<Dependency> dependencies;
		private final Set<String> providerModules;
		private final Set<String> clientModules;
		private final List<Set<String>> history = new ArrayList<>();
		private GraphDisplay display;
		private Set<String> currentFocus;
		private boolean suppressFocusEvents;

		GraphNavigator(
				List<Dependency> dependencies,
				Set<String> providerModules,
				Set<String> clientModules) throws Exception {
			this.dependencies = dependencies;
			this.providerModules = providerModules;
			this.clientModules = clientModules;

			PluginTool tool = state.getTool();
			GraphDisplayBroker broker = tool.getService(GraphDisplayBroker.class);
			display = broker.getDefaultGraphDisplay(false, monitor);
			display.setGraphDisplayListener(new NavigationListener());
			display.addAction(new FocusSelectedAction());
			display.addAction(new BackAction());
			display.addAction(new FullGraphAction());
			installMouseWheelZoom(display);
		}

		void render(Set<String> focusModules, boolean pushHistory) throws Exception {
			Set<String> normalizedFocus = normalizeFocus(focusModules);
			if (pushHistory) {
				history.add(copyFocus(currentFocus));
			}
			currentFocus = copyFocus(normalizedFocus);

			AttributedGraph graph = buildGraph(normalizedFocus);
			if (graph.getVertexCount() == 0) {
				popup("No dependency edges found.");
				return;
			}

			suppressFocusEvents = true;
			try {
				showGraph(display, graph, normalizedFocus);
			}
			finally {
				suppressFocusEvents = false;
			}
			println("Graph nodes: " + graph.getVertexCount());
			println("Graph edges: " + graph.getEdgeCount());
		}

		private AttributedGraph buildGraph(Set<String> focusModules) {
			GraphType graphType = new GraphTypeBuilder("ContextUEFI Dependency Graph")
				.vertexType(PROVIDER_VERTEX)
				.vertexType(CLIENT_VERTEX)
				.vertexType(PROVIDER_AND_CLIENT_VERTEX)
				.vertexType(FOCUS_VERTEX)
				.edgeType(EDGE_TYPE)
				.build();
			AttributedGraph graph = new AttributedGraph("ContextUEFI dependency graph", graphType);
			Map<String, AttributedVertex> vertices = new HashMap<>();
			int edgeCount = 0;

			for (Dependency dependency : dependencies) {
				if (!shouldShow(dependency, focusModules)) {
					continue;
				}
				AttributedVertex source = vertex(
					graph,
					vertices,
					dependency.providerModule,
					providerModules,
					clientModules,
					focusModules
				);
				AttributedVertex target = vertex(
					graph,
					vertices,
					dependency.clientModule,
					providerModules,
					clientModules,
					focusModules
				);
				AttributedEdge edge = graph.addEdge(source, target, "edge-" + edgeCount++);
				edge.setEdgeType(EDGE_TYPE);
				edge.setDescription(
					dependency.protocolName + "\n" +
					dependency.guid + "\n" +
					dependency.providerService
				);
				edge.setAttribute("Protocol", dependency.protocolName);
				edge.setAttribute("GUID", dependency.guid);
				edge.setAttribute("Provider Service", dependency.providerService);
				edge.setAttribute("Provider", dependency.providerModule);
				edge.setAttribute("Client", dependency.clientModule);
			}

			if (graph.getVertexCount() == 0 && focusModules != null) {
				for (String moduleName : focusModules) {
					vertex(graph, vertices, moduleName, providerModules, clientModules, focusModules);
				}
			}
			return graph;
		}

		private boolean shouldShow(Dependency dependency, Set<String> focusModules) {
			if (focusModules == null || focusModules.isEmpty()) {
				return true;
			}
			return focusModules.contains(dependency.providerModule) ||
				focusModules.contains(dependency.clientModule);
		}

		private Set<String> normalizeFocus(Set<String> focusModules) {
			if (focusModules == null || focusModules.isEmpty()) {
				return null;
			}
			return new LinkedHashSet<>(focusModules);
		}

		private Set<String> copyFocus(Set<String> focusModules) {
			if (focusModules == null || focusModules.isEmpty()) {
				return null;
			}
			return new LinkedHashSet<>(focusModules);
		}

		private void focusOnVertex(AttributedVertex vertex) {
			if (vertex == null || suppressFocusEvents) {
				return;
			}
			try {
				render(new LinkedHashSet<>(List.of(vertex.getId())), true);
			}
			catch (Exception e) {
				printerr("Unable to focus module " + vertex.getId() + ": " + e.getMessage());
			}
		}

		private void focusSelectedVertices() {
			try {
				Set<AttributedVertex> selectedVertices = display.getSelectedVertices();
				Set<String> moduleNames = new LinkedHashSet<>();
				if (selectedVertices != null) {
					for (AttributedVertex selectedVertex : selectedVertices) {
						moduleNames.add(selectedVertex.getId());
					}
				}
				if (moduleNames.isEmpty() && display.getFocusedVertex() != null) {
					moduleNames.add(display.getFocusedVertex().getId());
				}
				if (moduleNames.isEmpty()) {
					popup("Select one or more module nodes first.");
					return;
				}
				render(moduleNames, true);
			}
			catch (Exception e) {
				printerr("Unable to focus selected modules: " + e.getMessage());
			}
		}

		private void goBack() {
			if (history.isEmpty()) {
				popup("No previous ContextUEFI graph focus.");
				return;
			}
			Set<String> previousFocus = history.remove(history.size() - 1);
			try {
				render(previousFocus, false);
			}
			catch (Exception e) {
				printerr("Unable to go back: " + e.getMessage());
			}
		}

		private void showFullGraph() {
			try {
				render(null, true);
			}
			catch (Exception e) {
				printerr("Unable to show full graph: " + e.getMessage());
			}
		}

		private class NavigationListener implements GraphDisplayListener {
			@Override
			public void selectionChanged(Set<AttributedVertex> vertices) {
				// Selection is used by the "Focus selected module(s)" action.
			}

			@Override
			public void locationFocusChanged(AttributedVertex vertex) {
				focusOnVertex(vertex);
			}

			@Override
			public GraphDisplayListener cloneWith(GraphDisplay newDisplay) {
				display = newDisplay;
				installMouseWheelZoom(display);
				return this;
			}

			@Override
			public void dispose() {
				// Nothing to dispose.
			}
		}

		private class FocusSelectedAction extends DockingAction {
			FocusSelectedAction() {
				super("Focus selected module(s)", "ContextUEFI");
				setPopupMenuData(new MenuData(new String[] {
					"ContextUEFI",
					"Focus selected module(s)"
				}));
			}

			@Override
			public void actionPerformed(ActionContext context) {
				focusSelectedVertices();
			}
		}

		private class BackAction extends DockingAction {
			BackAction() {
				super("Back to previous focus", "ContextUEFI");
				setPopupMenuData(new MenuData(new String[] {
					"ContextUEFI",
					"Back to previous focus"
				}));
				setKeyBindingData(new KeyBindingData(KeyEvent.VK_Z, InputEvent.CTRL_DOWN_MASK));
			}

			@Override
			public void actionPerformed(ActionContext context) {
				goBack();
			}
		}

		private class FullGraphAction extends DockingAction {
			FullGraphAction() {
				super("Show full dependency graph", "ContextUEFI");
				setPopupMenuData(new MenuData(new String[] {
					"ContextUEFI",
					"Show full dependency graph"
				}));
			}

			@Override
			public void actionPerformed(ActionContext context) {
				showFullGraph();
			}
		}

		private void installMouseWheelZoom(GraphDisplay graphDisplay) {
			try {
				VisualizationViewer<?, ?> viewer = getViewer(graphDisplay);
				JComponent component = viewer.getComponent();
				if (Boolean.TRUE.equals(component.getClientProperty(WHEEL_ZOOM_INSTALLED_PROPERTY))) {
					return;
				}

				ScalingControl scaler = new CrossoverScalingControl();
				component.addMouseWheelListener(event -> {
					if (event.isConsumed()) {
						return;
					}

					double rotation = event.getPreciseWheelRotation();
					if (rotation == 0.0) {
						return;
					}

					double amount = Math.pow(WHEEL_ZOOM_STEP, -rotation);
					Point2D point = event.getPoint();
					scaler.scale(viewer, amount, amount, point);
					event.consume();
					viewer.repaint();
				});
				component.putClientProperty(WHEEL_ZOOM_INSTALLED_PROPERTY, Boolean.TRUE);
			}
			catch (Exception e) {
				printerr("Unable to install mouse wheel zoom: " + e.getMessage());
			}
		}

		private VisualizationViewer<?, ?> getViewer(GraphDisplay graphDisplay) throws Exception {
			Field viewerField = graphDisplay.getClass().getDeclaredField("viewer");
			viewerField.setAccessible(true);
			Object viewer = viewerField.get(graphDisplay);
			if (!(viewer instanceof VisualizationViewer)) {
				throw new IllegalStateException("Graph display viewer is unavailable");
			}
			return (VisualizationViewer<?, ?>) viewer;
		}
	}

	private ModuleInfo[] loadModules(File jsonFile) throws Exception {
		Gson gson = new Gson();
		try (Reader reader = new FileReader(jsonFile)) {
			JsonElement root = JsonParser.parseReader(reader);
			if (root.isJsonArray()) {
				return gson.fromJson(root, ModuleInfo[].class);
			}
			if (root.isJsonObject()) {
				return new ModuleInfo[] { gson.fromJson(root, ModuleInfo.class) };
			}
		}
		throw new IllegalArgumentException("Unsupported JSON root in " + jsonFile);
	}

	private AttributedVertex vertex(
			AttributedGraph graph,
			Map<String, AttributedVertex> vertices,
			String moduleName,
			Set<String> providerModules,
			Set<String> clientModules,
			Set<String> focusModules) {
		AttributedVertex existing = vertices.get(moduleName);
		if (existing != null) {
			return existing;
		}

		AttributedVertex vertex = graph.addVertex(moduleName, moduleName);
		boolean provider = providerModules.contains(moduleName);
		boolean client = clientModules.contains(moduleName);
		if (focusModules != null && focusModules.contains(moduleName)) {
			vertex.setVertexType(FOCUS_VERTEX);
		}
		else if (provider && client) {
			vertex.setVertexType(PROVIDER_AND_CLIENT_VERTEX);
		}
		else if (provider) {
			vertex.setVertexType(PROVIDER_VERTEX);
		}
		else {
			vertex.setVertexType(CLIENT_VERTEX);
		}
		vertex.setDescription(moduleName);
		vertices.put(moduleName, vertex);
		return vertex;
	}

	private GraphDisplayOptions graphOptions(AttributedGraph graph) {
		return new GraphDisplayOptionsBuilder(graph.getGraphType())
			.vertex(PROVIDER_VERTEX, VertexShape.RECTANGLE, new Color(0x2F, 0x6F, 0xC7))
			.vertex(CLIENT_VERTEX, VertexShape.RECTANGLE, new Color(0x3F, 0x8F, 0x5F))
			.vertex(PROVIDER_AND_CLIENT_VERTEX, VertexShape.RECTANGLE, new Color(0xC7, 0x8B, 0x2F))
			.vertex(FOCUS_VERTEX, VertexShape.RECTANGLE, new Color(0xD8, 0x46, 0x2F))
			.edge(EDGE_TYPE, new Color(0x66, 0x66, 0x66))
			.defaultVertexShape(VertexShape.RECTANGLE)
			.defaultLayoutAlgorithm("Compact Hierarchical")
			.maxNodeCount(20000)
			.build();
	}

	private void showGraph(GraphDisplay display, AttributedGraph graph, Set<String> focusModules)
			throws Exception {
		GraphDisplayOptions options = graphOptions(graph);
		String title = focusModules == null || focusModules.isEmpty()
			? "ContextUEFI dependency graph"
			: "ContextUEFI dependencies for " + focusModules;
		display.setGraph(graph, options, title, false, monitor);
	}
}

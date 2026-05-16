# ContextUEFI Ghidra Script

## ContextUefiDependencyGraph.java

This script loads a ContextUEFI `*-context.json` file and draws the module
dependency graph using Ghidra's native graph display.

It builds edges from protocol usage:

- Providers: `InstallProtocolInterface`, `InstallMultipleProtocolInterfaces`
- Clients: `LocateProtocol`, `OpenProtocol`
- Edge direction: provider module -> client module

## Install

1. Open Ghidra.
2. Open `Window -> Script Manager`.
3. Click `Manage Script Directories`.
4. Add this folder:

```text
ghidra_scripts/
```

## Use

1. Open any Ghidra project/program.
2. Open `Window -> Script Manager`.
3. Find `ContextUefiDependencyGraph.java` under `ContextUEFI`.
4. Run the script.
5. Select a `*-context.json` file.

## Navigation

- `Focus one module`: choose one module and display only its direct relationships.
- `Focus some modules`: select multiple modules from a filterable list.
- `Full graph`: show all dependency edges.
- Double-click a module node to focus it.
- Right-click the graph and use `ContextUEFI -> Focus selected module(s)`.
- Press `Ctrl+Z` or use `ContextUEFI -> Back to previous focus`.
- Use the mouse wheel to zoom in and out.

## Colors

- Blue: provider only.
- Green: client only.
- Orange: provider and client.
- Red: focused module.

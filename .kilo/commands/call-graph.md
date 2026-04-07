---
description: Trace callers or callees using the call graph
---

Trace function dependencies using the `call_graph` tool.

User input: $ARGUMENTS

Interpret input as follows:
- Default to `direction="callers"` unless input asks for callees/calls/makes calls.
- `name=<function>` or plain text function name sets `name`.
- `symbolId=<id>` is required for `direction="callees"`.

Execution flow:
1. If direction is `callers`, call `call_graph` with `{ name, direction: "callers" }`.
2. If direction is `callees` and `symbolId` is present, call `call_graph` with `{ name, direction: "callees", symbolId }`.
3. If direction is `callees` and `symbolId` is missing, first call `call_graph` with `direction="callers"` to get symbol IDs, then ask the user to choose one if multiple are returned.

Examples:
- `/call-graph Database` → callers for `Database`
- `/call-graph callers name=Indexer` → callers for `Indexer`
- `/call-graph callees name=Database symbolId=sym_abc123` → callees for selected symbol

If output says no callers found, suggest running `/index force` first.

"""Flask-SocketIO namespaces — per .skillgrid/ARCHITECTURE.md §3.6.

SSE is the primary push channel (ADR-0009); WebSocket remains for
bidirectional cases (exec/terminal). ``logs``/``events`` are stubs until the
observability + exec changes register their handlers on the SocketIO
instance."""

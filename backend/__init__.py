"""MCP-сервер MCP app (backend/server.py).

GUI запускает его дочерним процессом: `python main.py --backend` в исходниках,
`MCPApp.exe --backend` в сборке. Параметры — через переменные окружения
(MCP_PUBLIC_URL, MCP_SECRET_TOKEN и др., см. ServiceManager._server_env).
"""

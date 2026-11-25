"""Modular page views for MCP-app MainWindow."""
from __future__ import annotations

__all__ = [
    "ClientsPage",
    "ConnectionsPage",
    "GatewayPage",
    "HomePage",
    "LogsPage",
    "PageScaffold",
    "PlannedPage",
    "SecurityPage",
    "SettingsPage",
    "TasksPage",
]

from app.ui.pages.base import PageScaffold
from app.ui.pages.clients_page import ClientsPage
from app.ui.pages.connections_page import ConnectionsPage
from app.ui.pages.gateway_page import GatewayPage
from app.ui.pages.home_page import HomePage
from app.ui.pages.logs_page import LogsPage
from app.ui.pages.planned_page import PlannedPage
from app.ui.pages.security_page import SecurityPage
from app.ui.pages.settings_page import SettingsPage
from app.ui.pages.tasks_page import TasksPage

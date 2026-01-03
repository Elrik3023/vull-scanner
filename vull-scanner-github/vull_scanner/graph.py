"""LangGraph workflow definition for the vulnerability scanner."""

from langgraph.graph import StateGraph, START, END
from langgraph.prebuilt import ToolNode

from vull_scanner.state import ScannerState
from vull_scanner.nodes.input_node import input_node
from vull_scanner.nodes.port_scanner import port_scanner_node
from vull_scanner.nodes.login_finder import (
    login_finder_node,
    should_continue,
    parse_login_results_node,
)
from vull_scanner.nodes.credential_tester import credential_tester_node
from vull_scanner.nodes.result_printer import result_printer_node
from vull_scanner.tools import TOOLS


def route_after_port_scan(state: ScannerState) -> str:
    """Route based on port scan results.

    Args:
        state: Current scanner state.

    Returns:
        Next node name.
    """
    port_scan = state.get("port_scan")
    if port_scan and port_scan.base_url:
        return "login_finder"
    return "result_printer"


def route_after_login_discovery(state: ScannerState) -> str:
    """Route based on login discovery results.

    Args:
        state: Current scanner state.

    Returns:
        Next node name.
    """
    endpoints = state.get("login_endpoints", [])
    if endpoints:
        return "credential_tester"
    return "result_printer"


def create_scanner_graph() -> StateGraph:
    """Create and wire the vulnerability scanner graph.

    Graph structure:
        START -> input -> port_scanner -> [conditional]
                                              |
                              +---------------+---------------+
                              |                               |
                        (ports open)                    (ports closed)
                              |                               |
                       login_finder <--+               result_printer -> END
                              |        |
                       [conditional]   |
                         |       |     |
                       tools ----+     |
                                       |
                       parse_results --+
                              |
                       [conditional]
                         |       |
                   (found)     (none)
                       |         |
                credential_tester|
                       |         |
                result_printer <-+
                       |
                      END

    Returns:
        Configured StateGraph.
    """
    # Create the graph with our state schema
    graph = StateGraph(ScannerState)

    # Add all nodes
    graph.add_node("input", input_node)
    graph.add_node("port_scanner", port_scanner_node)
    graph.add_node("login_finder", login_finder_node)
    graph.add_node("tools", ToolNode(TOOLS))
    graph.add_node("parse_results", parse_login_results_node)
    graph.add_node("credential_tester", credential_tester_node)
    graph.add_node("result_printer", result_printer_node)

    # Define edges
    # START -> input
    graph.add_edge(START, "input")

    # input -> port_scanner
    graph.add_edge("input", "port_scanner")

    # port_scanner -> conditional (login_finder or result_printer)
    graph.add_conditional_edges(
        "port_scanner",
        route_after_port_scan,
        {
            "login_finder": "login_finder",
            "result_printer": "result_printer",
        },
    )

    # login_finder -> conditional (tools or parse_results)
    graph.add_conditional_edges(
        "login_finder",
        should_continue,
        {
            "tools": "tools",
            "parse_results": "parse_results",
        },
    )

    # tools -> login_finder (loop back)
    graph.add_edge("tools", "login_finder")

    # parse_results -> conditional (credential_tester or result_printer)
    graph.add_conditional_edges(
        "parse_results",
        route_after_login_discovery,
        {
            "credential_tester": "credential_tester",
            "result_printer": "result_printer",
        },
    )

    # credential_tester -> result_printer
    graph.add_edge("credential_tester", "result_printer")

    # result_printer -> END
    graph.add_edge("result_printer", END)

    return graph


def compile_scanner():
    """Compile the scanner graph for execution.

    Returns:
        Compiled graph ready for invocation.
    """
    graph = create_scanner_graph()
    return graph.compile()

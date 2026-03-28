"""
NL2Firewall Test Suite - Triplet Testing (NL Query, IR, CLI)
=============================================================

Two Testing Modes:
1. Mocked Mode (default): Tests compiler only using pre-defined IR
   - Fast, no API costs
   - Validates compiler logic in isolation

2. Live Mode (--live): Tests full pipeline including LLM
   - Validates NL → IR → CLI generation
   - Requires GROQ_API_KEY

Usage:
  python tests/test_triplets.py              # Mocked mode
  python tests/test_triplets.py --live       # Live mode (requires API key)

"""

import datetime
import difflib
import json
import os
import sys
import time
import unittest
import warnings
from pathlib import Path
from typing import Any, Dict, List

from dotenv import load_dotenv

# Suppress async ResourceWarnings (unclosed transports from asyncio.run in loop)
warnings.filterwarnings("ignore", category=ResourceWarning)

# Add project root to path
ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT))

# Handle command line arguments
ENABLE_LIVE_TESTS = False
if "--live" in sys.argv:
    ENABLE_LIVE_TESTS = True
    sys.argv.remove("--live")

# Load environment
env_path = ROOT / ".env"
if env_path.exists():
    load_dotenv(env_path)

# If mocked mode and no API key, provide dummy
if not ENABLE_LIVE_TESTS and "GROQ_API_KEY" not in os.environ:
    os.environ["GROQ_API_KEY"] = "dummy-key-for-mocked-tests"

# Import after env setup
from app.compiler.cisco import CiscoIOSCompiler
from app.models.ir import (
    Action,
    CanonicalRule,
    Direction,
    Endpoint,
    InterfaceTarget,
    PipelineState,
    PipelineStatus,
    PortOperator,
    PortSpec,
    Protocol,
)
from app.snmt.loader import SNMTLoader, set_active_snmt

# For live tests - import pipeline components
if ENABLE_LIVE_TESTS:
    import asyncio

    from langgraph.checkpoint.memory import MemorySaver

    from app.agents.pipeline import build_pipeline_graph, get_pipeline


class TestPipelineTriplets(unittest.TestCase):
    """Test suite for NL → IR → CLI pipeline."""

    # ANSI Color Codes
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    RED = "\033[91m"
    RESET = "\033[0m"
    BOLD = "\033[1m"

    def setUp(self):
        """Initialize test environment."""
        # Load SNMT
        self.snmt_path = ROOT / "data" / "networks" / "ccna_lab.yaml"
        self.snmt = SNMTLoader.from_file(self.snmt_path)
        self.compiler = CiscoIOSCompiler(self.snmt)

        # Set SNMT globally so pipeline nodes can access it via require_snmt()
        set_active_snmt(self.snmt)

        # Load test triplets from the new full IR test cases file
        self.test_cases_path = ROOT / "tests" / "ccna_lab_test_cases.json"
        with open(self.test_cases_path, "r") as f:
            data = json.load(f)
            self.all_triplets = data["test_cases"]
            print(
                f"\n{self.BLUE}Loaded {len(self.all_triplets)} test cases from: {data['test_suite']}{self.RESET}"
            )
            print(f"{self.BLUE}Version: {data.get('version', 'N/A')}{self.RESET}")
            print(f"{self.GREEN}SNMT loaded: {self.snmt_path.name}{self.RESET}")

    def test_triplets(self):
        """Main test dispatcher - runs mocked or live mode."""
        if ENABLE_LIVE_TESTS:
            self._run_live_tests()
        else:
            self._run_mocked_tests()

    def _run_mocked_tests(self):
        """Run mocked tests (compiler only, no LLM)."""
        print(f"\n{self.BOLD}{'=' * 70}{self.RESET}")
        print(f"{self.BOLD}RUNNING MOCKED TESTS (Compiler Validation Only){self.RESET}")
        print(f"{self.BOLD}{'=' * 70}{self.RESET}\n")

        passed = 0
        failed = 0

        for case in self.all_triplets:
            with self.subTest(case_id=case["id"]):
                print(
                    f"\n{self.BLUE}Testing: {case['id']}{self.RESET} - {case['description']}"
                )

                try:
                    # Convert JSON IR to CanonicalRule
                    canonical_rule = self._json_to_canonical_rule(case["expected_ir"])

                    # Compile
                    compiled = self.compiler.compile(canonical_rule)
                    actual_cli = compiled.to_cisco_config()

                    # Compare with expected CLI
                    expected_cli = case["expected_cli"].strip()
                    actual_cli = actual_cli.strip()

                    if expected_cli == actual_cli:
                        print(f"  {self.GREEN}✓ PASS{self.RESET} - CLI matches exactly")
                        passed += 1
                    else:
                        # Calculate similarity
                        similarity = (
                            difflib.SequenceMatcher(
                                None, expected_cli, actual_cli
                            ).ratio()
                            * 100
                        )
                        print(
                            f"  {self.RED}✗ FAIL{self.RESET} - CLI mismatch (Similarity: {similarity:.2f}%)"
                        )
                        print(f"\n  Expected:\n{self._indent(expected_cli, 4)}")
                        print(f"\n  Got:\n{self._indent(actual_cli, 4)}")
                        failed += 1

                except Exception as e:
                    print(f"  {self.RED}✗ ERROR{self.RESET} - {str(e)}")
                    failed += 1

        # Summary
        self._print_summary(passed, failed, len(self.all_triplets))

    def _run_live_tests(self):
        """Run live tests (full pipeline with LLM, auto-approve enabled)."""
        print(f"\n{self.BOLD}{'=' * 70}{self.RESET}")
        print(f"{self.BOLD}RUNNING LIVE TESTS (Full Pipeline with LLM){self.RESET}")
        print(f"{self.BOLD}{'=' * 70}{self.RESET}\n")

        # Setup logging
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        log_dir = ROOT / "tests" / "output"
        log_dir.mkdir(exist_ok=True)
        log_path = log_dir / f"{timestamp}_live_test_log.txt"

        print(f"{self.YELLOW}Logging to: {log_path}{self.RESET}\n")

        # Similarity threshold
        SIMILARITY_THRESHOLD = 95.0  # Allow 95% match for CLI

        passed = 0
        failed = 0
        failed_cases = []

        # Create a pipeline without interrupt_before for testing (auto-approve)
        # This allows the pipeline to run straight through without pausing
        pipeline_graph = build_pipeline_graph()
        test_pipeline = pipeline_graph.compile(
            checkpointer=MemorySaver(),
            # NO interrupt_before - runs straight through
        )

        with open(log_path, "w") as log:
            log.write(f"NL2Firewall Live Test Run: {timestamp}\n")
            log.write(f"Mode: Full Pipeline with LLM (auto-approve enabled)\n")
            log.write("=" * 70 + "\n\n")

            for case in self.all_triplets:
                with self.subTest(case_id=case["id"]):
                    print(f"\n{self.BLUE}{'─' * 70}{self.RESET}")
                    print(
                        f"{self.BLUE}LIVE Test: {case['id']}{self.RESET} - {case['description']}"
                    )
                    print(f"  NL Query: {case['nl_query'][:60]}...")

                    log.write(f"TEST: {case['id']}\n")
                    log.write(f"Description: {case['description']}\n")
                    log.write(f"NL Query: {case['nl_query']}\n")
                    log.write("-" * 70 + "\n")

                    try:
                        # Create initial pipeline state with auto-approve
                        session_id = f"test_{case['id']}_{timestamp}"
                        initial_state = PipelineState(
                            intent_text=case["nl_query"],
                            session_id=session_id,
                            status=PipelineStatus.PENDING,
                            current_step="Starting test pipeline",
                            human_feedback="approve",  # Auto-approve to skip review
                        )

                        config = {"configurable": {"thread_id": session_id}}

                        # Run the pipeline asynchronously
                        print(f"  {self.YELLOW}Running LLM pipeline...{self.RESET}")

                        final_state = asyncio.run(
                            self._run_pipeline_async(
                                test_pipeline, initial_state, config
                            )
                        )

                        # Check if pipeline succeeded
                        if final_state.status == PipelineStatus.FAILED:
                            raise Exception(f"Pipeline failed: {final_state.error}")

                        if final_state.status == PipelineStatus.BLOCKED:
                            raise Exception(
                                f"Pipeline blocked by safety gate: {final_state.error}"
                            )

                        # Get the generated CLI
                        actual_cli = final_state.final_config or ""
                        actual_cli = actual_cli.strip()

                        # Compare CLI
                        expected_cli = case["expected_cli"].strip()
                        similarity = (
                            difflib.SequenceMatcher(
                                None, expected_cli, actual_cli
                            ).ratio()
                            * 100
                        )

                        # Log generated IR for debugging
                        if final_state.resolved_rule:
                            log.write(
                                f"GENERATED IR:\n{final_state.resolved_rule.model_dump_json(indent=2)}\n\n"
                            )

                        if similarity >= SIMILARITY_THRESHOLD:
                            print(
                                f"  {self.GREEN}✓ PASS{self.RESET} - CLI similarity: {similarity:.2f}%"
                            )
                            log.write(
                                f"STATUS: PASS (Similarity: {similarity:.2f}%)\n\n"
                            )
                            passed += 1
                        else:
                            print(
                                f"  {self.RED}✗ FAIL{self.RESET} - CLI similarity: {similarity:.2f}% (threshold: {SIMILARITY_THRESHOLD}%)"
                            )
                            print(f"\n  Expected:\n{self._indent(expected_cli, 4)}")
                            print(f"\n  Got:\n{self._indent(actual_cli, 4)}")

                            log.write(f"STATUS: FAIL (Similarity: {similarity:.2f}%)\n")
                            log.write(f"EXPECTED CLI:\n{expected_cli}\n\n")
                            log.write(f"ACTUAL CLI:\n{actual_cli}\n\n")

                            failed += 1
                            failed_cases.append(case["id"])

                    except Exception as e:
                        print(f"  {self.RED}✗ ERROR{self.RESET} - {str(e)}")
                        log.write(f"STATUS: ERROR\nReason: {str(e)}\n\n")
                        failed += 1
                        failed_cases.append(case["id"])
                    
                    # Small delay between tests to avoid rate limiting (TPM)
                    time.sleep(2)

            # Write summary to log
            log.write("=" * 70 + "\n")
            log.write("SUMMARY\n")
            log.write("=" * 70 + "\n")
            log.write(f"Total: {len(self.all_triplets)}\n")
            log.write(f"Passed: {passed}\n")
            log.write(f"Failed: {failed}\n")
            if failed_cases:
                log.write("\nFailed Cases:\n")
                for case_id in failed_cases:
                    log.write(f"  - {case_id}\n")

        # Print summary
        self._print_summary(passed, failed, len(self.all_triplets), failed_cases)
        print(f"\n{self.YELLOW}Full log saved to: {log_path}{self.RESET}")

    async def _run_pipeline_async(self, pipeline, initial_state, config):
        """Run the LangGraph pipeline and return final state."""
        final_state = None

        async for event in pipeline.astream(initial_state, config=config):
            # Each event contains the output from a node
            node_name = list(event.keys())[0] if event else "unknown"
            # Update final_state from checkpoint
            checkpoint = pipeline.get_state(config)
            if checkpoint and checkpoint.values:
                # Get the state from checkpoint values
                final_state = checkpoint.values

        # Get final state from checkpoint
        checkpoint = pipeline.get_state(config)
        if checkpoint and checkpoint.values:
            # Convert dict back to PipelineState if needed
            if isinstance(checkpoint.values, dict):
                final_state = PipelineState(**checkpoint.values)
            else:
                final_state = checkpoint.values

        return final_state

    def _json_to_canonical_rule(self, ir_json: Dict[str, Any]) -> CanonicalRule:
        """
        Convert JSON IR to CanonicalRule object.

        The JSON now contains the FULL CanonicalRule structure with:
        - Complete Endpoint objects (entity_name, router, interface, prefix, zone)
        - Complete PortSpec objects (operator, port, port_high)
        - Complete InterfaceTarget objects (router, interface, direction, zone)
        - All CanonicalRule fields
        """

        # Parse protocol enum
        protocol_map = {
            "tcp": Protocol.TCP,
            "udp": Protocol.UDP,
            "icmp": Protocol.ICMP,
            "ip": Protocol.IP,
        }
        protocol = protocol_map.get(
            ir_json.get("protocol", "tcp").lower(), Protocol.TCP
        )

        # Parse action enum
        action_map = {
            "deny": Action.DENY,
            "permit": Action.PERMIT,
            "reject": Action.REJECT,
        }
        action = action_map.get(ir_json.get("action", "deny").lower(), Action.DENY)

        # Parse direction enum
        direction_map = {"inbound": Direction.INBOUND, "outbound": Direction.OUTBOUND}
        direction = direction_map.get(
            ir_json.get("direction", "inbound").lower(), Direction.INBOUND
        )

        # Parse sources (full Endpoint objects from JSON)
        sources = []
        for src in ir_json.get("sources", []):
            sources.append(
                Endpoint(
                    entity_name=src["entity_name"],
                    router=src["router"],
                    interface=src["interface"],
                    prefix=src["prefix"],
                )
            )

        # Parse destinations (full Endpoint objects from JSON)
        destinations = []
        for dst in ir_json.get("destinations", []):
            destinations.append(
                Endpoint(
                    entity_name=dst["entity_name"],
                    router=dst["router"],
                    interface=dst["interface"],
                    prefix=dst["prefix"],
                )
            )

        # Parse dst_ports (full PortSpec objects from JSON)
        dst_ports = []
        for port in ir_json.get("dst_ports", []):
            operator_map = {
                "eq": PortOperator.EQ,
                "neq": PortOperator.NEQ,
                "lt": PortOperator.LT,
                "gt": PortOperator.GT,
                "range": PortOperator.RANGE,
                "any": PortOperator.ANY,
            }
            dst_ports.append(
                PortSpec(
                    operator=operator_map.get(
                        port["operator"].lower(), PortOperator.EQ
                    ),
                    port=port.get("port"),
                    port_high=port.get("port_high"),
                )
            )

        # Parse src_ports (usually empty)
        src_ports = []
        for port in ir_json.get("src_ports", []):
            operator_map = {
                "eq": PortOperator.EQ,
                "neq": PortOperator.NEQ,
                "lt": PortOperator.LT,
                "gt": PortOperator.GT,
                "range": PortOperator.RANGE,
                "any": PortOperator.ANY,
            }
            src_ports.append(
                PortSpec(
                    operator=operator_map.get(
                        port["operator"].lower(), PortOperator.EQ
                    ),
                    port=port.get("port"),
                    port_high=port.get("port_high"),
                )
            )

        # Parse interfaces (full InterfaceTarget objects from JSON)
        interfaces = []
        for iface in ir_json.get("interfaces", []):
            iface_direction = direction_map.get(
                iface["direction"].lower(), Direction.INBOUND
            )
            interfaces.append(
                InterfaceTarget(
                    router=iface["router"],
                    interface=iface["interface"],
                    direction=iface_direction,
                )
            )

        # Create the CanonicalRule with all fields
        return CanonicalRule(
            rule_name=ir_json.get("rule_name", "test_rule"),
            description=ir_json.get("description", ""),
            intent_text=ir_json.get("intent_text", ""),
            sources=sources,
            destinations=destinations,
            protocol=protocol,
            src_ports=src_ports,
            dst_ports=dst_ports,
            source_is_any=ir_json.get("source_is_any", False),
            destination_is_any=ir_json.get("destination_is_any", False),
            action=action,
            direction=direction,
            interfaces=interfaces,
            tcp_established=ir_json.get("tcp_established", False),
            icmp_type=ir_json.get("icmp_type"),
            icmp_code=ir_json.get("icmp_code"),
            time_range=ir_json.get("time_range"),
            logging=ir_json.get("logging", False),
            confidence=ir_json.get("confidence", 1.0),
            ambiguities=ir_json.get("ambiguities", []),
        )

    def _print_summary(
        self, passed: int, failed: int, total: int, failed_cases: List[str] = None
    ):
        """Print test summary."""
        print(f"\n\n{self.BOLD}{'=' * 70}{self.RESET}")
        print(f"{self.BOLD}TEST SUMMARY{self.RESET}")
        print(f"{self.BOLD}{'=' * 70}{self.RESET}")
        print(f"Total Tests:  {total}")
        print(f"{self.GREEN}Passed:       {passed}{self.RESET}")
        print(f"{self.RED}Failed:       {failed}{self.RESET}")

        if failed_cases:
            print(f"\n{self.RED}Failed Cases:{self.RESET}")
            for case_id in failed_cases:
                print(f"  - {case_id}")

        print(f"{self.BOLD}{'=' * 70}{self.RESET}\n")

    @staticmethod
    def _indent(text: str, spaces: int) -> str:
        """Indent text by n spaces."""
        indent = " " * spaces
        return "\n".join(indent + line for line in text.split("\n"))


if __name__ == "__main__":
    unittest.main()

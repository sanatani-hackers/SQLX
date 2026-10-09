"""SQLMap decision engine for intelligent automation."""

import logging
from typing import List, Dict, Any, Optional
from dataclasses import dataclass
from enum import Enum

from sqlx.sqlmap.core_bridge import Finding

logger = logging.getLogger(__name__)


class ActionType(Enum):
    """Types of actions the agent can take."""
    CONTINUE_TESTING = "continue_testing"
    ENUMERATE_DATABASES = "enumerate_databases"
    ENUMERATE_DATABASES_BLIND = "enumerate_databases_blind"
    ENUMERATE_TABLES = "enumerate_tables"
    ENUMERATE_COLUMNS = "enumerate_columns"
    DUMP_TABLE = "dump_table"
    TEST_WAF_BYPASS = "test_waf_bypass"
    FINGERPRINT_DBMS = "fingerprint_dbms"
    GET_PRIVILEGES = "get_privileges"
    ESCALATE_PRIVILEGES = "escalate_privileges"
    TEST_STACKED_QUERIES = "test_stacked_queries"
    SAVE_FINDINGS = "save_findings"
    STOP = "stop"


class Priority(Enum):
    """Action priority levels."""
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


@dataclass
class Action:
    """Represents an action the agent should take."""
    type: ActionType
    priority: Priority
    reason: str
    finding: Optional[Finding] = None
    findings: Optional[List[Finding]] = None
    metadata: Optional[Dict[str, Any]] = None

    def __lt__(self, other):
        """Allow sorting by priority."""
        return self.priority.value > other.priority.value  # Higher priority first


class SQLMapDecisionEngine:
    """Make intelligent decisions based on SQLMap findings."""

    def __init__(self, target_profile=None, session=None):
        self.target_profile = target_profile
        self.session = session
        self._action_history: List[Action] = []

    def analyze_findings(self, findings: List[Finding]) -> List[Action]:
        """
        Given a list of findings, decide what to do next.

        Args:
            findings: List of SQL injection findings

        Returns:
            List of recommended actions, sorted by priority
        """
        actions = []

        if not findings:
            actions.append(Action(
                type=ActionType.CONTINUE_TESTING,
                priority=Priority.MEDIUM,
                reason='No injections found yet, continue testing'
            ))
            return actions

        # Always save findings first
        actions.append(Action(
            type=ActionType.SAVE_FINDINGS,
            priority=Priority.CRITICAL,
            reason=f'Save {len(findings)} discovered injections',
            findings=findings
        ))

        # Group findings by injection type and parameter
        by_type = self._group_by_injection_type(findings)
        by_param = self._group_by_parameter(findings)

        # Analyze by injection type
        for injection_type, type_findings in by_type.items():
            best_finding = self._select_best_finding(type_findings)

            if injection_type == 'union':
                # Union-based: fastest for data extraction
                actions.extend(self._plan_union_exploitation(best_finding))

            elif injection_type == 'error':
                # Error-based: fast and reliable
                actions.extend(self._plan_error_exploitation(best_finding))

            elif injection_type == 'boolean':
                # Boolean-based: slower but reliable
                actions.extend(self._plan_blind_exploitation(best_finding, 'boolean'))

            elif injection_type == 'time':
                # Time-based: very slow, use as last resort
                actions.append(Action(
                    type=ActionType.ENUMERATE_DATABASES_BLIND,
                    priority=Priority.LOW,
                    reason='Time-based blind injection (slow)',
                    finding=best_finding
                ))

            elif injection_type == 'stacked':
                # Stacked queries: potential for command execution
                actions.extend(self._plan_stacked_exploitation(best_finding))

        # Fingerprint DBMS if not already done
        if any(f.dbms is None for f in findings):
            actions.append(Action(
                type=ActionType.FINGERPRINT_DBMS,
                priority=Priority.HIGH,
                reason='Identify database management system',
                finding=findings[0]
            ))

        # Test for WAF if low confidence
        low_confidence = [f for f in findings if f.confidence < 0.5]
        if low_confidence:
            actions.append(Action(
                type=ActionType.TEST_WAF_BYPASS,
                priority=Priority.HIGH,
                reason=f'{len(low_confidence)} findings have low confidence, may indicate WAF',
                finding=low_confidence[0]
            ))

        # Sort by priority and return
        actions.sort()
        self._action_history.extend(actions)
        return actions

    def _group_by_injection_type(self, findings: List[Finding]) -> Dict[str, List[Finding]]:
        """Group findings by injection type."""
        by_type = {}
        for finding in findings:
            injection_type = finding.injection_type or 'unknown'
            by_type.setdefault(injection_type, []).append(finding)
        return by_type

    def _group_by_parameter(self, findings: List[Finding]) -> Dict[str, List[Finding]]:
        """Group findings by parameter."""
        by_param = {}
        for finding in findings:
            param = finding.parameter or 'unknown'
            by_param.setdefault(param, []).append(finding)
        return by_param

    def _select_best_finding(self, findings: List[Finding]) -> Finding:
        """Select the best finding from a list (highest confidence)."""
        return max(findings, key=lambda f: f.confidence)

    def _plan_union_exploitation(self, finding: Finding) -> List[Action]:
        """Plan exploitation using union-based injection."""
        return [
            Action(
                type=ActionType.ENUMERATE_DATABASES,
                priority=Priority.HIGH,
                reason='Union-based injection allows fast data extraction',
                finding=finding
            ),
            Action(
                type=ActionType.ENUMERATE_TABLES,
                priority=Priority.HIGH,
                reason='Enumerate tables after databases',
                finding=finding
            )
        ]

    def _plan_error_exploitation(self, finding: Finding) -> List[Action]:
        """Plan exploitation using error-based injection."""
        return [
            Action(
                type=ActionType.ENUMERATE_DATABASES,
                priority=Priority.HIGH,
                reason='Error-based injection provides reliable extraction',
                finding=finding
            ),
            Action(
                type=ActionType.FINGERPRINT_DBMS,
                priority=Priority.MEDIUM,
                reason='Error messages reveal DBMS details',
                finding=finding
            )
        ]

    def _plan_blind_exploitation(self, finding: Finding, blind_type: str) -> List[Action]:
        """Plan exploitation using blind injection."""
        return [
            Action(
                type=ActionType.ENUMERATE_DATABASES_BLIND,
                priority=Priority.MEDIUM,
                reason=f'{blind_type.capitalize()}-based blind injection (slower)',
                finding=finding
            ),
            Action(
                type=ActionType.FINGERPRINT_DBMS,
                priority=Priority.MEDIUM,
                reason='Fingerprint to optimize blind queries',
                finding=finding
            )
        ]

    def _plan_stacked_exploitation(self, finding: Finding) -> List[Action]:
        """Plan exploitation using stacked queries."""
        return [
            Action(
                type=ActionType.TEST_STACKED_QUERIES,
                priority=Priority.HIGH,
                reason='Stacked queries may allow command execution',
                finding=finding
            ),
            Action(
                type=ActionType.GET_PRIVILEGES,
                priority=Priority.HIGH,
                reason='Check privileges for potential escalation',
                finding=finding
            )
        ]

    def should_continue(self, findings: List[Finding], elapsed_time: float) -> bool:
        """
        Decide if testing should continue.

        Args:
            findings: Current findings
            elapsed_time: Time elapsed in seconds

        Returns:
            True if testing should continue
        """
        # Stop if we have high-confidence findings
        if any(f.confidence >= 0.8 for f in findings):
            logger.info("High-confidence injection found, stopping")
            return False

        # Stop if elapsed time exceeds threshold
        if elapsed_time > 600:  # 10 minutes
            logger.info("Time limit reached, stopping")
            return False

        # Continue otherwise
        return True

    def prioritize_parameters(self, parameters: List[str]) -> List[str]:
        """
        Prioritize which parameters to test first.

        Args:
            parameters: List of parameter names

        Returns:
            Sorted list with most promising parameters first
        """
        # Common vulnerable parameter names
        high_priority = ['id', 'user', 'userid', 'username', 'page', 'category', 'search']
        medium_priority = ['action', 'cmd', 'file', 'query', 'sort', 'order']

        prioritized = []

        # Add high priority
        for param in parameters:
            if param.lower() in high_priority:
                prioritized.append(param)

        # Add medium priority
        for param in parameters:
            if param.lower() in medium_priority and param not in prioritized:
                prioritized.append(param)

        # Add remaining
        for param in parameters:
            if param not in prioritized:
                prioritized.append(param)

        return prioritized

    def get_action_history(self) -> List[Action]:
        """Get history of all actions taken."""
        return self._action_history

    def clear_history(self):
        """Clear action history."""
        self._action_history.clear()

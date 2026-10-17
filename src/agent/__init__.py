"""
EviGraph Forensic Reasoning, LLM Agent & RAG Package (Member 3)
Connects Upstream Detection & Graph Engine (Member 2) with Downstream Forensic Reasoning & Reporting.
"""

from .citation_validator import CitationValidator
from .forensic_agent import ForensicAgent
from .courtroom_auditor import CourtroomCrossExaminer

__all__ = ["CitationValidator", "ForensicAgent", "CourtroomCrossExaminer"]

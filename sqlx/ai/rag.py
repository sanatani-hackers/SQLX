"""
sqlx/ai/rag.py
~~~~~~~~~~~~~~
Lightweight TF-IDF Retrieval-Augmented Generation for SQLX.

No external ML libraries required — pure Python.

Indexes findings, observations, and git commit messages from ALL past
target sessions and makes them queryable so the agent can learn from
previous runs automatically.
"""
from __future__ import annotations

import json
import math
import re
import subprocess
from pathlib import Path
from typing import Dict, List, Optional

# ---------------------------------------------------------------------------
# Stopwords (common English words that carry no signal)
# ---------------------------------------------------------------------------
_STOPWORDS = frozenset([
    "a", "an", "the", "and", "or", "but", "in", "on", "at", "to", "for",
    "of", "with", "by", "from", "is", "was", "are", "were", "be", "been",
    "has", "have", "had", "do", "does", "did", "will", "would", "could",
    "should", "may", "might", "it", "its", "this", "that", "these", "those",
    "i", "we", "you", "he", "she", "they", "not", "no", "so", "if", "as",
    "target", "sqlmap", "http", "https", "www", "get", "post",
])


def _tokenize(text: str) -> List[str]:
    """Lowercase, split on non-alphanumeric, remove stopwords."""
    tokens = re.findall(r"[a-z0-9_]+", text.lower())
    return [t for t in tokens if t not in _STOPWORDS and len(t) > 2]


# ---------------------------------------------------------------------------
# FindingsRAG
# ---------------------------------------------------------------------------

class FindingsRAG:
    """
    TF-IDF based RAG that indexes all past SQLX target findings and lets
    the agent query them for relevant context before each LLM call.

    Usage
    -----
    rag = FindingsRAG()
    rag.index_all_targets()           # or happens lazily on first query()
    context = rag.format_for_context("WAF bypass union injection")
    """

    def __init__(self, targets_base_dir: str = "targets") -> None:
        self.targets_base_dir = Path(targets_base_dir)
        self._chunks: List[Dict] = []     # {id, text, source, target_name}
        self._df: Dict[str, int] = {}     # document-frequency per token
        self._indexed = False

    # ------------------------------------------------------------------
    # Indexing
    # ------------------------------------------------------------------

    def index_all_targets(self) -> int:
        """
        Scan every target workspace and index:
          - sessions/*.json  → findings + observations lists
          - logs/events.jsonl → FindingCreated event data
          - findings/*.json  → raw finding files
          - git log --oneline → commit messages as context
        Returns the number of chunks indexed.
        """
        self._chunks.clear()
        self._df.clear()

        if not self.targets_base_dir.exists():
            self._indexed = True
            return 0

        for target_dir in self.targets_base_dir.iterdir():
            if not target_dir.is_dir() or target_dir.name == "reports":
                continue
            name = target_dir.name
            self._index_sessions(target_dir, name)
            self._index_event_log(target_dir, name)
            self._index_findings_dir(target_dir, name)
            self._index_git_log(target_dir, name)

        # Build document-frequency table
        for chunk in self._chunks:
            for token in set(_tokenize(chunk["text"])):
                self._df[token] = self._df.get(token, 0) + 1

        self._indexed = True
        return len(self._chunks)

    def _index_sessions(self, target_dir: Path, name: str) -> None:
        sessions_dir = target_dir / "sessions"
        if not sessions_dir.exists():
            return
        for f in sessions_dir.glob("*.json"):
            try:
                data = json.loads(f.read_text(encoding="utf-8"))
                for item in data.get("findings", []):
                    text = item if isinstance(item, str) else json.dumps(item)
                    self._add_chunks(text, "session:finding", name)
                for obs in data.get("observations", []):
                    self._add_chunks(str(obs), "session:observation", name)
                obj = data.get("objective", "")
                if obj:
                    self._add_chunks(obj, "session:objective", name)
            except Exception:
                pass

    def _index_event_log(self, target_dir: Path, name: str) -> None:
        log_file = target_dir / "logs" / "events.jsonl"
        if not log_file.exists():
            return
        for line in log_file.read_text(encoding="utf-8", errors="replace").splitlines():
            try:
                ev = json.loads(line)
                if ev.get("event_name") == "FindingCreated":
                    summary = ev.get("data", {}).get("summary", "")
                    if summary:
                        self._add_chunks(summary, "event:finding", name)
            except Exception:
                pass

    def _index_findings_dir(self, target_dir: Path, name: str) -> None:
        findings_dir = target_dir / "findings"
        if not findings_dir.exists():
            return
        for f in findings_dir.glob("*.json"):
            try:
                data = json.loads(f.read_text(encoding="utf-8"))
                text = data if isinstance(data, str) else json.dumps(data)
                self._add_chunks(text, "finding_file", name)
            except Exception:
                pass

    def _index_git_log(self, target_dir: Path, name: str) -> None:
        try:
            result = subprocess.run(
                ["git", "log", "--oneline", "--no-decorate"],
                cwd=str(target_dir),
                capture_output=True,
                text=True,
                timeout=5,
            )
            if result.returncode == 0:
                for line in result.stdout.strip().splitlines():
                    # e.g. "a1b2c3d Add GearFourth tamper script"
                    msg = re.sub(r"^[0-9a-f]+\s+", "", line).strip()
                    if msg and msg != "baseline":
                        self._add_chunks(msg, "git:commit", name)
        except Exception:
            pass

    def _add_chunks(self, text: str, source: str, target_name: str,
                    chunk_size: int = 250, overlap: int = 50) -> None:
        """Split text into overlapping chunks and append to self._chunks."""
        text = text.strip()
        if not text:
            return
        start = 0
        chunk_id = len(self._chunks)
        while start < len(text):
            end = min(start + chunk_size, len(text))
            chunk_text = text[start:end].strip()
            if chunk_text:
                self._chunks.append({
                    "id": chunk_id,
                    "text": chunk_text,
                    "source": source,
                    "target_name": target_name,
                })
                chunk_id += 1
            start += chunk_size - overlap

    # ------------------------------------------------------------------
    # Scoring & retrieval
    # ------------------------------------------------------------------

    def _tfidf_score(self, query_tokens: List[str], chunk: Dict) -> float:
        """TF-IDF dot-product between query and chunk."""
        chunk_tokens = _tokenize(chunk["text"])
        if not chunk_tokens or not query_tokens:
            return 0.0

        total_docs = max(len(self._chunks), 1)
        chunk_freq: Dict[str, int] = {}
        for t in chunk_tokens:
            chunk_freq[t] = chunk_freq.get(t, 0) + 1

        score = 0.0
        for token in query_tokens:
            tf = chunk_freq.get(token, 0) / len(chunk_tokens)
            df = self._df.get(token, 0)
            idf = math.log((total_docs + 1) / (df + 1)) + 1.0
            score += tf * idf
        return score

    def query(self, query_text: str, top_k: int = 5, min_score: float = 0.05) -> List[Dict]:
        """
        Return up to *top_k* chunks most relevant to *query_text*.
        Each result dict adds a 'score' key.
        """
        if not self._indexed:
            self.index_all_targets()
        if not self._chunks:
            return []

        q_tokens = _tokenize(query_text)
        if not q_tokens:
            return []

        scored = []
        for chunk in self._chunks:
            s = self._tfidf_score(q_tokens, chunk)
            if s >= min_score:
                scored.append({**chunk, "score": s})

        scored.sort(key=lambda x: x["score"], reverse=True)
        return scored[:top_k]

    # ------------------------------------------------------------------
    # Context formatting
    # ------------------------------------------------------------------

    def format_for_context(self, query_text: str, top_k: int = 3) -> str:
        """
        Return a block ready to inject into the agent's system context.
        Returns empty string when nothing relevant is found.
        """
        results = self.query(query_text, top_k=top_k)
        if not results:
            return ""

        lines = ["=== Relevant Past Findings ==="]
        for r in results:
            lines.append(
                f"[Target: {r['target_name']}] "
                f"({r['source']}, score={r['score']:.2f}) "
                f"{r['text'][:300]}"
            )
        lines.append("=== End Past Findings ===")
        return "\n".join(lines)

    # ------------------------------------------------------------------
    # Live updates
    # ------------------------------------------------------------------

    def add_finding(self, target_name: str, finding_text: str) -> None:
        """
        Live-add a new finding without a full re-index.
        Also updates the document-frequency table for new tokens.
        """
        self._add_chunks(finding_text, "live:finding", target_name)
        # Update DF for new tokens
        for token in set(_tokenize(finding_text)):
            self._df[token] = self._df.get(token, 0) + 1
        self._indexed = True   # mark as ready


# ---------------------------------------------------------------------------
# Module-level singleton — imported by agent.py and search_past_findings tool
# ---------------------------------------------------------------------------
_rag = FindingsRAG()

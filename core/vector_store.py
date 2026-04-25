"""core/vector_store.py
Ephemeral ChromaDB vector store with Ollama-based embeddings.

Provides semantic chunk retrieval for the RAG workbench. Intentionally
stateful — the cached instance in app.py accumulates indexed documents
across Streamlit reruns for the lifetime of the server process.
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass
class RetrievedChunk:
    text: str
    source: str
    distance: float

    @property
    def relevance(self) -> float:
        """Cosine distance → relevance score (0–1, higher = more relevant)."""
        return max(0.0, 1.0 - self.distance)


class VectorStore:
    """Ephemeral ChromaDB collection backed by Ollama embeddings.

    Uses chromadb.EphemeralClient() — no disk persistence. Designed to be
    instantiated once via @st.cache_resource so mutations (index_document,
    delete_source) survive Streamlit reruns.
    """

    def __init__(
        self,
        ollama_host: str = "http://localhost:11434",
        embed_model: str = "nomic-embed-text",
        collection_name: str = "rag_docs",
        chunk_size: int = 200,
        chunk_overlap: int = 40,
        top_k: int = 3,
    ):
        import chromadb  # lazy — graceful ImportError if not installed

        self.ollama_host = ollama_host
        self.embed_model = embed_model
        self.chunk_size = chunk_size
        self.chunk_overlap = chunk_overlap
        self.top_k = top_k

        self._chroma = chromadb.EphemeralClient()
        self._col = self._chroma.get_or_create_collection(collection_name)
        self._chunk_ids: set[str] = set()

    # ── Embedding ─────────────────────────────────────────────────────────────

    def _embed(self, texts: list[str]) -> list[list[float]]:
        from ollama import Client
        client = Client(host=self.ollama_host)
        return [client.embeddings(model=self.embed_model, prompt=t)["embedding"] for t in texts]

    # ── Chunking ──────────────────────────────────────────────────────────────

    def _chunk(self, text: str, source: str) -> list[tuple[str, str, str]]:
        """Split text into overlapping word-count chunks.

        Returns list of (chunk_text, chunk_id, source).
        """
        words = text.split()
        chunks: list[tuple[str, str, str]] = []
        i, idx = 0, 0
        while i < len(words):
            chunk_text = " ".join(words[i : i + self.chunk_size])
            chunks.append((chunk_text, f"{source}::c{idx}", source))
            i += self.chunk_size - self.chunk_overlap
            idx += 1
        return chunks

    # ── Public API ────────────────────────────────────────────────────────────

    def index_document(self, text: str, source: str) -> int:
        """Chunk, embed, and store a document. Returns chunk count added."""
        self.delete_source(source)  # replace any existing version
        chunks = self._chunk(text, source)
        if not chunks:
            return 0
        texts = [c[0] for c in chunks]
        ids = [c[1] for c in chunks]
        metas = [{"source": source} for _ in chunks]
        embeddings = self._embed(texts)
        self._col.add(embeddings=embeddings, documents=texts, metadatas=metas, ids=ids)
        self._chunk_ids.update(ids)
        return len(chunks)

    def query(self, query_text: str) -> list[RetrievedChunk]:
        """Return top-k most relevant chunks for query_text."""
        n = self._col.count()
        if n == 0:
            return []
        q_emb = self._embed([query_text])[0]
        results = self._col.query(
            query_embeddings=[q_emb],
            n_results=min(self.top_k, n),
        )
        return [
            RetrievedChunk(text=doc, source=meta["source"], distance=dist)
            for doc, meta, dist in zip(
                results["documents"][0],
                results["metadatas"][0],
                results["distances"][0],
            )
        ]

    def delete_source(self, source: str) -> None:
        """Remove all chunks belonging to *source*."""
        ids = [cid for cid in self._chunk_ids if cid.startswith(f"{source}::")]
        if ids:
            self._col.delete(ids=ids)
            self._chunk_ids -= set(ids)

    def get_sources(self) -> list[str]:
        """Return sorted list of unique indexed source names."""
        if self._col.count() == 0:
            return []
        result = self._col.get(include=["metadatas"])
        return sorted({m["source"] for m in result["metadatas"]})

    def count(self) -> int:
        """Total chunk count across all indexed documents."""
        return self._col.count()

    def is_embed_model_available(self) -> bool:
        """Return True if the embed model is pulled in Ollama."""
        try:
            from ollama import Client
            client = Client(host=self.ollama_host)
            response = client.list()
            # SDK returns ListResponse with .models list of Model objects (.model attr)
            model_names = [m.model for m in response.models]
            base = self.embed_model.split(":")[0].lower()
            return any(base == m.split(":")[0].lower() for m in model_names)
        except Exception:
            return False

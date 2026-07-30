"""Core RAG pipeline — intentionally observable for attack analysis."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from langchain_text_splitters import RecursiveCharacterTextSplitter
from langchain_chroma import Chroma
from langchain_community.document_loaders import DirectoryLoader, TextLoader
from langchain_huggingface import HuggingFaceEmbeddings
from langchain_core.documents import Document
from langchain_core.language_models import BaseLLM
from langchain_core.output_parsers import StrOutputParser
from langchain_core.prompts import ChatPromptTemplate
from langchain_core.runnables import RunnablePassthrough


@dataclass
class RetrievalTrace:
    query: str
    retrieved_chunks: list[Document]
    full_prompt: str
    response: str
    injected: bool = False
    injection_source: str | None = None


@dataclass
class Pipeline:
    llm: BaseLLM
    persist_dir: str = ".hemlock/chroma"
    collection: str = "hemlock"
    chunk_size: int = 500
    chunk_overlap: int = 50
    top_k: int = 4
    _store: Chroma | None = field(default=None, repr=False)
    _embeddings: HuggingFaceEmbeddings | None = field(default=None, repr=False)

    def _get_embeddings(self) -> HuggingFaceEmbeddings:
        if self._embeddings is None:
            self._embeddings = HuggingFaceEmbeddings(
                model_name="sentence-transformers/all-MiniLM-L6-v2"
            )
        return self._embeddings

    def _get_store(self) -> Chroma:
        if self._store is None:
            self._store = Chroma(
                collection_name=self.collection,
                embedding_function=self._get_embeddings(),
                persist_directory=self.persist_dir,
            )
        return self._store

    def ingest_dir(self, path: str | Path, glob: str = "**/*.md") -> int:
        loader = DirectoryLoader(str(path), glob=glob, loader_cls=TextLoader)
        docs = loader.load()
        return self._index(docs)

    def ingest_text(self, text: str, metadata: dict[str, Any] | None = None) -> int:
        doc = Document(page_content=text, metadata=metadata or {})
        return self._index([doc])

    def _index(self, docs: list[Document]) -> int:
        splitter = RecursiveCharacterTextSplitter(
            chunk_size=self.chunk_size,
            chunk_overlap=self.chunk_overlap,
        )
        chunks = splitter.split_documents(docs)
        self._get_store().add_documents(chunks)
        return len(chunks)

    def query(self, question: str, system_prompt: str | None = None) -> RetrievalTrace:
        store = self._get_store()
        retriever = store.as_retriever(search_kwargs={"k": self.top_k})
        chunks = retriever.invoke(question)

        prompt_template = system_prompt or (
            "You are a helpful assistant. Answer the question using only the context below.\n\n"
            "Context:\n{context}\n\n"
            "Question: {question}"
        )

        prompt = ChatPromptTemplate.from_template(prompt_template)
        context_text = "\n\n---\n\n".join(c.page_content for c in chunks)
        full_prompt = prompt_template.replace("{context}", context_text).replace(
            "{question}", question
        )

        chain = (
            {"context": retriever | self._format_docs, "question": RunnablePassthrough()}
            | prompt
            | self.llm
            | StrOutputParser()
        )

        response = chain.invoke(question)

        # Detect if any retrieved chunk looks like an injection attempt
        injected, source = self._detect_injection(chunks)

        return RetrievalTrace(
            query=question,
            retrieved_chunks=chunks,
            full_prompt=full_prompt,
            response=response,
            injected=injected,
            injection_source=source,
        )

    def reset(self) -> None:
        store = self._get_store()
        store.delete_collection()
        self._store = None

    @staticmethod
    def _format_docs(docs: list[Document]) -> str:
        return "\n\n---\n\n".join(d.page_content for d in docs)

    @staticmethod
    def _detect_injection(chunks: list[Document]) -> tuple[bool, str | None]:
        injection_markers = [
            "ignore previous instructions",
            "ignore all previous",
            "disregard",
            "you are now",
            "new instructions:",
            "system:",
            "assistant:",
            "[system]",
            "forget everything",
        ]
        for chunk in chunks:
            content_lower = chunk.page_content.lower()
            for marker in injection_markers:
                if marker in content_lower:
                    source = chunk.metadata.get("source", "unknown")
                    return True, source
        return False, None

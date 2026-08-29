import faiss
import numpy as np
from sentence_transformers import SentenceTransformer


class RepositoryVectorStore:

    def __init__(self):
        # Small and fast embedding model
        self.model = SentenceTransformer(
            "all-MiniLM-L6-v2"
        )

        self.index = None
        self.documents = []

    def add_documents(self, documents):
        """
        Convert repository code chunks into embeddings
        and store them in FAISS.
        """

        if not documents:
            return

        self.documents = documents

        embeddings = self.model.encode(
            documents,
            convert_to_numpy=True
        )

        embeddings = embeddings.astype(
            "float32"
        )

        dimension = embeddings.shape[1]

        self.index = faiss.IndexFlatL2(
            dimension
        )

        self.index.add(
            embeddings
        )

    def search(self, query, top_k=3):
        """
        Search the repository for the most
        relevant code/document chunks.
        """

        if self.index is None:
            return []

        query_embedding = self.model.encode(
            [query],
            convert_to_numpy=True
        )

        query_embedding = query_embedding.astype(
            "float32"
        )

        distances, indices = self.index.search(
            query_embedding,
            min(top_k, len(self.documents))
        )

        results = []

        for distance, index in zip(
            distances[0],
            indices[0]
        ):

            if index < 0:
                continue

            results.append({
                "document": self.documents[index],
                "distance": float(distance)
            })

        return results
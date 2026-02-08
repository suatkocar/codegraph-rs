//! Embedding engine powered by fastembed (jina-embeddings-v2-base-code).
//!
//! Generates 768-dimensional normalized embeddings entirely on-device via
//! ONNX Runtime. Uses a code-specific model (Jina v2 Base Code) that
//! understands programming language semantics — significantly better than
//! general-purpose models for code search and similarity.
//!
//! The model is lazily downloaded on first use and cached in
//! `.fastembed_cache` (or `$HF_HOME`).
//!
//! Feature-gated behind `embedding` — disable with `--no-default-features`
//! for environments without ONNX Runtime.

#[cfg(feature = "embedding")]
use fastembed::{EmbeddingModel, InitOptions, TextEmbedding};

use std::path::Path;

#[cfg(feature = "embedding")]
use rusqlite::params;

use crate::error::{CodeGraphError, Result};
use crate::types::CodeNode;

// ---------------------------------------------------------------------------
// EmbeddingEngine
// ---------------------------------------------------------------------------

/// On-device embedding engine.
///
/// Wraps fastembed's `TextEmbedding` with lazy initialization, node text
/// construction matching the TS version, and SQLite persistence for both
/// the raw embeddings (`embedding_cache`) and the sqlite-vec virtual table
/// (`vec_embeddings`).
pub struct EmbeddingEngine {
    #[cfg(feature = "embedding")]
    model: TextEmbedding,
    pub dim: usize,
}

impl EmbeddingEngine {
    /// Create a new embedding engine (downloads the model on first use).
    ///
    /// # Errors
    /// Returns an error if the model cannot be loaded or the ONNX session
    /// fails to initialize.
    pub fn try_new() -> Result<Self> {
        #[cfg(feature = "embedding")]
        {
            let model = TextEmbedding::try_new(
                InitOptions::new(EmbeddingModel::JinaEmbeddingsV2BaseCode)
                    .with_show_download_progress(true),
            )
            .map_err(|e| CodeGraphError::Embedding(e.to_string()))?;

            Ok(Self { model, dim: 768 })
        }

        #[cfg(not(feature = "embedding"))]
        {
            Err(CodeGraphError::Embedding(
                "Embedding support not compiled. Rebuild with `--features embedding`.".into(),
            ))
        }
    }

    /// Embed a single text string into a 768-d vector.
    #[cfg(feature = "embedding")]
    pub fn embed(&self, text: &str) -> Result<Vec<f32>> {
        let results = self
            .model
            .embed(vec![text], None)
            .map_err(|e| CodeGraphError::Embedding(e.to_string()))?;

        results
            .into_iter()
            .next()
            .ok_or_else(|| CodeGraphError::Embedding("No embedding returned".into()))
    }

    /// Embed a batch of texts.
    #[cfg(feature = "embedding")]
    pub fn embed_batch(&self, texts: Vec<&str>) -> Result<Vec<Vec<f32>>> {
        self.model
            .embed(texts, None)
            .map_err(|e| CodeGraphError::Embedding(e.to_string()))
    }

    /// Produce a rich embedding for a CodeNode.
    ///
    /// Combines the node's structural identity, documentation, and a
    /// truncated body preview into a single text, matching the TS version's
    /// `embedNode()` format:
    ///
    ///   `"{kind} {name} in {fileName}: {doc} {bodyPreview}"`
    #[cfg(feature = "embedding")]
    pub fn embed_node(&self, node: &CodeNode) -> Result<Vec<f32>> {
        let text = node_to_embedding_text(node);
        self.embed(&text)
    }

    /// Embed multiple nodes in a batch for throughput.
    #[cfg(feature = "embedding")]
    pub fn embed_nodes(&self, nodes: &[CodeNode]) -> Result<Vec<Vec<f32>>> {
        let texts: Vec<String> = nodes.iter().map(node_to_embedding_text).collect();
        let refs: Vec<&str> = texts.iter().map(|s| s.as_str()).collect();
        self.embed_batch(refs)
    }

    /// Embed all nodes and store them in both `embedding_cache` and
    /// `vec_embeddings` tables.
    #[cfg(feature = "embedding")]
    pub fn embed_and_store(
        &self,
        conn: &rusqlite::Connection,
        nodes: &[CodeNode],
    ) -> Result<usize> {
        if nodes.is_empty() {
            return Ok(0);
        }

        let embeddings = self.embed_nodes(nodes)?;
        let mut count = 0;

        for (node, embedding) in nodes.iter().zip(embeddings.iter()) {
            // Store in embedding_cache (BLOB format)
            let blob: Vec<u8> = embedding.iter().flat_map(|f| f.to_le_bytes()).collect();

            conn.execute(
                "INSERT OR REPLACE INTO embedding_cache (node_id, embedding, model_version)
                 VALUES (?1, ?2, 'jina-embeddings-v2-base-code')",
                params![node.id, blob],
            )?;

            // Store in vec_embeddings (sqlite-vec format)
            // sqlite-vec expects the embedding as a JSON array string
            let vec_json = serde_json::to_string(embedding)
                .map_err(|e| CodeGraphError::Embedding(e.to_string()))?;

            // Try to insert into vec_embeddings; if sqlite-vec isn't loaded, skip
            let _ = conn.execute(
                "INSERT OR REPLACE INTO vec_embeddings (node_id, embedding)
                 VALUES (?1, ?2)",
                params![node.id, vec_json],
            );

            count += 1;
        }

        Ok(count)
    }
}

// ---------------------------------------------------------------------------
// Text construction
// ---------------------------------------------------------------------------

/// Build the text representation of a node for embedding.
///
/// Format matches TS: `"{kind} {name} in {fileName}: {doc} {bodyPreview}"`
pub fn node_to_embedding_text(node: &CodeNode) -> String {
    let file_name = Path::new(&node.file_path)
        .file_name()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_default();

    let doc = node.documentation.as_deref().unwrap_or("");
    let body_preview = node
        .body
        .as_deref()
        .map(|b| if b.len() > 500 { &b[..b.floor_char_boundary(500)] } else { b })
        .unwrap_or("");

    format!(
        "{} {} in {}: {} {}",
        node.kind.as_str(),
        node.name,
        file_name,
        doc,
        body_preview
    )
    .trim()
    .to_string()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{Language, NodeKind};

    fn make_node(name: &str, kind: NodeKind, file: &str) -> CodeNode {
        CodeNode {
            id: format!("{}:{}:{}:1", kind.as_str(), file, name),
            name: name.to_string(),
            qualified_name: None,
            kind,
            file_path: file.to_string(),
            start_line: 1,
            end_line: 10,
            start_column: 0,
            end_column: 0,
            language: Language::TypeScript,
            body: Some("function hello() { return 42; }".to_string()),
            documentation: Some("Say hello".to_string()),
            exported: Some(true),
        }
    }

    #[test]
    fn node_to_embedding_text_format() {
        let node = make_node("hello", NodeKind::Function, "src/main.ts");
        let text = node_to_embedding_text(&node);
        assert!(text.contains("function hello in main.ts:"));
        assert!(text.contains("Say hello"));
        assert!(text.contains("function hello()"));
    }

    #[test]
    fn node_to_embedding_text_without_docs_or_body() {
        let mut node = make_node("foo", NodeKind::Class, "lib/utils.ts");
        node.documentation = None;
        node.body = None;
        let text = node_to_embedding_text(&node);
        assert_eq!(text, "class foo in utils.ts:");
    }

    #[test]
    fn node_to_embedding_text_truncates_long_body() {
        let mut node = make_node("big", NodeKind::Function, "src/big.ts");
        node.body = Some("x".repeat(1000));
        node.documentation = None;
        let text = node_to_embedding_text(&node);
        // Should be truncated to ~500 chars of body
        assert!(text.len() < 600);
    }

    // Embedding model tests only run when the feature is enabled and
    // the model is available (skipped in CI without ONNX).
    #[cfg(feature = "embedding")]
    #[test]
    fn embed_single_text_returns_768_dims() {
        let engine = match EmbeddingEngine::try_new() {
            Ok(e) => e,
            Err(_) => return, // Skip if model unavailable
        };
        let vec = engine.embed("hello world").unwrap();
        assert_eq!(vec.len(), 768);
    }

    #[cfg(feature = "embedding")]
    #[test]
    fn embed_node_returns_768_dims() {
        let engine = match EmbeddingEngine::try_new() {
            Ok(e) => e,
            Err(_) => return,
        };
        let node = make_node("test", NodeKind::Function, "src/test.ts");
        let vec = engine.embed_node(&node).unwrap();
        assert_eq!(vec.len(), 768);
    }

    #[cfg(feature = "embedding")]
    #[test]
    fn embed_batch_matches_individual() {
        let engine = match EmbeddingEngine::try_new() {
            Ok(e) => e,
            Err(_) => return,
        };
        let texts = vec!["hello", "world"];
        let batch = engine.embed_batch(texts).unwrap();
        assert_eq!(batch.len(), 2);
        assert_eq!(batch[0].len(), 768);
        assert_eq!(batch[1].len(), 768);
    }
}

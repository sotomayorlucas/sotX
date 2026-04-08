use crate::graph::{Edge, ProvenanceGraph, SOId, SOType};

/// A raw provenance entry consumed from a ring buffer.
#[derive(Debug, Clone)]
pub struct ProvenanceEntry {
    pub src_id: SOId,
    pub src_type: SOType,
    pub dst_id: SOId,
    pub dst_type: SOType,
    pub operation: u16,
    pub domain_id: u32,
    pub timestamp: u64,
    pub tx_id: u64,
}

/// Consumes provenance entries and builds the graph.
pub struct ProvenanceIngestor<'a> {
    graph: &'a mut ProvenanceGraph,
}

impl<'a> ProvenanceIngestor<'a> {
    pub fn new(graph: &'a mut ProvenanceGraph) -> Self {
        Self { graph }
    }

    /// Ingest a batch of entries, creating nodes as needed and adding edges.
    pub fn ingest_batch(&mut self, entries: &[ProvenanceEntry]) {
        for entry in entries {
            self.graph.add_node(entry.src_id, entry.src_type);
            self.graph.add_node(entry.dst_id, entry.dst_type);
            self.graph.add_edge(Edge {
                src: entry.src_id,
                dst: entry.dst_id,
                operation: entry.operation,
                domain_id: entry.domain_id,
                timestamp: entry.timestamp,
                tx_id: entry.tx_id,
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ingest_builds_graph() {
        let mut graph = ProvenanceGraph::new();
        let entries = [
            ProvenanceEntry {
                src_id: 1,
                src_type: SOType::File,
                dst_id: 2,
                dst_type: SOType::Process,
                operation: 1,
                domain_id: 10,
                timestamp: 100,
                tx_id: 0,
            },
            ProvenanceEntry {
                src_id: 2,
                src_type: SOType::Process,
                dst_id: 3,
                dst_type: SOType::Socket,
                operation: 2,
                domain_id: 10,
                timestamp: 200,
                tx_id: 1,
            },
        ];

        {
            let mut ingestor = ProvenanceIngestor::new(&mut graph);
            ingestor.ingest_batch(&entries);
        }

        assert_eq!(graph.node_count(), 3);
        assert_eq!(graph.edge_count(), 2);
    }

    #[test]
    fn ingest_deduplicates_nodes() {
        let mut graph = ProvenanceGraph::new();
        let entries = [
            ProvenanceEntry {
                src_id: 1,
                src_type: SOType::File,
                dst_id: 2,
                dst_type: SOType::Process,
                operation: 1,
                domain_id: 10,
                timestamp: 100,
                tx_id: 0,
            },
            ProvenanceEntry {
                src_id: 1,
                src_type: SOType::File,
                dst_id: 2,
                dst_type: SOType::Process,
                operation: 3,
                domain_id: 10,
                timestamp: 200,
                tx_id: 1,
            },
        ];

        {
            let mut ingestor = ProvenanceIngestor::new(&mut graph);
            ingestor.ingest_batch(&entries);
        }

        assert_eq!(graph.node_count(), 2);
        assert_eq!(graph.edge_count(), 2);
    }
}

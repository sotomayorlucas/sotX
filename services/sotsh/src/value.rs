//! Values flowing through a sotSh pipeline.
//!
//! Pipelines pass structured [`Value`]s rather than byte streams. This lets
//! built-ins operate on typed data (rows, ints, bools) without reparsing.
//!
//! Future variants: `Fd(CapRef)` for capability-tagged file descriptors,
//! `Graph(DagId)` for sotFS DAG references.

use core::fmt;

/// A value moving between built-ins.
#[derive(Debug, Clone)]
pub enum Value {
    Nil,
    Str(String),
    Int(i64),
    Bool(bool),
    Table(Vec<Row>),
}

/// A row in a [`Value::Table`]: an ordered list of named cells.
#[derive(Debug, Clone)]
pub struct Row {
    pub cells: Vec<(String, Value)>,
}

impl Row {
    pub fn new() -> Self {
        Self { cells: Vec::new() }
    }

    pub fn with(mut self, key: impl Into<String>, val: Value) -> Self {
        self.cells.push((key.into(), val));
        self
    }
}

impl Default for Row {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for Value {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Value::Nil => Ok(()),
            Value::Str(s) => f.write_str(s),
            Value::Int(i) => write!(f, "{i}"),
            Value::Bool(b) => write!(f, "{b}"),
            Value::Table(rows) => {
                for (i, row) in rows.iter().enumerate() {
                    if i > 0 {
                        writeln!(f)?;
                    }
                    for (j, (k, v)) in row.cells.iter().enumerate() {
                        if j > 0 {
                            f.write_str("  ")?;
                        }
                        write!(f, "{k}={v}")?;
                    }
                }
                Ok(())
            }
        }
    }
}

//! Everything having to do with pagination of collection and search APIs from CUBE.

mod builder;
mod search;
mod searches;

pub use builder::SearchBuilder;
pub use search::*;
pub use searches::*;
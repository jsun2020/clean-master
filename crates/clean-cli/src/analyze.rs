use crate::fmt::human_bytes;
use clean_core::report;
use clean_core::session::Session;
use comfy_table::{presets::UTF8_FULL_CONDENSED, Cell, CellAlignment, Table};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Clone, Copy, PartialEq, clap::ValueEnum)]
pub enum Section {
    Files,
    Dir,
    Ext,
    Age,
}

fn table_with_header(headers: &[&str]) -> Table {
    let mut t = Table::new();
    t.load_preset(UTF8_FULL_CONDENSED);
    t.set_header(headers.iter().map(|h| Cell::new(h)).collect::<Vec<_>>());
    t
}

fn size_cell(bytes: u64) -> Cell {
    Cell::new(human_bytes(bytes)).set_alignment(CellAlignment::Right)
}

pub fn run(session: &Session, top: usize, only: Option<Section>) {
    println!(
        "Session: {} ({} files, {} in total)",
        session.root,
        session.file_count(),
        human_bytes(session.total_file_bytes())
    );
    println!();

    let show = |s: Section| only.is_none() || only == Some(s);

    if show(Section::Files) {
        let mut t = table_with_header(&["Largest files", "Size"]);
        for r in report::top_files(&session.records, top) {
            t.add_row(vec![Cell::new(&r.path), size_cell(r.size)]);
        }
        println!("{t}");
        println!();
    }

    if show(Section::Dir) {
        let mut t = table_with_header(&["Largest directories (cumulative)", "Files", "Size"]);
        for d in report::top_dirs(&session.records, &session.root, top) {
            t.add_row(vec![
                Cell::new(&d.path),
                Cell::new(d.files).set_alignment(CellAlignment::Right),
                size_cell(d.bytes),
            ]);
        }
        println!("{t}");
        println!();
    }

    if show(Section::Ext) {
        let mut t = table_with_header(&["Extension", "Count", "Size"]);
        for e in report::by_extension(&session.records, top) {
            t.add_row(vec![
                Cell::new(&e.ext),
                Cell::new(e.count).set_alignment(CellAlignment::Right),
                size_cell(e.bytes),
            ]);
        }
        println!("{t}");
        println!();
    }

    if show(Section::Age) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        let mut t = table_with_header(&["Last modified", "Count", "Size"]);
        for b in report::by_age(&session.records, now) {
            t.add_row(vec![
                Cell::new(b.label),
                Cell::new(b.count).set_alignment(CellAlignment::Right),
                size_cell(b.bytes),
            ]);
        }
        println!("{t}");
    }
}

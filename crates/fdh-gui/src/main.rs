use std::fs;
use std::path::{Path, PathBuf};
use std::sync::mpsc::{self, Receiver};
use std::thread;

use eframe::egui;
use fdh_core::{
    ChunkValueEncoding, DictionarySearcher, FdhHeader, GenerateOptions, HashRegistry,
    append_chunks, convert_legacy_dir, generate_dictionary, recommended_threads,
};

const STORAGE_FILE: &str = "dictionaries.conf";

#[derive(PartialEq, Eq)]
enum Tab {
    Search,
    Generate,
    Convert,
}

enum WorkerEvent {
    Log(String),
    Progress(f32),
    Done(Result<String, String>),
}

struct DictEntry {
    path: PathBuf,
    header: Option<FdhHeader>,
    error: Option<String>,
}

struct FdhGuiApp {
    tab: Tab,
    dictionaries: Vec<DictEntry>,
    selected_dict: Option<usize>,
    active_searcher: Option<(PathBuf, DictionarySearcher)>,

    // Search state
    search_hash: String,
    search_result: String,

    // Generate / Append state
    available_algos: Vec<&'static str>,
    gen_algo_idx: usize,
    gen_alphabet: String,
    gen_chunks: u32,
    gen_threads: usize,
    gen_output: String,
    append_chunks_count: u32,

    // Convert state
    conv_input_dir: String,
    conv_output_file: String,

    // Background job state
    worker_rx: Option<Receiver<WorkerEvent>>,
    worker_progress: f32,
    worker_logs: Vec<String>,
    worker_running: bool,
}

impl FdhGuiApp {
    fn new() -> Self {
        let reg = HashRegistry::with_builtins();
        let available_algos = reg.list_names();
        let mut app = Self {
            tab: Tab::Search,
            dictionaries: Vec::new(),
            selected_dict: None,
            active_searcher: None,
            search_hash: String::new(),
            search_result: String::new(),
            available_algos,
            gen_algo_idx: 0,
            gen_alphabet: "0123456789".into(),
            gen_chunks: 1,
            gen_threads: recommended_threads(),
            gen_output: "dictionary.fdh".into(),
            append_chunks_count: 1,
            conv_input_dir: String::new(),
            conv_output_file: "converted.fdh".into(),
            worker_rx: None,
            worker_progress: 0.0,
            worker_logs: Vec::new(),
            worker_running: false,
        };
        app.load_dictionaries();
        app
    }

    fn load_dictionaries(&mut self) {
        self.dictionaries.clear();
        if let Ok(content) = fs::read_to_string(STORAGE_FILE) {
            for line in content.lines() {
                let p = line.trim();
                if !p.is_empty() {
                    self.push_dict_entry(PathBuf::from(p));
                }
            }
        }
        if !self.dictionaries.is_empty() {
            self.selected_dict = Some(0);
        }
    }

    fn save_dictionaries(&self) {
        let mut out = String::new();
        for d in &self.dictionaries {
            out.push_str(&d.path.to_string_lossy());
            out.push('\n');
        }
        let _ = fs::write(STORAGE_FILE, out);
    }

    fn push_dict_entry(&mut self, path: PathBuf) {
        match FdhHeader::read_file(&path) {
            Ok(hdr) => self.dictionaries.push(DictEntry {
                path,
                header: Some(hdr),
                error: None,
            }),
            Err(e) => self.dictionaries.push(DictEntry {
                path,
                header: None,
                error: Some(e.to_string()),
            }),
        }
    }

    fn ensure_searcher(&mut self, path: &Path) -> Result<&DictionarySearcher, String> {
        let needs_load = match &self.active_searcher {
            Some((loaded_path, _)) => loaded_path != path,
            None => true,
        };
        if needs_load {
            let searcher = DictionarySearcher::open(path).map_err(|e| e.to_string())?;
            self.active_searcher = Some((path.to_path_buf(), searcher));
        }
        Ok(&self.active_searcher.as_ref().unwrap().1)
    }

    fn poll_worker(&mut self) {
        let mut finished = false;
        if let Some(rx) = &self.worker_rx {
            while let Ok(ev) = rx.try_recv() {
                match ev {
                    WorkerEvent::Log(msg) => self.worker_logs.push(msg),
                    WorkerEvent::Progress(p) => self.worker_progress = p,
                    WorkerEvent::Done(res) => {
                        match res {
                            Ok(msg) => self.worker_logs.push(format!("DONE: {}", msg)),
                            Err(err) => self.worker_logs.push(format!("ERROR: {}", err)),
                        }
                        self.worker_progress = 1.0;
                        finished = true;
                    }
                }
            }
        }
        if finished {
            self.worker_running = false;
            self.worker_rx = None;
            self.active_searcher = None;
            // Refresh headers
            let paths: Vec<PathBuf> = self.dictionaries.iter().map(|d| d.path.clone()).collect();
            self.dictionaries.clear();
            for p in paths {
                self.push_dict_entry(p);
            }
        }
    }

    fn start_generate(&mut self) {
        let algo = self.available_algos[self.gen_algo_idx].to_string();
        let alphabet = self.gen_alphabet.clone();
        let chunks = self.gen_chunks;
        let threads = self.gen_threads;
        let output = PathBuf::from(&self.gen_output);

        let (tx, rx) = mpsc::channel();
        self.worker_rx = Some(rx);
        self.worker_running = true;
        self.worker_progress = 0.0;
        self.worker_logs.clear();
        self.worker_logs.push(format!(
            "Starting generation: {} ({} chunks, {} threads)...",
            output.display(),
            chunks,
            threads
        ));

        thread::spawn(move || {
            let mut opts = GenerateOptions::new(algo, alphabet, chunks);
            opts.threads = threads;
            let mut done = 0u32;
            let res = generate_dictionary(&output, &opts, |stats| {
                done += 1;
                let _ = tx.send(WorkerEvent::Progress(done as f32 / chunks.max(1) as f32));
                let _ = tx.send(WorkerEvent::Log(format!(
                    "Chunk #{} ready in {:.2}s (hash={:.0}ms, sort={:.0}ms, write={:.0}ms)",
                    stats.chunk_index,
                    stats.total_ms / 1000.0,
                    stats.hash_ms,
                    stats.sort_ms,
                    stats.write_ms
                )));
            });
            match res {
                Ok(hdr) => {
                    let _ = tx.send(WorkerEvent::Done(Ok(format!(
                        "Created {} ({} chunks, alphabet={:?})",
                        output.display(),
                        hdr.chunk_count,
                        hdr.alphabet
                    ))));
                }
                Err(e) => {
                    let _ = tx.send(WorkerEvent::Done(Err(e.to_string())));
                }
            }
        });
    }

    fn start_append(&mut self, path: PathBuf) {
        let chunks = self.append_chunks_count;
        let threads = self.gen_threads;

        let (tx, rx) = mpsc::channel();
        self.worker_rx = Some(rx);
        self.worker_running = true;
        self.worker_progress = 0.0;
        self.worker_logs.clear();
        self.worker_logs.push(format!(
            "Appending {} chunk(s) to {}...",
            chunks,
            path.display()
        ));

        thread::spawn(move || {
            let mut done = 0u32;
            let res = append_chunks(&path, chunks, threads, |stats| {
                done += 1;
                let _ = tx.send(WorkerEvent::Progress(done as f32 / chunks.max(1) as f32));
                let _ = tx.send(WorkerEvent::Log(format!(
                    "Appended chunk #{} in {:.2}s",
                    stats.chunk_index,
                    stats.total_ms / 1000.0
                )));
            });
            match res {
                Ok(hdr) => {
                    let _ = tx.send(WorkerEvent::Done(Ok(format!(
                        "Dictionary now has {} chunks",
                        hdr.chunk_count
                    ))));
                }
                Err(e) => {
                    let _ = tx.send(WorkerEvent::Done(Err(e.to_string())));
                }
            }
        });
    }

    fn start_convert(&mut self) {
        let input = PathBuf::from(&self.conv_input_dir);
        let output = PathBuf::from(&self.conv_output_file);

        let (tx, rx) = mpsc::channel();
        self.worker_rx = Some(rx);
        self.worker_running = true;
        self.worker_progress = 0.0;
        self.worker_logs.clear();
        self.worker_logs.push(format!(
            "Converting {} -> {}...",
            input.display(),
            output.display()
        ));

        thread::spawn(move || {
            let res = convert_legacy_dir(&input, &output, |done, total| {
                let _ = tx.send(WorkerEvent::Progress(done as f32 / total.max(1) as f32));
                if done == total || done % 10 == 0 || total <= 20 {
                    let _ = tx.send(WorkerEvent::Log(format!("Copied {}/{} chunks", done, total)));
                }
            });
            match res {
                Ok(report) => {
                    for w in report.warnings {
                        let _ = tx.send(WorkerEvent::Log(format!("WARNING: {}", w)));
                    }
                    let _ = tx.send(WorkerEvent::Done(Ok(format!(
                        "Converted {} chunks ({}) -> {}",
                        report.header.chunk_count,
                        report.header.algorithm,
                        output.display()
                    ))));
                }
                Err(e) => {
                    let _ = tx.send(WorkerEvent::Done(Err(e.to_string())));
                }
            }
        });
    }
}

impl eframe::App for FdhGuiApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.poll_worker();
        if self.worker_running {
            ctx.request_repaint();
        }

        egui::TopBottomPanel::top("top_bar").show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.heading("FlashDeHash");
                ui.separator();
                ui.selectable_value(&mut self.tab, Tab::Search, "Search");
                ui.selectable_value(&mut self.tab, Tab::Generate, "Generate / Append");
                ui.selectable_value(&mut self.tab, Tab::Convert, "Convert Legacy");
            });
        });

        egui::SidePanel::left("dicts_panel")
            .min_width(240.0)
            .show(ctx, |ui| {
                ui.heading("Dictionaries (.fdh)");
                ui.horizontal(|ui| {
                    if ui.button("+ Add").clicked()
                        && let Some(path) = rfd::FileDialog::new()
                            .add_filter("FDH Dictionary", &["fdh"])
                            .pick_file()
                    {
                        self.push_dict_entry(path);
                        self.selected_dict = Some(self.dictionaries.len() - 1);
                        self.save_dictionaries();
                    }
                    if ui
                        .add_enabled(self.selected_dict.is_some(), egui::Button::new("Remove"))
                        .clicked()
                        && let Some(idx) = self.selected_dict
                    {
                        self.dictionaries.remove(idx);
                        self.selected_dict = if self.dictionaries.is_empty() {
                            None
                        } else {
                            Some(idx.min(self.dictionaries.len() - 1))
                        };
                        self.active_searcher = None;
                        self.save_dictionaries();
                    }
                });
                ui.separator();

                egui::ScrollArea::vertical().show(ui, |ui| {
                    for (idx, entry) in self.dictionaries.iter().enumerate() {
                        let name = entry
                            .path
                            .file_name()
                            .and_then(|n| n.to_str())
                            .unwrap_or("dictionary.fdh");
                        let selected = self.selected_dict == Some(idx);
                        if ui.selectable_label(selected, name).clicked() {
                            self.selected_dict = Some(idx);
                        }
                        if let Some(hdr) = &entry.header {
                            ui.small(format!(
                                "{} | {} chunks | {} chars",
                                hdr.algorithm,
                                hdr.chunk_count,
                                hdr.alphabet.chars().count()
                            ));
                        } else if let Some(err) = &entry.error {
                            ui.colored_label(egui::Color32::RED, err);
                        }
                        ui.separator();
                    }
                });
            });

        egui::CentralPanel::default().show(ctx, |ui| match self.tab {
            Tab::Search => self.ui_search(ui),
            Tab::Generate => self.ui_generate(ui),
            Tab::Convert => self.ui_convert(ui),
        });
    }
}

impl FdhGuiApp {
    fn ui_search(&mut self, ui: &mut egui::Ui) {
        ui.heading("Instant Hash Search");
        let selected_path = self
            .selected_dict
            .and_then(|i| self.dictionaries.get(i))
            .map(|d| d.path.clone());

        if let Some(path) = selected_path {
            ui.label(format!("Active: {}", path.display()));
            ui.add_space(8.0);
            ui.horizontal(|ui| {
                ui.label("Hex hash:");
                let resp = ui.add(
                    egui::TextEdit::singleline(&mut self.search_hash)
                        .desired_width(420.0)
                        .hint_text("Paste hex hash here..."),
                );
                let enter = resp.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
                if ui.button("Crack").clicked() || enter {
                    let h = self.search_hash.trim().to_string();
                    match self.ensure_searcher(&path) {
                        Ok(searcher) => match searcher.search_hex(&h) {
                            Ok(Some(hit)) => {
                                self.search_result = format!(
                                    "FOUND: {:?}\nChunk: #{}\nPosition: {}\nTime: {:.3} ms{}",
                                    hit.plaintext,
                                    hit.chunk_index,
                                    hit.position,
                                    hit.elapsed.as_secs_f64() * 1000.0,
                                    if hit.used_fallback { " (fallback)" } else { "" }
                                );
                            }
                            Ok(None) => self.search_result = "Hash not found.".into(),
                            Err(e) => self.search_result = format!("Error: {}", e),
                        },
                        Err(e) => self.search_result = format!("Failed to open dictionary: {}", e),
                    }
                }
            });
            ui.add_space(12.0);
            ui.group(|ui| {
                ui.set_min_width(ui.available_width());
                ui.label(if self.search_result.is_empty() {
                    "Enter a hash and press Crack."
                } else {
                    &self.search_result
                });
            });
        } else {
            ui.label("Select or add a `.fdh` dictionary from the left sidebar.");
        }
    }

    fn ui_generate(&mut self, ui: &mut egui::Ui) {
        ui.heading("Create New Dictionary (.fdh)");
        ui.add_space(4.0);

        egui::Grid::new("gen_grid").num_columns(2).show(ui, |ui| {
            ui.label("Hash algorithm:");
            egui::ComboBox::from_id_salt("algo_combo")
                .selected_text(self.available_algos[self.gen_algo_idx])
                .show_ui(ui, |ui| {
                    for (i, &name) in self.available_algos.iter().enumerate() {
                        ui.selectable_value(&mut self.gen_algo_idx, i, name);
                    }
                });
            ui.end_row();

            ui.label("Alphabet:");
            ui.text_edit_singleline(&mut self.gen_alphabet);
            ui.end_row();

            ui.label("Normalized preview:");
            match ChunkValueEncoding::new_normalized(&self.gen_alphabet) {
                Ok(enc) => ui.label(format!("{:?} (base {})", enc.alphabet(), enc.base())),
                Err(e) => ui.colored_label(egui::Color32::RED, e.to_string()),
            };
            ui.end_row();

            ui.label("Chunks (48 MiB each):");
            ui.add(egui::DragValue::new(&mut self.gen_chunks).range(1..=4096));
            ui.end_row();

            ui.label("Threads:");
            ui.add(egui::DragValue::new(&mut self.gen_threads).range(1..=64));
            ui.end_row();

            ui.label("Output .fdh:");
            ui.horizontal(|ui| {
                ui.text_edit_singleline(&mut self.gen_output);
                if ui.button("Browse...").clicked()
                    && let Some(p) = rfd::FileDialog::new()
                        .add_filter("FDH Dictionary", &["fdh"])
                        .save_file()
                {
                    self.gen_output = p.to_string_lossy().to_string();
                }
            });
            ui.end_row();
        });

        ui.add_space(6.0);
        if ui
            .add_enabled(!self.worker_running, egui::Button::new("Start Generation"))
            .clicked()
        {
            self.start_generate();
        }

        ui.separator();
        ui.heading("Append Chunks to Selected Dictionary");
        if let Some(idx) = self.selected_dict
            && let Some(entry) = self.dictionaries.get(idx)
        {
            let path = entry.path.clone();
            ui.horizontal(|ui| {
                ui.label("Additional chunks:");
                ui.add(egui::DragValue::new(&mut self.append_chunks_count).range(1..=4096));
                if ui
                    .add_enabled(!self.worker_running, egui::Button::new("Append"))
                    .clicked()
                {
                    self.start_append(path);
                }
            });
        } else {
            ui.label("Select a dictionary in the sidebar to append chunks.");
        }

        self.ui_worker_panel(ui);
    }

    fn ui_convert(&mut self, ui: &mut egui::Ui) {
        ui.heading("Convert Legacy Java Folder -> Single .fdh File");
        ui.add_space(4.0);

        egui::Grid::new("conv_grid").num_columns(2).show(ui, |ui| {
            ui.label("Legacy folder:");
            ui.horizontal(|ui| {
                ui.text_edit_singleline(&mut self.conv_input_dir);
                if ui.button("Browse...").clicked()
                    && let Some(dir) = rfd::FileDialog::new().pick_folder()
                {
                    self.conv_input_dir = dir.to_string_lossy().to_string();
                }
            });
            ui.end_row();

            ui.label("Output .fdh:");
            ui.horizontal(|ui| {
                ui.text_edit_singleline(&mut self.conv_output_file);
                if ui.button("Browse...").clicked()
                    && let Some(p) = rfd::FileDialog::new()
                        .add_filter("FDH Dictionary", &["fdh"])
                        .save_file()
                {
                    self.conv_output_file = p.to_string_lossy().to_string();
                }
            });
            ui.end_row();
        });

        ui.add_space(6.0);
        if ui
            .add_enabled(!self.worker_running, egui::Button::new("Convert"))
            .clicked()
        {
            self.start_convert();
        }

        self.ui_worker_panel(ui);
    }

    fn ui_worker_panel(&self, ui: &mut egui::Ui) {
        ui.separator();
        ui.add(egui::ProgressBar::new(self.worker_progress).show_percentage());
        egui::ScrollArea::vertical()
            .max_height(180.0)
            .stick_to_bottom(true)
            .show(ui, |ui| {
                for line in &self.worker_logs {
                    ui.monospace(line);
                }
            });
    }
}

fn main() -> eframe::Result<()> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([860.0, 560.0])
            .with_min_inner_size([640.0, 420.0]),
        ..Default::default()
    };
    eframe::run_native(
        "FlashDeHash",
        options,
        Box::new(|_cc| Ok(Box::new(FdhGuiApp::new()))),
    )
}

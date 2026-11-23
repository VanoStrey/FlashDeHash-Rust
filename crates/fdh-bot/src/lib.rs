use std::fs;
use std::path::Path;
use std::time::{Duration, Instant};

use fdh_core::DictionarySearcher;
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum BotError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("HTTP error: {0}")]
    Http(String),
    #[error("Bot config incomplete: {0}")]
    Config(String),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BotConfig {
    pub token: String,
    pub username: String,
}

impl BotConfig {
    pub fn load_or_create(path: impl AsRef<Path>) -> Result<Self, BotError> {
        let path = path.as_ref();
        if !path.exists() {
            let template = Self {
                token: "INSERT_TOKEN_HERE".into(),
                username: "INSERT_BOT_USERNAME_HERE".into(),
            };
            fs::write(path, serde_json::to_string_pretty(&template)?)?;
            return Err(BotError::Config(format!(
                "Created template at {}. Fill in token and username and restart.",
                path.display()
            )));
        }

        let content = fs::read_to_string(path)?;
        let cfg: Self = serde_json::from_str(&content)?;
        if cfg.token.contains("INSERT_")
            || cfg.token.contains("ВСТАВЬ")
            || cfg.token.trim().is_empty()
        {
            return Err(BotError::Config(format!(
                "Please fill in valid token in {}",
                path.display()
            )));
        }
        Ok(cfg)
    }
}

#[derive(Debug, Deserialize)]
struct TgResponse<T> {
    ok: bool,
    result: Option<T>,
}

#[derive(Debug, Deserialize)]
struct TgUpdate {
    update_id: i64,
    message: Option<TgMessage>,
}

#[derive(Debug, Deserialize)]
struct TgMessage {
    chat: TgChat,
    text: Option<String>,
}

#[derive(Debug, Deserialize)]
struct TgChat {
    id: i64,
}

/// Runs a synchronous long-polling Telegram bot backed by `DictionarySearcher`.
pub fn run_bot(config: &BotConfig, searcher: &DictionarySearcher) -> Result<(), BotError> {
    let base_url = format!("https://api.telegram.org/bot{}", config.token);
    let mut offset: i64 = 0;

    println!(
        "Telegram bot @{} started (algo: {}, chunks: {}, combinations: {})",
        config.username,
        searcher.header().algorithm,
        searcher.header().chunk_count,
        format_with_dots(searcher.header().total_combinations())
    );

    let agent: ureq::Agent = ureq::Agent::config_builder()
        .timeout_global(Some(Duration::from_secs(40)))
        .build()
        .into();

    loop {
        let url = format!("{}/getUpdates?timeout=30&offset={}", base_url, offset);
        let resp = match agent.get(&url).call() {
            Ok(r) => r,
            Err(e) => {
                eprintln!("getUpdates error: {} (retrying in 3s)", e);
                std::thread::sleep(Duration::from_secs(3));
                continue;
            }
        };

        let body: TgResponse<Vec<TgUpdate>> = match resp.into_body().read_json() {
            Ok(b) => b,
            Err(e) => {
                eprintln!("parse getUpdates error: {}", e);
                std::thread::sleep(Duration::from_secs(2));
                continue;
            }
        };

        if !body.ok {
            std::thread::sleep(Duration::from_secs(2));
            continue;
        }

        if let Some(updates) = body.result {
            for upd in updates {
                offset = upd.update_id + 1;
                if let Some(msg) = upd.message
                    && let Some(text) = msg.text
                {
                    handle_message(&agent, &base_url, msg.chat.id, text.trim(), searcher);
                }
            }
        }
    }
}

fn handle_message(
    agent: &ureq::Agent,
    base_url: &str,
    chat_id: i64,
    text: &str,
    searcher: &DictionarySearcher,
) {
    if text.eq_ignore_ascii_case("/start") {
        let hdr = searcher.header();
        let welcome = format!(
            "FlashDeHash (Rust Engine)\n\n\
             Algorithm: {}\n\
             Alphabet ({} chars): {:?}\n\
             Chunks: {}\n\
             Total combinations: {}\n\n\
             Send me a hex hash to crack it instantly.",
            hdr.algorithm,
            searcher.encoding().base(),
            hdr.alphabet,
            hdr.chunk_count,
            format_with_dots(hdr.total_combinations())
        );
        send_message(agent, base_url, chat_id, &welcome);
        return;
    }

    let t0 = Instant::now();
    let reply = match searcher.search_hex(text) {
        Ok(Some(hit)) => format!(
            "{}\n\nFound in chunk #{} in {:.3} ms",
            hit.plaintext,
            hit.chunk_index,
            hit.elapsed.as_secs_f64() * 1000.0
        ),
        Ok(None) => format!(
            "Hash not found ({:.3} ms)",
            t0.elapsed().as_secs_f64() * 1000.0
        ),
        Err(e) => format!("Invalid hash: {}", e),
    };
    send_message(agent, base_url, chat_id, &reply);
}

fn send_message(agent: &ureq::Agent, base_url: &str, chat_id: i64, text: &str) {
    let url = format!("{}/sendMessage", base_url);
    let payload = serde_json::json!({
        "chat_id": chat_id,
        "text": text,
    });
    if let Err(e) = agent.post(&url).send_json(payload) {
        eprintln!("sendMessage error: {}", e);
    }
}

pub fn format_with_dots(n: u128) -> String {
    let s = n.to_string();
    let mut out = String::with_capacity(s.len() + s.len() / 3);
    for (i, c) in s.chars().enumerate() {
        if i > 0 && (s.len() - i).is_multiple_of(3) {
            out.push('.');
        }
        out.push(c);
    }
    out
}

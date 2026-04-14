//! sotSh REPL entry point.

use rustyline::error::ReadlineError;
use rustyline::history::DefaultHistory;
use rustyline::Editor;

use sotos_sotsh::ast::{Ast, Command};
use sotos_sotsh::builtins;
use sotos_sotsh::context::Context;
use sotos_sotsh::error::Error;
use sotos_sotsh::parser;
use sotos_sotsh::value::Value;

const PROMPT: &str = "sotsh> ";

type ReplEditor = Editor<(), DefaultHistory>;

fn main() -> std::io::Result<()> {
    let mut ctx = Context::new()?;
    let mut rl: ReplEditor = match ReplEditor::new() {
        Ok(e) => e,
        Err(e) => {
            eprintln!("sotsh: failed to init line editor: {e}");
            std::process::exit(1);
        }
    };

    print_banner();

    loop {
        match rl.readline(PROMPT) {
            Ok(line) => {
                let trimmed = line.trim();
                if trimmed.is_empty() {
                    continue;
                }
                let _ = rl.add_history_entry(trimmed);

                if let Some(stop) = handle_meta(trimmed) {
                    if stop {
                        break;
                    }
                    continue;
                }

                match run_line(trimmed, &mut ctx) {
                    Ok(value) => print_value(&value),
                    Err(e) => eprintln!("sotsh: {e}"),
                }
            }
            Err(ReadlineError::Interrupted) => {
                // Ctrl-C: drop the current line, keep the REPL alive.
                continue;
            }
            Err(ReadlineError::Eof) => {
                println!();
                break;
            }
            Err(e) => {
                eprintln!("sotsh: readline error: {e}");
                break;
            }
        }
    }

    Ok(())
}

/// Handle `:` meta-commands. Returns `Some(true)` to exit the REPL,
/// `Some(false)` when the line was a consumed meta-command, and `None`
/// when the line should flow through the normal pipeline path.
fn handle_meta(line: &str) -> Option<bool> {
    if !line.starts_with(':') {
        return None;
    }
    let mut parts = line[1..].split_whitespace();
    match parts.next().unwrap_or("") {
        "quit" | "q" | "exit" => Some(true),
        "help" | "h" | "?" => {
            println!("{}", help_text());
            Some(false)
        }
        other => {
            eprintln!("sotsh: unknown meta-command ':{other}' (try :help)");
            Some(false)
        }
    }
}

/// Parse one line and execute its pipeline. The final stage's [`Value`] is
/// returned — Wave-2 will grow this into streaming intermediate values.
fn run_line(line: &str, ctx: &mut Context) -> Result<Value, Error> {
    let ast = parser::parse(line)?;
    let Ast::Pipeline(cmds) = ast;
    execute_pipeline(&cmds, ctx)
}

fn execute_pipeline(cmds: &[Command], ctx: &mut Context) -> Result<Value, Error> {
    let mut last = Value::Nil;
    for cmd in cmds {
        check_caps(&cmd.name)?;
        last = builtins::dispatch(&cmd.name, &cmd.args, ctx)?;
    }
    Ok(last)
}

/// Stub capability check. Wave-2+ will wire this to the real cap set held
/// in [`Context`]; today every cap is "held" so dispatch succeeds.
fn check_caps(name: &str) -> Result<(), Error> {
    let _required = builtins::required_caps(name);
    Ok(())
}

fn print_value(v: &Value) {
    match v {
        Value::Nil => {}
        other => println!("{other}"),
    }
}

fn print_banner() {
    println!("sotSh v0.1.0 — capability-first native shell for sotOS");
    println!("Type :help for meta-commands, :quit to exit.");
}

fn help_text() -> &'static str {
    "meta-commands:\n\
     \x20  :help, :h, :?       show this help\n\
     \x20  :quit, :q, :exit    leave the shell\n\
     \n\
     built-ins (Wave-2 work in progress): ls cat cd ps cap arm\n"
}

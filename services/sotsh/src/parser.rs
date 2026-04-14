//! Minimal pipeline parser for sotSh.
//!
//! Grammar (B4b: pipes + redirection + background):
//!
//! ```text
//! pipeline = command ( '|' command )* '&'?
//! command  = ident arg* redirect*
//! arg      = quoted_string | bare_word
//! redirect = ( '>>' | '>' | '<' ) path
//! path     = quoted_string | bare_word
//! ```
//!
//! The trailing `&` marks the pipeline as a **background job**. It is a
//! statement terminator only — `&&` (short-circuit AND) is not supported.
//!
//! Redirection tokens are consumed after the ident+args and are attached
//! to the [`Command`]'s `stdin` / `stdout` fields. `>>` sets `append=true`;
//! `>` sets `append=false`. Multiple redirects on the same command collapse
//! to the *last* one for each direction (shell-standard behaviour).
//!
//! Bare words that parse cleanly as an i64 are promoted to [`Value::Int`];
//! everything else stays a [`Value::Str`]. No env-var substitution, no
//! subshells.

use alloc::string::{String, ToString};
use alloc::vec::Vec;

use chumsky::prelude::*;

use crate::ast::{Ast, Command, Pipeline, Redirect};
use crate::error::Error;
use crate::value::Value;

/// Parse a single command line into an [`Ast::Pipeline`].
pub fn parse(input: &str) -> Result<Ast, Error> {
    pipeline_parser()
        .parse(input)
        .map_err(|errs| {
            let mut msg = String::new();
            for (i, e) in errs.iter().enumerate() {
                if i > 0 {
                    msg.push_str("; ");
                }
                msg.push_str(&e.to_string());
            }
            Error::ParseError(msg)
        })
}

/// One suffix clause attached to a command: either an argument or a
/// redirection. Collected together so they can appear in any order after
/// the command name (e.g. `cat file > out` vs `cat > out file`).
#[derive(Clone)]
enum Suffix {
    Arg(Value),
    Stdin(String),
    Stdout { path: String, append: bool },
}

fn pipeline_parser() -> impl Parser<char, Ast, Error = Simple<char>> {
    let ident = filter::<_, _, Simple<char>>(|c: &char| c.is_ascii_alphabetic() || *c == '_')
        .chain::<char, Vec<_>, _>(
            filter(|c: &char| c.is_ascii_alphanumeric() || *c == '_' || *c == '-' || *c == '.')
                .repeated(),
        )
        .collect::<String>()
        .labelled("identifier");

    // Double-quoted string with \" and \\ escapes.
    let escaped = just::<_, _, Simple<char>>('\\').ignore_then(choice((
        just('"').to('"'),
        just('\\').to('\\'),
        just('n').to('\n'),
        just('t').to('\t'),
        just('r').to('\r'),
    )));
    let quoted_str = just('"')
        .ignore_then(
            choice((escaped, filter(|c: &char| *c != '"' && *c != '\\'))).repeated(),
        )
        .then_ignore(just('"'))
        .collect::<String>()
        .labelled("quoted string");

    let quoted_arg = quoted_str.clone().map(Value::Str);

    // Bare word: any non-whitespace, non-pipe, non-quote, non-redirect run.
    // Parsed as an integer if every char (after an optional leading '-') is
    // a digit; otherwise kept as a Str.
    let bare_str = filter::<_, _, Simple<char>>(|c: &char| {
        !c.is_whitespace() && *c != '|' && *c != '"' && *c != '>' && *c != '<'
    })
    .repeated()
    .at_least(1)
    .collect::<String>()
    .labelled("bare word");

    let bare_arg = bare_str.clone().map(|s: String| match s.parse::<i64>() {
        Ok(n) => Value::Int(n),
        Err(_) => Value::Str(s),
    });

    let arg = choice((quoted_arg, bare_arg));

    let hspace = filter::<_, _, Simple<char>>(|c: &char| *c == ' ' || *c == '\t')
        .repeated()
        .at_least(1)
        .ignored();

    let opt_hspace = filter::<_, _, Simple<char>>(|c: &char| *c == ' ' || *c == '\t')
        .repeated()
        .ignored();

    // A path for redirection: same grammar as an arg but always string-typed.
    let path = choice((quoted_str.clone(), bare_str.clone()));

    // Redirect operators. `>>` must be tried BEFORE `>` so the lexer does
    // not gobble a single `>` and then choke on the trailing `>`.
    let append_op = just::<_, _, Simple<char>>('>').then(just('>')).ignored();
    let trunc_op = just::<_, _, Simple<char>>('>').ignored();
    let stdin_op = just::<_, _, Simple<char>>('<').ignored();

    let redir_append = append_op
        .ignore_then(opt_hspace.clone())
        .ignore_then(path.clone())
        .map(|p| Suffix::Stdout { path: p, append: true });
    let redir_trunc = trunc_op
        .ignore_then(opt_hspace.clone())
        .ignore_then(path.clone())
        .map(|p| Suffix::Stdout { path: p, append: false });
    let redir_stdin = stdin_op
        .ignore_then(opt_hspace.clone())
        .ignore_then(path.clone())
        .map(Suffix::Stdin);

    let suffix = choice((redir_append, redir_trunc, redir_stdin, arg.map(Suffix::Arg)));

    let command = ident
        .then(hspace.ignore_then(suffix).repeated())
        .map(|(name, suffixes)| fold_suffixes(name, suffixes));

    let pipe_sep = opt_hspace
        .clone()
        .ignore_then(just('|'))
        .then_ignore(opt_hspace.clone());

    // Optional `&` terminator (B4b): marks the pipeline as background.
    // Appears after the last command, before trailing whitespace / EOF.
    let bg_mark = opt_hspace
        .clone()
        .ignore_then(just::<_, _, Simple<char>>('&'))
        .or_not()
        .map(|m| m.is_some());

    command
        .separated_by(pipe_sep)
        .at_least(1)
        .then(bg_mark)
        .padded()
        .then_ignore(end())
        .map(|(commands, background)| Ast::Pipeline(Pipeline { commands, background }))
}

/// Collapse the flat `Suffix` list produced by the parser into a fully-
/// formed [`Command`]. Stdin / stdout redirects use last-wins semantics.
fn fold_suffixes(name: String, suffixes: Vec<Suffix>) -> Command {
    let mut args: Vec<Value> = Vec::new();
    let mut stdin: Option<Redirect> = None;
    let mut stdout: Option<Redirect> = None;
    let mut append = false;
    for s in suffixes {
        match s {
            Suffix::Arg(v) => args.push(v),
            Suffix::Stdin(p) => stdin = Some(Redirect::File(p)),
            Suffix::Stdout { path, append: ap } => {
                stdout = Some(Redirect::File(path));
                append = ap;
            }
        }
    }
    Command { name, args, stdin, stdout, append }
}

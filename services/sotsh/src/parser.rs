//! Minimal pipeline parser for sotSh.
//!
//! Grammar (intentionally tiny — Wave-2 built-ins don't need more yet):
//!
//! ```text
//! pipeline = command ( '|' command )*
//! command  = ident arg*
//! arg      = quoted_string | bare_word
//! ```
//!
//! Bare words that parse cleanly as an i64 are promoted to [`Value::Int`];
//! everything else stays a [`Value::Str`]. No env-var substitution, no
//! redirection, no subshells.

use chumsky::prelude::*;

use crate::ast::{Ast, Command};
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
    let quoted = just('"')
        .ignore_then(
            choice((escaped, filter(|c: &char| *c != '"' && *c != '\\'))).repeated(),
        )
        .then_ignore(just('"'))
        .collect::<String>()
        .map(Value::Str)
        .labelled("quoted string");

    // Bare word: any non-whitespace, non-pipe, non-quote run. Parsed as an
    // integer if every char (after an optional leading '-') is a digit;
    // otherwise kept as a Str.
    let bare = filter::<_, _, Simple<char>>(|c: &char| {
        !c.is_whitespace() && *c != '|' && *c != '"'
    })
    .repeated()
    .at_least(1)
    .collect::<String>()
    .map(|s: String| match s.parse::<i64>() {
        Ok(n) => Value::Int(n),
        Err(_) => Value::Str(s),
    })
    .labelled("bare word");

    let arg = choice((quoted, bare));

    let hspace = filter::<_, _, Simple<char>>(|c: &char| *c == ' ' || *c == '\t')
        .repeated()
        .at_least(1)
        .ignored();

    let command = ident
        .then(hspace.ignore_then(arg).repeated())
        .map(|(name, args)| Command { name, args });

    let pipe_sep = filter::<_, _, Simple<char>>(|c: &char| *c == ' ' || *c == '\t')
        .repeated()
        .ignore_then(just('|'))
        .then_ignore(filter(|c: &char| *c == ' ' || *c == '\t').repeated());

    command
        .separated_by(pipe_sep)
        .at_least(1)
        .padded()
        .then_ignore(end())
        .map(Ast::Pipeline)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_pipeline(ast: Ast, expected_names: &[&str]) {
        let Ast::Pipeline(cmds) = ast;
        let got: Vec<&str> = cmds.iter().map(|c| c.name.as_str()).collect();
        assert_eq!(got, expected_names);
    }

    #[test]
    fn parses_bare_ls() {
        let ast = parse("ls").expect("ls should parse");
        assert_pipeline(ast, &["ls"]);
    }

    #[test]
    fn parses_ls_with_arg() {
        let ast = parse("ls /tmp").expect("ls /tmp should parse");
        let Ast::Pipeline(cmds) = ast;
        assert_eq!(cmds.len(), 1);
        assert_eq!(cmds[0].name, "ls");
        assert_eq!(cmds[0].args.len(), 1);
        if let Value::Str(s) = &cmds[0].args[0] {
            assert_eq!(s, "/tmp");
        } else {
            panic!("expected Str arg");
        }
    }

    #[test]
    fn parses_ls_pipe_cat() {
        let ast = parse("ls | cat").expect("ls | cat should parse");
        assert_pipeline(ast, &["ls", "cat"]);
    }

    #[test]
    fn parses_three_stage_pipeline_with_args() {
        let ast = parse("ls /etc | cat foo | ps").expect("three-stage should parse");
        assert_pipeline(ast, &["ls", "cat", "ps"]);
    }

    #[test]
    fn parses_quoted_string_arg() {
        let ast = parse(r#"cat "hello world""#).expect("quoted should parse");
        let Ast::Pipeline(cmds) = ast;
        if let Value::Str(s) = &cmds[0].args[0] {
            assert_eq!(s, "hello world");
        } else {
            panic!("expected quoted Str");
        }
    }

    #[test]
    fn parses_integer_arg() {
        let ast = parse("cat 42").expect("int should parse");
        let Ast::Pipeline(cmds) = ast;
        if let Value::Int(n) = &cmds[0].args[0] {
            assert_eq!(*n, 42);
        } else {
            panic!("expected Int");
        }
    }

    #[test]
    fn rejects_empty_input() {
        assert!(parse("").is_err());
    }

    #[test]
    fn rejects_trailing_pipe() {
        assert!(parse("ls |").is_err());
    }
}

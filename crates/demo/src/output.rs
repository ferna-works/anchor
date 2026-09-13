use owo_colors::{OwoColorize, Stream};

/// Prints a success message to stdout.
pub fn success(message: &str) {
    println!(
        "{} {message}",
        "✓".if_supports_color(Stream::Stdout, |text| text.green())
    );
}

/// Prints an error message to stderr.
pub fn error(message: &str) {
    eprintln!(
        "{} {message}",
        "✗".if_supports_color(Stream::Stderr, |text| text.red())
    );
}

/// Prints a bold section header to stdout.
pub fn header(text: &str) {
    println!(
        "{}",
        text.if_supports_color(Stream::Stdout, |text| text.bold())
    );
}

/// Prints a labeled field to stdout.
pub fn field(label: &str, value: &str) {
    println!(
        "  {}: {value}",
        label.if_supports_color(Stream::Stdout, |text| text.dimmed())
    );
}

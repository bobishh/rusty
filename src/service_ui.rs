//! Original Rusty branding and pinned tincanban styles, embedded independently of Sink.
use axum::{
    extract::Path,
    http::StatusCode,
    response::{IntoResponse, Response},
};

pub(crate) async fn asset(Path(name): Path<String>) -> Response {
    let (mime, bytes): (&str, &[u8]) = match name.as_str() {
        "OFL-Caveat.txt" => (
            "text/plain; charset=utf-8",
            include_bytes!("ui/OFL-Caveat.txt"),
        ),
        "OFL-FiraCode.txt" => (
            "text/plain; charset=utf-8",
            include_bytes!("ui/OFL-FiraCode.txt"),
        ),
        "archive-hatch.svg" => ("image/svg+xml", include_bytes!("ui/archive-hatch.svg")),
        "caveat-cyrillic-ext-wght.woff2" => (
            "font/woff2",
            include_bytes!("ui/caveat-cyrillic-ext-wght.woff2"),
        ),
        "caveat-cyrillic-wght.woff2" => (
            "font/woff2",
            include_bytes!("ui/caveat-cyrillic-wght.woff2"),
        ),
        "caveat-latin-ext-wght.woff2" => (
            "font/woff2",
            include_bytes!("ui/caveat-latin-ext-wght.woff2"),
        ),
        "caveat-latin-wght.woff2" => ("font/woff2", include_bytes!("ui/caveat-latin-wght.woff2")),
        "column-hatch.svg" => ("image/svg+xml", include_bytes!("ui/column-hatch.svg")),
        "design-system.css" => (
            "text/css; charset=utf-8",
            include_bytes!("ui/design-system.css"),
        ),
        "fira-code-cyrillic-wght.woff2" => (
            "font/woff2",
            include_bytes!("ui/fira-code-cyrillic-wght.woff2"),
        ),
        "fira-code-latin-wght.woff2" => (
            "font/woff2",
            include_bytes!("ui/fira-code-latin-wght.woff2"),
        ),
        "ink-focus-0.svg" => ("image/svg+xml", include_bytes!("ui/ink-focus-0.svg")),
        "ink-focus-1.svg" => ("image/svg+xml", include_bytes!("ui/ink-focus-1.svg")),
        "ink-focus-2.svg" => ("image/svg+xml", include_bytes!("ui/ink-focus-2.svg")),
        "ink-frame-0.svg" => ("image/svg+xml", include_bytes!("ui/ink-frame-0.svg")),
        "ink-frame-1.svg" => ("image/svg+xml", include_bytes!("ui/ink-frame-1.svg")),
        "ink-frame-2.svg" => ("image/svg+xml", include_bytes!("ui/ink-frame-2.svg")),
        "ink-frame-white.svg" => ("image/svg+xml", include_bytes!("ui/ink-frame-white.svg")),
        "ink-surface-0.svg" => ("image/svg+xml", include_bytes!("ui/ink-surface-0.svg")),
        "ink-surface-1.svg" => ("image/svg+xml", include_bytes!("ui/ink-surface-1.svg")),
        "ink-surface-2.svg" => ("image/svg+xml", include_bytes!("ui/ink-surface-2.svg")),
        "inter-latin-wght-normal.woff2" => (
            "font/woff2",
            include_bytes!("ui/inter-latin-wght-normal.woff2"),
        ),
        "rusty-head-180.png" => ("image/png", include_bytes!("ui/rusty-head-180.png")),
        "rusty-head-32.png" => ("image/png", include_bytes!("ui/rusty-head-32.png")),
        "rusty-logo.webp" => ("image/webp", include_bytes!("ui/rusty-logo.webp")),
        "typography.css" => (
            "text/css; charset=utf-8",
            include_bytes!("ui/typography.css"),
        ),
        _ => return StatusCode::NOT_FOUND.into_response(),
    };
    (
        [
            ("content-type", mime),
            ("x-content-type-options", "nosniff"),
            ("cache-control", "public, max-age=3600"),
        ],
        bytes,
    )
        .into_response()
}

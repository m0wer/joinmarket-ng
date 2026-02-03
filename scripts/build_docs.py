#!/usr/bin/env python3
"""Build API documentation using pdoc3 and convert DOCS.md to HTML."""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

import markdown  # type: ignore[import-untyped]

# Root directory
ROOT = Path(__file__).parent.parent

# Output directory
OUTPUT_DIR = ROOT / "docs_build"

# Modules to document
MODULES = [
    "jmcore/src/jmcore",
    "jmwallet/src/jmwallet",
    "taker/src/taker",
    "maker/src/maker",
    "directory_server/src/directory_server",
    "orderbook_watcher/src/orderbook_watcher",
]


def convert_latex_to_mathml(text: str) -> str:
    """Convert LaTeX math expressions to MathML.

    Handles both display math ($$...$$) and inline math ($...$).
    Uses latex2mathml for conversion, falling back to original text on error.
    """
    try:
        import latex2mathml.converter  # type: ignore[import-untyped]
    except ImportError:
        print("Warning: latex2mathml not installed, math will not be rendered")
        return text

    def convert_display_math(match: re.Match[str]) -> str:
        """Convert display math ($$...$$) to MathML."""
        latex = match.group(1).strip()
        try:
            mathml = latex2mathml.converter.convert(latex)
            # Wrap in a div for block display
            return f'<div class="math-display">{mathml}</div>'
        except Exception:
            # Return original on conversion error
            return match.group(0)

    def convert_inline_math(match: re.Match[str]) -> str:
        """Convert inline math ($...$) to MathML."""
        latex = match.group(1).strip()
        # Skip if it looks like an environment variable (all caps with underscores)
        if re.match(r"^[A-Z_]+(/|$)", latex):
            return match.group(0)
        try:
            mathml = latex2mathml.converter.convert(latex)
            # Wrap in a span for inline display
            return f'<span class="math-inline">{mathml}</span>'
        except Exception:
            # Return original on conversion error
            return match.group(0)

    # First convert display math ($$...$$) - must be done before inline
    # Use DOTALL to match across lines
    text = re.sub(r"\$\$(.+?)\$\$", convert_display_math, text, flags=re.DOTALL)

    # Then convert inline math ($...$)
    # Avoid matching:
    # - Already converted display math
    # - Content inside backticks (code)
    # - Shell variables like $HOME, $PATH, $JOINMARKET_DATA_DIR
    # The negative lookbehind (?<!`) avoids matching after backticks
    # The pattern requires math-like content (letters, numbers, operators, braces)
    text = re.sub(r"(?<![\$`])\$([^$\n`]+?)\$(?![\$`])", convert_inline_math, text)

    return text


def build_api_docs() -> None:
    """Generate API documentation using pdoc3."""
    print("Building API documentation with pdoc3...")

    # Build pdoc command
    cmd = [
        "pdoc",
        "--html",
        "--force",
        "--output-dir",
        str(OUTPUT_DIR),
    ]

    # Add all modules
    for module in MODULES:
        cmd.append(str(ROOT / module))

    # Run pdoc
    result = subprocess.run(cmd, capture_output=True, text=True)

    if result.returncode != 0:
        print(f"Error running pdoc: {result.stderr}", file=sys.stderr)
        sys.exit(1)

    print(f"✓ API docs generated in {OUTPUT_DIR}")


def inject_dark_theme() -> None:
    """Inject dark theme CSS into generated pdoc HTML files."""
    print("Injecting dark theme into API documentation...")

    dark_css_file = ROOT / "scripts" / "pdoc_dark.css"
    if not dark_css_file.exists():
        print("Warning: pdoc_dark.css not found, skipping theme injection")
        return

    # Read the dark CSS
    with open(dark_css_file) as f:
        dark_css = f.read()

    # CSS injection template
    css_inject = f"""
    <link rel="icon" type="image/x-icon" href="../favicon.ico">
    <style>
    {dark_css}
    </style>
</head>"""

    # Find and update all HTML files
    html_files = list(OUTPUT_DIR.rglob("*.html"))
    updated_count = 0

    for html_file in html_files:
        # Skip our main index.html (DOCS.md conversion)
        if html_file.name == "index.html" and html_file.parent == OUTPUT_DIR:
            continue

        try:
            content = html_file.read_text()

            # Inject CSS before closing </head> tag
            if "</head>" in content and dark_css not in content:
                content = content.replace("</head>", css_inject)
                html_file.write_text(content)
                updated_count += 1
        except Exception as e:
            print(f"Warning: Failed to inject CSS into {html_file}: {e}")

    print(f"✓ Injected dark theme into {updated_count} API documentation files")


def convert_docs_md() -> None:
    """Convert DOCS.md to HTML."""
    print("Converting DOCS.md to HTML...")

    docs_md = ROOT / "DOCS.md"
    if not docs_md.exists():
        print(f"Warning: {docs_md} not found", file=sys.stderr)
        return

    # Read markdown content
    with open(docs_md) as f:
        md_content = f.read()

    # Convert LaTeX math to MathML before markdown processing
    md_content = convert_latex_to_mathml(md_content)

    # Configure markdown extensions for better rendering
    md = markdown.Markdown(
        extensions=[
            "tables",
            "fenced_code",
            "codehilite",
            "toc",
            "sane_lists",
        ],
        extension_configs={
            "codehilite": {
                "css_class": "highlight",
                "guess_lang": True,
            },
            "toc": {
                "permalink": True,
                "toc_depth": 3,
            },
        },
    )

    # Convert to HTML
    content_html = md.convert(md_content)

    # Extract table of contents from markdown
    toc_html = md.toc if hasattr(md, "toc") else ""

    # Create full HTML page with dark theme and styling
    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>JoinMarket NG Documentation</title>
    <link rel="icon" type="image/x-icon" href="favicon.ico">
    <style>
        :root {{
            --bg-primary: #ffffff;
            --bg-secondary: #f5f5f5;
            --bg-nav: #ffffff;
            --bg-code: #f4f4f4;
            --bg-code-block: #f8f8f8;
            --bg-table-alt: #fafafa;
            --bg-table-header: #f8f8f8;
            --text-primary: #333;
            --text-secondary: #222;
            --border-color: #ddd;
            --link-color: #0066cc;
            --link-hover: #004499;
            --shadow: rgba(0,0,0,0.1);
        }}

        @media (prefers-color-scheme: dark) {{
            :root {{
                --bg-primary: #1e1e1e;
                --bg-secondary: #121212;
                --bg-nav: #252525;
                --bg-code: #2d2d2d;
                --bg-code-block: #2a2a2a;
                --bg-table-alt: #252525;
                --bg-table-header: #2d2d2d;
                --text-primary: #e0e0e0;
                --text-secondary: #f0f0f0;
                --border-color: #404040;
                --link-color: #58a6ff;
                --link-hover: #79c0ff;
                --shadow: rgba(0,0,0,0.3);
            }}
        }}

        * {{
            box-sizing: border-box;
        }}

        body {{
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
            line-height: 1.6;
            margin: 0;
            padding: 0;
            background: var(--bg-secondary);
            color: var(--text-primary);
            transition: background-color 0.3s ease, color 0.3s ease;
        }}

        .container {{
            max-width: 1400px;
            margin: 0 auto;
            padding: 20px;
            display: grid;
            grid-template-columns: 280px 1fr;
            gap: 30px;
        }}

        @media (max-width: 1024px) {{
            .container {{
                grid-template-columns: 1fr;
            }}
            .sidebar {{
                position: static !important;
                height: auto !important;
                max-height: 400px;
                overflow-y: auto;
            }}
        }}

        nav {{
            background: var(--bg-nav);
            padding: 15px 20px;
            box-shadow: 0 2px 5px var(--shadow);
            position: sticky;
            top: 0;
            z-index: 100;
            display: flex;
            flex-wrap: wrap;
            gap: 10px;
            align-items: center;
        }}

        nav a {{
            text-decoration: none;
            color: var(--link-color);
            font-weight: 500;
            padding: 8px 12px;
            border-radius: 5px;
            transition: background-color 0.2s;
        }}

        nav a:hover {{
            background: var(--bg-code);
        }}

        .sidebar {{
            position: sticky;
            top: 80px;
            height: fit-content;
            max-height: calc(100vh - 100px);
            overflow-y: auto;
            background: var(--bg-primary);
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 5px var(--shadow);
        }}

        .sidebar h2 {{
            margin-top: 0;
            font-size: 1.1em;
            border-bottom: 2px solid var(--border-color);
            padding-bottom: 10px;
        }}

        .sidebar ul {{
            list-style: none;
            padding-left: 0;
        }}

        .sidebar li {{
            margin: 8px 0;
        }}

        .sidebar li li {{
            margin-left: 15px;
            font-size: 0.9em;
        }}

        .sidebar li li li {{
            margin-left: 15px;
            font-size: 0.85em;
        }}

        .sidebar a {{
            color: var(--link-color);
            text-decoration: none;
            display: block;
            padding: 4px 8px;
            border-radius: 4px;
            transition: background-color 0.2s;
        }}

        .sidebar a:hover {{
            background: var(--bg-code);
        }}

        .content {{
            background: var(--bg-primary);
            padding: 40px;
            border-radius: 8px;
            box-shadow: 0 2px 5px var(--shadow);
            min-width: 0;
        }}

        h1, h2, h3, h4, h5, h6 {{
            color: var(--text-secondary);
            margin-top: 1.5em;
            margin-bottom: 0.5em;
            scroll-margin-top: 80px;
        }}

        h1 {{
            border-bottom: 3px solid var(--link-color);
            padding-bottom: 10px;
        }}

        h2 {{
            border-bottom: 2px solid var(--border-color);
            padding-bottom: 8px;
        }}

        code {{
            background: var(--bg-code);
            padding: 2px 6px;
            border-radius: 3px;
            font-family: "Monaco", "Courier New", "Consolas", monospace;
            font-size: 0.9em;
            color: var(--text-primary);
        }}

        pre {{
            background: var(--bg-code-block);
            border: 1px solid var(--border-color);
            border-radius: 5px;
            padding: 15px;
            overflow-x: auto;
            line-height: 1.4;
        }}

        pre code {{
            background: none;
            padding: 0;
        }}

        table {{
            border-collapse: collapse;
            width: 100%;
            margin: 20px 0;
            overflow-x: auto;
            display: block;
        }}

        table thead {{
            display: table;
            width: 100%;
            table-layout: fixed;
        }}

        table tbody {{
            display: table;
            width: 100%;
            table-layout: fixed;
        }}

        th, td {{
            border: 1px solid var(--border-color);
            padding: 12px;
            text-align: left;
        }}

        th {{
            background-color: var(--bg-table-header);
            font-weight: 600;
        }}

        tr:nth-child(even) {{
            background-color: var(--bg-table-alt);
        }}

        a {{
            color: var(--link-color);
            transition: color 0.2s;
        }}

        a:hover {{
            color: var(--link-hover);
        }}

        .headerlink {{
            opacity: 0.3;
            text-decoration: none;
            margin-left: 5px;
            font-weight: normal;
        }}

        .headerlink:hover {{
            opacity: 1;
        }}

        /* Scrollbar styling for dark mode */
        @media (prefers-color-scheme: dark) {{
            ::-webkit-scrollbar {{
                width: 12px;
            }}

            ::-webkit-scrollbar-track {{
                background: var(--bg-secondary);
            }}

            ::-webkit-scrollbar-thumb {{
                background: #555;
                border-radius: 6px;
            }}

            ::-webkit-scrollbar-thumb:hover {{
                background: #777;
            }}
        }}

        /* Math rendering styles */
        .math-display {{
            display: block;
            text-align: center;
            margin: 1.5em 0;
            overflow-x: auto;
        }}

        .math-inline {{
            display: inline;
        }}

        /* MathML styling */
        math {{
            font-size: 1.1em;
        }}

        .math-display math {{
            font-size: 1.2em;
        }}
    </style>
</head>
<body>
    <nav>
        <a href="index.html">📖 Protocol Guide</a>
        <a href="jmcore/index.html">jmcore</a>
        <a href="jmwallet/index.html">jmwallet</a>
        <a href="taker/index.html">taker</a>
        <a href="maker/index.html">maker</a>
        <a href="directory_server/index.html">directory_server</a>
        <a href="orderbook_watcher/index.html">orderbook_watcher</a>
    </nav>
    <div class="container">
        <aside class="sidebar">
            <h2>Table of Contents</h2>
            {toc_html}
        </aside>
        <main class="content">
            {content_html}
        </main>
    </div>
</body>
</html>
"""

    # Write HTML file
    output_file = OUTPUT_DIR / "index.html"
    output_file.parent.mkdir(parents=True, exist_ok=True)

    with open(output_file, "w") as f:
        f.write(html)

    print(f"✓ DOCS.md converted to {output_file}")


def create_nojekyll() -> None:
    """Create .nojekyll file for GitHub Pages."""
    print("Creating .nojekyll for GitHub Pages...")

    # GitHub Pages uses Jekyll by default, which ignores directories starting with _
    # pdoc3 generates files that may have _ prefixes, so we need .nojekyll
    nojekyll = OUTPUT_DIR / ".nojekyll"
    nojekyll.touch()

    print("✓ .nojekyll created")


def copy_favicon() -> None:
    """Copy favicon.ico to documentation build directory."""
    print("Copying favicon.ico to documentation build...")

    import shutil

    favicon_src = ROOT / "media" / "favicon.ico"
    if not favicon_src.exists():
        print(f"Warning: {favicon_src} not found, skipping favicon copy")
        return

    favicon_dest = OUTPUT_DIR / "favicon.ico"
    shutil.copy2(favicon_src, favicon_dest)

    print("✓ favicon.ico copied to documentation build")


def main() -> None:
    """Main entry point."""
    print("=" * 60)
    print("Building JoinMarket NG Documentation")
    print("=" * 60)

    # Clean output directory
    if OUTPUT_DIR.exists():
        import shutil

        print(f"Cleaning {OUTPUT_DIR}...")
        shutil.rmtree(OUTPUT_DIR)

    # Build API docs
    build_api_docs()

    # Inject dark theme into API docs
    inject_dark_theme()

    # Convert DOCS.md
    convert_docs_md()

    # Create .nojekyll for GitHub Pages
    create_nojekyll()

    # Copy favicon to docs build
    copy_favicon()

    print("=" * 60)
    print("✓ Documentation build complete!")
    print(f"Output directory: {OUTPUT_DIR}")
    print("=" * 60)


if __name__ == "__main__":
    main()

use std::env;
use std::fs;
use std::path::Path;

fn main() {
    println!("cargo:rerun-if-changed=../../assets/logo.svg");

    let out_dir = env::var("OUT_DIR").unwrap();
    generate_logos(&out_dir);
}

fn generate_logos(out_dir: &str) {
    let manifest_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
    let svg_path = Path::new(&manifest_dir)
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("assets/logo.svg");

    // Read and parse the SVG
    let svg_data = fs::read(&svg_path).expect("Failed to read logo.svg");
    let tree = resvg::usvg::Tree::from_data(&svg_data, &resvg::usvg::Options::default())
        .expect("Failed to parse SVG");

    // Generate PNGs at different sizes for different use cases
    let sizes = [
        (64, "logo_64.png"),   // Small notifications
        (128, "logo_128.png"), // Standard notifications
        (256, "logo_256.png"), // High-DPI notifications
    ];

    for (size, filename) in sizes {
        let output_path = Path::new(out_dir).join(filename);
        render_png(&tree, size, &output_path);
    }
}

fn render_png(tree: &resvg::usvg::Tree, size: u32, output_path: &Path) {
    let tree_size = tree.size();
    let scale = size as f32 / tree_size.width().max(tree_size.height());

    let scaled_width = (tree_size.width() * scale).ceil() as u32;
    let scaled_height = (tree_size.height() * scale).ceil() as u32;

    let mut pixmap = resvg::tiny_skia::Pixmap::new(scaled_width, scaled_height)
        .expect("Failed to create pixmap");

    // Fill with transparent background
    pixmap.fill(resvg::tiny_skia::Color::TRANSPARENT);

    let transform = resvg::tiny_skia::Transform::from_scale(scale, scale);

    resvg::render(tree, transform, &mut pixmap.as_mut());

    pixmap.save_png(output_path).expect("Failed to save PNG");
}

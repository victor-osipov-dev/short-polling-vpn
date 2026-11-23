use eframe::egui;

pub const BG: egui::Color32 = egui::Color32::from_rgb(11, 14, 20);
pub const HEADER: egui::Color32 = egui::Color32::from_rgb(13, 17, 24);
pub const CARD: egui::Color32 = egui::Color32::from_rgb(20, 25, 34);
pub const CARD_HOVER: egui::Color32 = egui::Color32::from_rgb(27, 34, 46);
pub const BORDER: egui::Color32 = egui::Color32::from_rgb(38, 46, 59);
pub const TEXT: egui::Color32 = egui::Color32::from_rgb(241, 245, 250);
pub const MUTED: egui::Color32 = egui::Color32::from_rgb(139, 152, 171);
pub const ACCENT: egui::Color32 = egui::Color32::from_rgb(61, 125, 255);
pub const GREEN: egui::Color32 = egui::Color32::from_rgb(52, 211, 153);
pub const RED: egui::Color32 = egui::Color32::from_rgb(255, 107, 107);
pub const AMBER: egui::Color32 = egui::Color32::from_rgb(240, 183, 74);

pub fn apply(ctx: &egui::Context) {
    ctx.set_theme(egui::ThemePreference::Dark);
    ctx.all_styles_mut(|style| {
        let mut visuals = egui::Visuals::dark();
        visuals.panel_fill = BG;
        visuals.window_fill = BG;
        visuals.extreme_bg_color = CARD;
        visuals.faint_bg_color = CARD;
        visuals.override_text_color = Some(TEXT);
        visuals.widgets.noninteractive.bg_fill = CARD;
        visuals.widgets.noninteractive.bg_stroke = egui::Stroke::new(1.0, BORDER);
        visuals.widgets.inactive.bg_fill = CARD;
        visuals.widgets.inactive.bg_stroke = egui::Stroke::new(1.0, BORDER);
        visuals.widgets.hovered.bg_fill = CARD_HOVER;
        visuals.widgets.hovered.bg_stroke = egui::Stroke::new(1.0, ACCENT);
        visuals.widgets.active.bg_fill = egui::Color32::from_rgb(31, 42, 56);
        visuals.widgets.active.bg_stroke = egui::Stroke::new(1.0, ACCENT);
        visuals.selection.bg_fill = ACCENT.gamma_multiply(0.35);
        visuals.selection.stroke = egui::Stroke::new(1.0, ACCENT);
        visuals.hyperlink_color = ACCENT;
        style.visuals = visuals;
        style.spacing.item_spacing = egui::vec2(8.0, 8.0);
        style.spacing.button_padding = egui::vec2(12.0, 7.0);
        style.spacing.interact_size.y = 32.0;
        style.visuals.widgets.inactive.corner_radius = 9.0.into();
        style.visuals.widgets.hovered.corner_radius = 9.0.into();
        style.visuals.widgets.active.corner_radius = 9.0.into();
    });

    let mut fonts = egui::FontDefinitions::default();
    for (name, path) in [
        ("segoe", r"C:\Windows\Fonts\segoeui.ttf"),
        ("segoe-semibold", r"C:\Windows\Fonts\seguisb.ttf"),
    ] {
        if let Ok(bytes) = std::fs::read(path) {
            fonts
                .font_data
                .insert(name.to_owned(), egui::FontData::from_owned(bytes).into());
            fonts
                .families
                .entry(egui::FontFamily::Proportional)
                .or_default()
                .insert(0, name.to_owned());
        }
    }
    if let Ok(bytes) = std::fs::read(r"C:\Windows\Fonts\consola.ttf") {
        fonts
            .font_data
            .insert("consolas".into(), egui::FontData::from_owned(bytes).into());
        fonts
            .families
            .entry(egui::FontFamily::Monospace)
            .or_default()
            .insert(0, "consolas".into());
    }
    ctx.set_fonts(fonts);
}

pub fn card() -> egui::Frame {
    egui::Frame::NONE
        .fill(CARD)
        .stroke(egui::Stroke::new(1.0, BORDER))
        .corner_radius(16)
        .inner_margin(egui::Margin::symmetric(18, 16))
}

/// A card that always fills the current content column, so every block in a
/// page has the same width.
pub fn card_ui(ui: &mut egui::Ui, add: impl FnOnce(&mut egui::Ui)) {
    card().show(ui, |ui| {
        ui.set_min_width(ui.available_width());
        add(ui);
    });
}

pub fn section_title(ui: &mut egui::Ui, text: &str) {
    ui.add_space(2.0);
    ui.label(egui::RichText::new(text).size(16.0).color(TEXT).strong());
    ui.add_space(4.0);
}

pub fn hint(ui: &mut egui::Ui, text: &str) {
    ui.label(egui::RichText::new(text).size(11.0).color(MUTED));
}

/// Small pill-shaped navigation / language button.
pub fn nav_button(ui: &mut egui::Ui, text: &str, active: bool) -> bool {
    let color = if active {
        egui::Color32::WHITE
    } else {
        MUTED
    };
    ui.add(
        egui::Button::new(egui::RichText::new(text).size(13.0).strong().color(color))
            .fill(if active {
                ACCENT
            } else {
                egui::Color32::TRANSPARENT
            })
            .stroke(egui::Stroke::new(
                1.0,
                if active { ACCENT } else { BORDER },
            ))
            .corner_radius(9),
    )
    .clicked()
}

/// Compact toolbar button used above the profile list.
pub fn tool_button(ui: &mut egui::Ui, text: &str) -> bool {
    tool_button_response(ui, text).clicked()
}

/// Same button as [`tool_button`], but returns the full response so callers
/// can inspect its rectangle (used to exclude the Test button from card clicks).
pub fn tool_button_response(ui: &mut egui::Ui, text: &str) -> egui::Response {
    ui.add(
        egui::Button::new(egui::RichText::new(text).size(12.0).color(TEXT))
            .fill(egui::Color32::TRANSPARENT)
            .stroke(egui::Stroke::new(1.0, BORDER))
            .corner_radius(9),
    )
}

/// Compact destructive action button (e.g. remove a subscription).
pub fn danger_button(ui: &mut egui::Ui, text: &str) -> bool {
    ui.add(
        egui::Button::new(egui::RichText::new(text).size(12.0).color(RED))
            .fill(egui::Color32::TRANSPARENT)
            .stroke(egui::Stroke::new(1.0, RED.gamma_multiply(0.45)))
            .corner_radius(9),
    )
    .clicked()
}

pub fn pill(ui: &mut egui::Ui, text: &str, color: egui::Color32) {
    egui::Frame::NONE
        .fill(color.gamma_multiply(0.16))
        .corner_radius(10)
        .inner_margin(egui::Margin::symmetric(8, 3))
        .show(ui, |ui| {
            ui.label(egui::RichText::new(text).size(11.0).color(color).strong());
        });
}

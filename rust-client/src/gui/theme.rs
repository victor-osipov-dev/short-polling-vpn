use eframe::egui;

pub const BG: egui::Color32 = egui::Color32::from_rgb(10, 13, 18);
pub const CARD: egui::Color32 = egui::Color32::from_rgb(19, 24, 32);
pub const CARD_HOVER: egui::Color32 = egui::Color32::from_rgb(25, 32, 42);
pub const BORDER: egui::Color32 = egui::Color32::from_rgb(38, 47, 60);
pub const TEXT: egui::Color32 = egui::Color32::from_rgb(232, 238, 246);
pub const MUTED: egui::Color32 = egui::Color32::from_rgb(136, 149, 166);
pub const ACCENT: egui::Color32 = egui::Color32::from_rgb(77, 163, 255);
pub const GREEN: egui::Color32 = egui::Color32::from_rgb(61, 214, 140);
pub const RED: egui::Color32 = egui::Color32::from_rgb(255, 107, 107);
pub const AMBER: egui::Color32 = egui::Color32::from_rgb(240, 183, 74);

pub fn apply(ctx: &egui::Context) {
    ctx.set_theme(egui::ThemePreference::Dark);
    ctx.all_styles_mut(|style| {
        let mut visuals = egui::Visuals::dark();
        visuals.panel_fill = BG;
        visuals.window_fill = BG;
        visuals.extreme_bg_color = egui::Color32::from_rgb(14, 18, 24);
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
        style.spacing.interact_size.y = 30.0;
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
        .corner_radius(14)
        .inner_margin(egui::Margin::symmetric(14, 12))
}

pub fn section_title(ui: &mut egui::Ui, text: &str) {
    ui.add_space(4.0);
    ui.label(
        egui::RichText::new(text.to_uppercase())
            .size(11.0)
            .color(MUTED)
            .strong(),
    );
    ui.add_space(2.0);
}

pub fn hint(ui: &mut egui::Ui, text: &str) {
    ui.label(egui::RichText::new(text).size(11.0).color(MUTED));
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

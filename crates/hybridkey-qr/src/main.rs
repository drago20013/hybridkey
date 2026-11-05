//! Shows hybridkey's QR code in a small GTK window.
//!
//! hybridkeyd writes the prompt to stdin, one command per line (see
//! docs/qr-helper-protocol.md). Closing the window or pressing Escape exits with
//! status 0, which the daemon treats as "cancelled by the user". EOF on stdin
//! closes the window.

use std::cell::RefCell;
use std::io::BufRead;
use std::rc::Rc;
use std::time::Duration;

use gtk::prelude::*;
use gtk::{gdk, gio, glib};
use qrcode::{Color, QrCode};

const APP_ID: &str = "dev.hybridkey.Qr";
const QR_SIZE: i32 = 280;
const QUIET_ZONE: usize = 4;

#[derive(Default)]
struct Prompt {
    rp: String,
    op: String,
    url: String,
    failed: bool,
}

struct Widgets {
    window: gtk::ApplicationWindow,
    title: gtk::Label,
    rp: gtk::Label,
    qr: gtk::DrawingArea,
    status: gtk::Label,
}

fn main() -> glib::ExitCode {
    let (tx, rx) = async_channel::unbounded::<String>();
    std::thread::spawn(move || {
        for line in std::io::stdin().lock().lines() {
            let Ok(line) = line else { break };
            if tx.send_blocking(line).is_err() {
                break;
            }
        }
        // Dropping tx closes the channel, which the UI treats as EOF.
    });

    let app = gtk::Application::builder()
        .application_id(APP_ID)
        .flags(gio::ApplicationFlags::NON_UNIQUE)
        .build();

    let rx = Rc::new(RefCell::new(Some(rx)));
    app.connect_activate(move |app| {
        let Some(rx) = rx.borrow_mut().take() else {
            return;
        };
        let prompt = Rc::new(RefCell::new(Prompt::default()));
        let widgets = Rc::new(build_ui(app, prompt.clone()));
        glib::spawn_future_local(drive(app.clone(), rx, prompt, widgets));
    });

    // Don't let GTK interpret our (nonexistent) arguments.
    app.run_with_args::<&str>(&[])
}

async fn drive(
    app: gtk::Application,
    rx: async_channel::Receiver<String>,
    prompt: Rc<RefCell<Prompt>>,
    w: Rc<Widgets>,
) {
    while let Ok(line) = rx.recv().await {
        let (cmd, arg) = line.split_once(' ').unwrap_or((line.as_str(), ""));
        match cmd {
            "rp" => prompt.borrow_mut().rp = arg.to_owned(),
            "op" => prompt.borrow_mut().op = arg.to_owned(),
            "url" => prompt.borrow_mut().url = arg.to_owned(),
            "show" => {
                let p = prompt.borrow();
                w.title.set_text(if p.op == "mc" {
                    "Create a passkey on your phone"
                } else {
                    "Sign in with your phone"
                });
                w.rp.set_text(&p.rp);
                w.qr.queue_draw();
                w.window.present();
            }
            "status" => {
                let (state, detail) = arg.split_once(' ').unwrap_or((arg, ""));
                if state == "failed" {
                    prompt.borrow_mut().failed = true;
                }
                w.status.set_text(&status_text(state, detail));
            }
            _ => {}
        }
    }

    // EOF: the daemon is done with this prompt. Leave errors on screen briefly.
    if prompt.borrow().failed {
        glib::timeout_future(Duration::from_secs(3)).await;
    }
    app.quit();
}

fn status_text(state: &str, detail: &str) -> String {
    match state {
        "proximity" => "Waiting for your phone. Keep it close to this computer.".into(),
        "connecting" => "Connecting to your phone…".into(),
        "authenticating" => "Setting up a secure connection…".into(),
        "connected" => "Connected. Confirm on your phone.".into(),
        "done" => "Done.".into(),
        "failed" if !detail.is_empty() => format!("Failed: {detail}"),
        "failed" => "Failed.".into(),
        other => other.to_owned(),
    }
}

fn build_ui(app: &gtk::Application, prompt: Rc<RefCell<Prompt>>) -> Widgets {
    let window = gtk::ApplicationWindow::builder()
        .application(app)
        .title("Passkey on phone")
        .resizable(false)
        .build();

    let content = gtk::Box::builder()
        .orientation(gtk::Orientation::Vertical)
        .spacing(12)
        .margin_top(24)
        .margin_bottom(24)
        .margin_start(24)
        .margin_end(24)
        .width_request(QR_SIZE + 40)
        .build();

    let title = gtk::Label::new(None);
    title.add_css_class("title-2");

    let rp = gtk::Label::new(None);
    rp.add_css_class("heading");
    rp.set_selectable(false);
    rp.set_ellipsize(gtk::pango::EllipsizeMode::Middle);

    let hint = gtk::Label::new(Some(
        "Scan this QR code with your phone's camera. Bluetooth must be on, on both devices.",
    ));
    hint.set_wrap(true);
    hint.set_justify(gtk::Justification::Center);
    hint.set_max_width_chars(36);
    hint.add_css_class("dim-label");

    let qr = gtk::DrawingArea::builder()
        .content_width(QR_SIZE)
        .content_height(QR_SIZE)
        .halign(gtk::Align::Center)
        .build();
    qr.set_draw_func(move |_, cr, width, height| {
        draw_qr(cr, width, height, &prompt.borrow().url);
    });

    let status = gtk::Label::new(Some("Waiting for your phone…"));
    status.set_wrap(true);
    status.set_justify(gtk::Justification::Center);
    status.set_max_width_chars(36);

    let cancel = gtk::Button::with_label("Cancel");
    cancel.set_halign(gtk::Align::Center);
    let app_for_cancel = app.clone();
    cancel.connect_clicked(move |_| app_for_cancel.quit());

    for widget in [
        title.upcast_ref::<gtk::Widget>(),
        rp.upcast_ref(),
        hint.upcast_ref(),
        qr.upcast_ref(),
        status.upcast_ref(),
        cancel.upcast_ref(),
    ] {
        content.append(widget);
    }
    window.set_child(Some(&content));

    let keys = gtk::EventControllerKey::new();
    let app_for_keys = app.clone();
    keys.connect_key_pressed(move |_, key, _, _| {
        if key == gdk::Key::Escape {
            app_for_keys.quit();
            return glib::Propagation::Stop;
        }
        glib::Propagation::Proceed
    });
    window.add_controller(keys);

    Widgets {
        window,
        title,
        rp,
        qr,
        status,
    }
}

fn draw_qr(cr: &gtk::cairo::Context, width: i32, height: i32, url: &str) {
    // Always dark-on-light: phone scanners expect it regardless of the theme.
    cr.set_source_rgb(1.0, 1.0, 1.0);
    cr.rectangle(0.0, 0.0, width as f64, height as f64);
    let _ = cr.fill();
    if url.is_empty() {
        return;
    }
    let Ok(code) = QrCode::new(url.as_bytes()) else {
        return;
    };
    let modules = code.width();
    let colors = code.to_colors();
    let span = (modules + 2 * QUIET_ZONE) as f64;
    let cell = (width.min(height) as f64 / span).floor().max(1.0);
    let offset_x = (width as f64 - cell * span) / 2.0 + cell * QUIET_ZONE as f64;
    let offset_y = (height as f64 - cell * span) / 2.0 + cell * QUIET_ZONE as f64;

    cr.set_source_rgb(0.0, 0.0, 0.0);
    for (i, color) in colors.iter().enumerate() {
        if *color == Color::Dark {
            let (x, y) = ((i % modules) as f64, (i / modules) as f64);
            cr.rectangle(offset_x + x * cell, offset_y + y * cell, cell, cell);
        }
    }
    let _ = cr.fill();
}

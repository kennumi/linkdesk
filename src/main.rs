#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]
//! LinkDesk: share your screen with a friend, or control theirs, over Tailscale.
//! Hosting only listens on your Tailscale address, so traffic is always encrypted
//! by Tailscale, and a shared password (HMAC challenge) gates who gets in.

use eframe::egui::{self, ColorImage, Event, MouseWheelUnit, PointerButton, Sense, TextureHandle, TextureOptions};
use enigo::{Axis, Button, Coordinate, Direction, Enigo, Keyboard, Mouse, Settings};
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use std::io::{self, BufRead, Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream, ToSocketAddrs};
use std::os::windows::process::CommandExt;
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

const PORT: u16 = 5900;
const MAX_MSG: usize = 64 << 20;
const NO_WINDOW: u32 = 0x0800_0000;
const TAILSCALE_EXE: &str = r"C:\Program Files\Tailscale\tailscale.exe";

// ---------- wire protocol: u32 length + payload ----------

fn send(s: &mut TcpStream, data: &[u8]) -> io::Result<()> {
    let mut buf = (data.len() as u32).to_be_bytes().to_vec();
    buf.extend_from_slice(data);
    s.write_all(&buf)
}

fn recv(s: &mut TcpStream) -> io::Result<Vec<u8>> {
    let mut len = [0; 4];
    s.read_exact(&mut len)?;
    let n = u32::from_be_bytes(len) as usize;
    if n > MAX_MSG {
        return Err(io::Error::other("message too big"));
    }
    let mut buf = vec![0; n];
    s.read_exact(&mut buf)?;
    Ok(buf)
}

fn mac(password: &str, nonce: &[u8]) -> Hmac<Sha256> {
    let mut m = Hmac::<Sha256>::new_from_slice(password.as_bytes()).unwrap();
    m.update(nonce);
    m
}

// ---------- shared state between UI and worker threads ----------

#[derive(Default)]
struct Shared {
    status: String,
    checked: bool,
    installed: bool,
    ip: Option<String>,
    busy: bool,
    hosting: bool,
    viewing: bool,
    conn: Option<TcpStream>,
    frame: Option<ColorImage>,
}
type Sh = Arc<Mutex<Shared>>;

fn set_status(sh: &Sh, msg: impl Into<String>) {
    sh.lock().unwrap().status = msg.into();
}

// ---------- Tailscale setup ----------

fn tailscale() -> Command {
    let exe = if std::path::Path::new(TAILSCALE_EXE).exists() { TAILSCALE_EXE } else { "tailscale" };
    let mut c = Command::new(exe);
    c.creation_flags(NO_WINDOW);
    c
}

fn ts_ip() -> Option<String> {
    let o = tailscale().args(["ip", "-4"]).output().ok()?;
    let ip = String::from_utf8_lossy(&o.stdout).lines().next()?.trim().to_string();
    (o.status.success() && !ip.is_empty()).then_some(ip)
}

fn ts_installed() -> bool {
    tailscale().arg("version").output().is_ok_and(|o| o.status.success())
}

fn install_tailscale(sh: &Sh) {
    set_status(sh, "Installing Tailscale... approve the Windows prompt if one appears");
    let ok = Command::new("winget")
        .args(["install", "-e", "--id", "Tailscale.Tailscale", "--silent",
               "--accept-package-agreements", "--accept-source-agreements"])
        .creation_flags(NO_WINDOW)
        .status()
        .is_ok_and(|s| s.success());
    if ok {
        sign_in(sh);
    } else {
        set_status(sh, "Install failed. Get it manually from tailscale.com/download");
    }
}

fn sign_in(sh: &Sh) {
    set_status(sh, "Finish signing in to Tailscale in your browser...");
    let Ok(mut child) = tailscale().arg("up").stdout(Stdio::null()).stderr(Stdio::piped()).spawn() else {
        return set_status(sh, "Couldn't run tailscale");
    };
    // `tailscale up` prints a login URL and blocks until sign-in completes.
    for line in io::BufReader::new(child.stderr.take().unwrap()).lines().map_while(Result::ok) {
        if let Some(url) = line.split_whitespace().find(|w| w.starts_with("https://")) {
            let _ = Command::new("explorer").arg(url).spawn();
        }
    }
    let _ = child.wait();
    set_status(sh, "");
}

// ---------- hosting (sharing your screen) ----------

fn host(sh: Sh, ip: String, password: String) {
    let listener = match TcpListener::bind((ip.as_str(), PORT)) {
        Ok(l) => l,
        Err(e) => {
            sh.lock().unwrap().hosting = false;
            return set_status(&sh, format!("Couldn't start sharing: {e}"));
        }
    };
    for conn in listener.incoming() {
        set_status(&sh, format!("Sharing at {ip}. Waiting for your friend..."));
        let Ok(mut conn) = conn else { continue };
        let err = serve(&sh, &mut conn, &password).unwrap_err();
        let _ = conn.shutdown(Shutdown::Both);
        set_status(&sh, format!("Sharing at {ip}. Last viewer left ({err}). Waiting..."));
    }
}

fn serve(sh: &Sh, conn: &mut TcpStream, password: &str) -> io::Result<()> {
    let mut nonce = [0u8; 32];
    getrandom::fill(&mut nonce).map_err(io::Error::other)?;
    send(conn, &nonce)?;
    conn.set_read_timeout(Some(Duration::from_secs(10)))?;
    if mac(password, &nonce).verify_slice(&recv(conn)?).is_err() {
        thread::sleep(Duration::from_secs(1)); // one guess per second
        return Err(io::Error::other("wrong password"));
    }
    conn.set_read_timeout(None)?;
    conn.set_nodelay(true)?;
    set_status(sh, format!("Your friend is connected from {}", conn.peer_addr()?.ip()));

    let mut reader = conn.try_clone()?;
    thread::spawn(move || {
        if let Ok(mut enigo) = Enigo::new(&Settings::default()) {
            while let Ok(msg) = recv(&mut reader) {
                handle(&mut enigo, &String::from_utf8_lossy(&msg));
            }
        }
        let _ = reader.shutdown(Shutdown::Both);
    });

    let monitor = xcap::Monitor::all()
        .map_err(io::Error::other)?
        .into_iter()
        .find(|m| m.is_primary().unwrap_or(false))
        .ok_or_else(|| io::Error::other("no primary monitor"))?;
    loop {
        let img = monitor.capture_image().map_err(io::Error::other)?;
        let mut jpg = Vec::new();
        image::codecs::jpeg::JpegEncoder::new_with_quality(&mut jpg, 50)
            .encode_image(&image::DynamicImage::ImageRgba8(img).to_rgb8())
            .map_err(io::Error::other)?;
        send(conn, &jpg)?;
        thread::sleep(Duration::from_millis(40)); // ponytail: full JPEG each frame, send changed tiles if it lags
    }
}

/// Input messages: "m x y" (0..1), "b l|r|m 1|0", "w clicks", "t text", "k KeyName ctrl alt shift".
fn handle(e: &mut Enigo, msg: &str) -> Option<()> {
    let (kind, rest) = (msg.get(..1)?, msg.get(1..)?);
    let mut a = rest.split_whitespace();
    match kind {
        "m" => {
            let (w, h) = e.main_display().ok()?;
            let x: f32 = a.next()?.parse().ok()?;
            let y: f32 = a.next()?.parse().ok()?;
            e.move_mouse((x * w as f32) as i32, (y * h as f32) as i32, Coordinate::Abs).ok()?;
        }
        "b" => {
            let b = match a.next()? { "l" => Button::Left, "r" => Button::Right, "m" => Button::Middle, _ => return None };
            e.button(b, if a.next()? == "1" { Direction::Press } else { Direction::Release }).ok()?;
        }
        "w" => e.scroll(a.next()?.parse().ok()?, Axis::Vertical).ok()?,
        "t" => e.text(rest).ok()?,
        "k" => {
            let key = map_key(a.next()?)?;
            let mods: Vec<_> = [enigo::Key::Control, enigo::Key::Alt, enigo::Key::Shift]
                .into_iter()
                .zip(a)
                .filter(|(_, on)| *on == "1")
                .map(|(m, _)| m)
                .collect();
            for m in &mods {
                e.key(*m, Direction::Press).ok()?;
            }
            e.key(key, Direction::Click).ok()?;
            for m in mods.iter().rev() {
                e.key(*m, Direction::Release).ok()?;
            }
        }
        _ => {}
    }
    Some(())
}

fn map_key(name: &str) -> Option<enigo::Key> {
    use enigo::Key as K;
    Some(match name {
        "Enter" => K::Return, "Tab" => K::Tab, "Backspace" => K::Backspace, "Escape" => K::Escape,
        "Delete" => K::Delete, "Insert" => K::Insert, "Home" => K::Home, "End" => K::End,
        "PageUp" => K::PageUp, "PageDown" => K::PageDown, "Space" => K::Space,
        "Up" => K::UpArrow, "Down" => K::DownArrow, "Left" => K::LeftArrow, "Right" => K::RightArrow,
        "F1" => K::F1, "F2" => K::F2, "F3" => K::F3, "F4" => K::F4, "F5" => K::F5, "F6" => K::F6,
        "F7" => K::F7, "F8" => K::F8, "F9" => K::F9, "F10" => K::F10, "F11" => K::F11, "F12" => K::F12,
        _ => {
            let mut c = name.chars();
            let ch = c.next()?;
            if c.next().is_some() {
                return None;
            }
            K::Unicode(ch.to_ascii_lowercase())
        }
    })
}

// ---------- viewing (controlling a friend's screen) ----------

fn view(sh: Sh, ctx: egui::Context, addr: String, password: String) {
    let mut got_frame = false;
    let result = (|| -> io::Result<()> {
        let sa = (addr.as_str(), PORT).to_socket_addrs()?.next().ok_or_else(|| io::Error::other("bad address"))?;
        let mut s = TcpStream::connect_timeout(&sa, Duration::from_secs(5))?;
        s.set_nodelay(true)?;
        let nonce = recv(&mut s)?;
        send(&mut s, &mac(&password, &nonce).finalize().into_bytes())?;
        sh.lock().unwrap().conn = Some(s.try_clone()?);
        loop {
            let jpg = recv(&mut s)?;
            let img = image::load_from_memory_with_format(&jpg, image::ImageFormat::Jpeg)
                .map_err(io::Error::other)?
                .to_rgba8();
            let frame = ColorImage::from_rgba_unmultiplied([img.width() as usize, img.height() as usize], &img);
            sh.lock().unwrap().frame = Some(frame);
            got_frame = true;
            ctx.request_repaint();
        }
    })();
    let mut s = sh.lock().unwrap();
    s.viewing = false;
    s.conn = None;
    s.frame = None;
    s.status = match result {
        Err(_) if !got_frame => "Couldn't connect: wrong password, or your friend isn't sharing".into(),
        Err(e) => format!("Disconnected ({e})"),
        Ok(()) => String::new(),
    };
    ctx.send_viewport_cmd(egui::ViewportCommand::InnerSize(egui::vec2(420.0, 320.0)));
    ctx.request_repaint();
}

/// Turn local egui input over the remote image into wire messages.
fn input_messages(events: &[Event], rect: egui::Rect) -> Vec<String> {
    let norm = |p: egui::Pos2| ((p.x - rect.min.x) / rect.width(), (p.y - rect.min.y) / rect.height());
    let mut out = Vec::new();
    for ev in events {
        match ev {
            Event::PointerMoved(p) if rect.contains(*p) => {
                let (x, y) = norm(*p);
                out.push(format!("m {x} {y}"));
            }
            Event::PointerButton { pos, button, pressed, .. } if rect.contains(*pos) => {
                let b = match button { PointerButton::Primary => "l", PointerButton::Secondary => "r", PointerButton::Middle => "m", _ => continue };
                let (x, y) = norm(*pos);
                out.push(format!("m {x} {y}"));
                out.push(format!("b {b} {}", *pressed as u8));
            }
            Event::MouseWheel { unit, delta, .. } => {
                let lines = if *unit == MouseWheelUnit::Point { delta.y / 50.0 } else { delta.y };
                if lines != 0.0 {
                    out.push(format!("w {}", -(lines.signum() * lines.abs().max(1.0)).round() as i32));
                }
            }
            Event::Text(t) => out.push(format!("t{t}")),
            Event::Key { key, pressed: true, modifiers: m, .. } => {
                // Plain printable keys arrive as Event::Text; only send shortcuts and non-text keys here.
                let name = key.name();
                let types_text = name.chars().count() == 1 || name == "Space";
                if m.ctrl || m.alt || !types_text {
                    out.push(format!("k {name} {} {} {}", m.ctrl as u8, m.alt as u8, m.shift as u8));
                }
            }
            // egui swallows Ctrl+C/X/V into these, so forward them as the shortcut.
            Event::Copy => out.push("k C 1 0 0".into()),
            Event::Cut => out.push("k X 1 0 0".into()),
            Event::Paste(_) => out.push("k V 1 0 0".into()),
            _ => {}
        }
    }
    out
}

// ---------- UI ----------

struct App {
    sh: Sh,
    password: String,
    friend: String,
    tex: Option<TextureHandle>,
}

impl eframe::App for App {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        let ctx = ui.ctx().clone();
        let mut sh = self.sh.lock().unwrap();

        if sh.viewing {
            if let Some(frame) = sh.frame.take() {
                match &mut self.tex {
                    Some(t) => t.set(frame, TextureOptions::LINEAR),
                    None => self.tex = Some(ctx.load_texture("remote", frame, TextureOptions::LINEAR)),
                }
            }
            egui::Panel::top("bar").show(ui, |ui| {
                ui.horizontal(|ui| {
                    if ui.button("Disconnect").clicked() {
                        if let Some(c) = &sh.conn {
                            let _ = c.shutdown(Shutdown::Both);
                        }
                    }
                    ui.label(format!("Controlling {}", self.friend));
                });
            });
            egui::CentralPanel::default().frame(egui::Frame::NONE).show(ui, |ui| {
                let (rect, _) = ui.allocate_exact_size(ui.available_size(), Sense::click_and_drag());
                if let Some(t) = &self.tex {
                    ui.painter().image(t.id(), rect, egui::Rect::from_min_max(egui::pos2(0.0, 0.0), egui::pos2(1.0, 1.0)), egui::Color32::WHITE);
                } else {
                    ui.painter().text(rect.center(), egui::Align2::CENTER_CENTER, "Connecting...", egui::FontId::proportional(18.0), egui::Color32::GRAY);
                }
                let msgs = input_messages(&ui.input(|i| i.events.clone()), rect);
                if let Some(c) = &mut sh.conn {
                    for m in msgs {
                        let _ = send(c, m.as_bytes());
                    }
                }
            });
            return;
        }

        egui::CentralPanel::default().show(ui, |ui| {
            ui.heading("LinkDesk");
            ui.add_space(8.0);

            // Step 1: Tailscale
            if !sh.checked {
                ui.label("Checking Tailscale...");
            } else if let Some(ip) = sh.ip.clone() {
                ui.horizontal(|ui| {
                    ui.label(format!("Your address: {ip}"));
                    if ui.small_button("Copy").clicked() {
                        ctx.copy_text(ip);
                    }
                });
            } else {
                let (label, installed) = if sh.installed { ("Sign in to Tailscale", true) } else { ("Install Tailscale", false) };
                if ui.add_enabled(!sh.busy, egui::Button::new(label)).clicked() {
                    sh.busy = true;
                    let s = self.sh.clone();
                    thread::spawn(move || {
                        if installed { sign_in(&s) } else { install_tailscale(&s) }
                        s.lock().unwrap().busy = false;
                    });
                }
                ui.small("Both of you need Tailscale, on the same network (invite each other at login.tailscale.com).");
            }
            ui.separator();

            // Step 2: password + share or connect
            ui.horizontal(|ui| {
                ui.label("Password:");
                ui.add(egui::TextEdit::singleline(&mut self.password).password(true));
            });
            let ready = !self.password.is_empty();

            ui.add_space(6.0);
            if sh.hosting {
                ui.label("Sharing your screen. Close LinkDesk to stop.");
            } else if ui.add_enabled(ready && sh.ip.is_some(), egui::Button::new("Share my screen")).clicked() {
                sh.hosting = true;
                let (s, ip, pw) = (self.sh.clone(), sh.ip.clone().unwrap(), self.password.clone());
                thread::spawn(move || host(s, ip, pw));
            }

            ui.add_space(6.0);
            ui.horizontal(|ui| {
                ui.add(egui::TextEdit::singleline(&mut self.friend).hint_text("friend's address").desired_width(140.0));
                if ui.add_enabled(ready && !self.friend.trim().is_empty(), egui::Button::new("Connect")).clicked() {
                    sh.viewing = true;
                    sh.status.clear();
                    self.tex = None;
                    ctx.send_viewport_cmd(egui::ViewportCommand::InnerSize(egui::vec2(1280.0, 760.0)));
                    let (s, c, addr, pw) = (self.sh.clone(), ctx.clone(), self.friend.trim().to_string(), self.password.clone());
                    thread::spawn(move || view(s, c, addr, pw));
                }
            });

            ui.add_space(8.0);
            ui.label(&sh.status);
        });
    }
}

fn main() -> eframe::Result {
    let sh = Sh::default();
    let (s, ctx_slot) = (sh.clone(), Arc::new(Mutex::new(None::<egui::Context>)));
    let ctx_bg = ctx_slot.clone();
    // Keep Tailscale status fresh (picks up install/sign-in done anywhere).
    thread::spawn(move || loop {
        let ip = ts_ip();
        let installed = ip.is_some() || ts_installed();
        {
            let mut g = s.lock().unwrap();
            (g.ip, g.installed, g.checked) = (ip, installed, true);
        }
        if let Some(c) = &*ctx_bg.lock().unwrap() {
            c.request_repaint();
        }
        thread::sleep(Duration::from_secs(3));
    });
    eframe::run_native(
        "LinkDesk",
        eframe::NativeOptions {
            viewport: egui::ViewportBuilder::default().with_inner_size([420.0, 320.0]),
            ..Default::default()
        },
        Box::new(move |cc| {
            *ctx_slot.lock().unwrap() = Some(cc.egui_ctx.clone());
            Ok(Box::new(App { sh, password: String::new(), friend: String::new(), tex: None }))
        }),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auth_and_framing() {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap();
        thread::spawn(move || {
            let mut c = TcpStream::connect(addr).unwrap();
            let nonce = recv(&mut c).unwrap();
            send(&mut c, &mac("pw", &nonce).finalize().into_bytes()).unwrap();
        });
        let (mut s, _) = l.accept().unwrap();
        send(&mut s, b"nonce123").unwrap();
        assert!(mac("pw", b"nonce123").verify_slice(&recv(&mut s).unwrap()).is_ok());
        assert!(mac("wrong", b"nonce123").verify_slice(&mac("pw", b"nonce123").finalize().into_bytes()).is_err());
    }

    #[test]
    fn keys_map() {
        assert_eq!(map_key("C"), Some(enigo::Key::Unicode('c')));
        assert_eq!(map_key("Enter"), Some(enigo::Key::Return));
        assert_eq!(map_key("Nope"), None);
    }
}

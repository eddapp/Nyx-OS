mod client;
mod ui;

use gtk::glib;
use gtk::prelude::*;

fn main() -> glib::ExitCode {
    let app = gtk::Application::builder()
        .application_id("org.nyxos.Dashboard")
        .build();

    app.connect_activate(ui::build);
    app.run()
}

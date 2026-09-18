//! Minimal `/etc/passwd` reader — no extra dependency for something this
//! small. Returns every account nyx-wipe should clean traces for: root plus
//! real human accounts (uid in the normal human range, with a real login
//! shell — not system/service accounts).

use std::fs;
use std::path::PathBuf;

pub struct Account {
    pub name: String,
    pub home: PathBuf,
}

const HUMAN_UID_MIN: u32 = 1000;
const HUMAN_UID_MAX: u32 = 60000;
const NON_LOGIN_SHELLS: &[&str] = &["/usr/bin/nologin", "/sbin/nologin", "/bin/false", "/usr/bin/false"];

pub fn accounts() -> Vec<Account> {
    let mut out = vec![Account {
        name: "root".to_string(),
        home: PathBuf::from("/root"),
    }];

    let Ok(contents) = fs::read_to_string("/etc/passwd") else {
        return out;
    };

    for line in contents.lines() {
        let fields: Vec<&str> = line.split(':').collect();
        if fields.len() < 7 {
            continue;
        }
        let (name, uid_s, home, shell) = (fields[0], fields[2], fields[5], fields[6]);
        let Ok(uid) = uid_s.parse::<u32>() else { continue };
        if !(HUMAN_UID_MIN..=HUMAN_UID_MAX).contains(&uid) {
            continue;
        }
        if NON_LOGIN_SHELLS.contains(&shell) {
            continue;
        }
        out.push(Account {
            name: name.to_string(),
            home: PathBuf::from(home),
        });
    }

    out
}

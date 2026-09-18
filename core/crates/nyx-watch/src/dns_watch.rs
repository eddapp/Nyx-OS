//! Category 4: DNS posture changes, sourced from `nyx-dns`'s own socket
//! rather than re-deriving resolver/leak state from `/proc` a second time.
//! `nyx-dns` already owns this truth (see `nyx-dns/src/checks.rs`) — this
//! is the one place nyx-watch is explicitly allowed to depend on
//! `nyx_core::protocol` types (`DnsCommand`/`DnsReport`) and the published
//! `DNS_SOCKET` constant, read-only, the same way `nyx-diagnostics`
//! already does in `core/crates/nyx-diagnostics/src/main.rs`. Every other
//! category in this daemon keeps its wire types local to this crate.

use nyx_core::{DnsCommand, DnsReport, NyxOutput, DNS_SOCKET};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;
use tokio::time::{timeout, Duration};

/// Generous but bounded — a hung/unresponsive nyx-dns must never stall
/// nyx-watch's own poll loop.
const CALL_TIMEOUT: Duration = Duration::from_secs(3);

/// Query nyx-dns for its current `DnsReport`. `None` covers every failure
/// mode uniformly (socket doesn't exist because nyx-dns isn't
/// installed/running, connection refused, timed out, malformed response)
/// — nyx-watch treats "can't reach nyx-dns right now" as "no DNS data this
/// poll", not as a crash, and the diff logic in `poller.rs` turns a
/// reachable -> unreachable transition into its own real event.
pub async fn query() -> Option<DnsReport> {
    let attempt = async {
        let mut stream = UnixStream::connect(DNS_SOCKET).await.ok()?;

        let mut line = serde_json::to_string(&DnsCommand::Status).ok()?;
        line.push('\n');
        stream.write_all(line.as_bytes()).await.ok()?;
        stream.flush().await.ok()?;

        let (read_half, _write_half) = stream.into_split();
        let mut reader = BufReader::new(read_half);
        let mut response = String::new();
        let n = reader.read_line(&mut response).await.ok()?;
        if n == 0 {
            return None; // nyx-dns closed the connection with no reply.
        }

        let parsed: NyxOutput<DnsReport> = serde_json::from_str(&response).ok()?;
        parsed.data
    };

    timeout(CALL_TIMEOUT, attempt).await.ok().flatten()
}

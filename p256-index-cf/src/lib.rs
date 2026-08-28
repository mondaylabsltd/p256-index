//! Cloudflare Workers shell for the p256 registry.
//!
//! One sentence of architecture: all strongly-consistent state lives in one
//! Durable Object ([`submitter::SubmitterDo`]), the response cache lives in
//! the platform Cache API, and everything CPU-bound runs here in the
//! stateless edge layer — `p256_registrar` makes every decision in all
//! three places.

mod chain;
mod config;
mod edge;
mod proto;
mod submitter;
mod telegram;

pub use submitter::SubmitterDo;

use worker::{Context, Env, Method, Request, Response, Result, ScheduleContext, ScheduledEvent, event};

use edge::{Edge, apply_cors, error_response};

#[event(fetch)]
async fn fetch(req: Request, env: Env, _ctx: Context) -> Result<Response> {
    if req.method() == Method::Options {
        let mut response = Response::empty()?.with_status(204);
        apply_cors(&mut response)?;
        return Ok(response);
    }
    let mut response = match Edge::new(env) {
        Ok(edge) => edge
            .route(req)
            .await
            .or_else(|_| error_response(500, "internal error"))?,
        Err(error) => error_response(500, &format!("service misconfigured: {error}"))?,
    };
    apply_cors(&mut response)?;
    Ok(response)
}

/// The docker shell's 60s maintenance tick, as a cron trigger: the pass
/// itself (unstick sweep, operator alerts, daily heartbeat) runs inside the
/// Durable Object, whose SQLite holds the ledger and the throttle state.
#[event(scheduled)]
async fn scheduled(_event: ScheduledEvent, env: Env, _ctx: ScheduleContext) {
    let outcome = async {
        let stub = env
            .durable_object("SUBMITTER")?
            .id_from_name("v1")?
            .get_stub()?;
        stub.fetch_with_str("https://do/maintain").await
    };
    if outcome.await.is_err() {
        worker::console_warn!("maintenance tick failed to reach the durable object");
    }
}

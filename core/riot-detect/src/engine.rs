//! The QuickJS host. One runtime on one dedicated thread (QuickJS is single-threaded); callers
//! talk to it through a channel and block on the reply. Deadlines are enforced inside the
//! interpreter through QuickJS's interrupt handler, so a slow scan is cut short instead of
//! holding up an Endpoint Security response.

use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use rquickjs::{CatchResultExt, CaughtError, Context, Ctx, Function, Object, Promise, Runtime, TypedArray, Value};
use serde::de::DeserializeOwned;

use crate::pdf;
use crate::types::{DetectOutcome, Detokenized, FileScan, Options, RedactOutcome};

/// The bundle built by `js/build.mjs`: engine + guard-core token memory + polyfills.
pub const DETECTION_JS: &str = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/../../js/dist/detection.js"));

/// Largest file the scanners accept (containers); the JS extractors apply the per-format limits.
pub const FILE_MAX_BYTES: u64 = 25 * 1024 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("detection engine stopped")]
    Stopped,
    #[error("deadline exceeded")]
    Timeout,
    #[error("javascript error: {0}")]
    Js(String),
    #[error("i/o error: {0}")]
    Io(#[from] std::io::Error),
    #[error("bad engine output: {0}")]
    Decode(#[from] serde_json::Error),
}

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Clone)]
pub struct EngineConfig {
    /// Hard cap on the JS heap. The extension's own ceilings (64 KiB paste, 1 MiB extracted text)
    /// keep real use far below it.
    pub memory_limit: usize,
    /// Run one detection at startup so the first real paste does not pay for loading the NLP model.
    pub warm_up: bool,
}

impl Default for EngineConfig {
    fn default() -> Self {
        Self { memory_limit: 256 * 1024 * 1024, warm_up: true }
    }
}

type Job = Box<dyn FnOnce(&Host) + Send>;

/// Handle to the engine thread. Cheap to clone; the thread stops when the last handle drops.
#[derive(Clone)]
pub struct Engine {
    jobs: mpsc::Sender<Job>,
}

/// Memory as QuickJS accounts it (the engine's share of the process footprint).
#[derive(Debug, Clone, Copy)]
pub struct HeapStats {
    pub malloc_size: i64,
    pub memory_used_size: i64,
}

impl Engine {
    pub fn start(config: EngineConfig) -> Result<Self> {
        let (jobs, inbox) = mpsc::channel::<Job>();
        let (ready_tx, ready_rx) = mpsc::channel::<Result<()>>();
        thread::Builder::new()
            .name("riot-detect-js".into())
            // compromise and the regex engine recurse; give QuickJS room under its own stack cap.
            .stack_size(16 * 1024 * 1024)
            .spawn(move || {
                let host = match Host::new(&config) {
                    Ok(host) => {
                        let _ = ready_tx.send(Ok(()));
                        host
                    }
                    Err(e) => {
                        let _ = ready_tx.send(Err(e));
                        return;
                    }
                };
                for job in inbox {
                    job(&host);
                }
            })?;
        ready_rx.recv().map_err(|_| Error::Stopped)??;
        Ok(Self { jobs })
    }

    fn run<T: Send + 'static>(&self, f: impl FnOnce(&Host) -> Result<T> + Send + 'static) -> Result<T> {
        let (tx, rx) = mpsc::sync_channel(1);
        self.jobs.send(Box::new(move |host| {
            let _ = tx.send(f(host));
        })).map_err(|_| Error::Stopped)?;
        rx.recv().map_err(|_| Error::Stopped)?
    }

    /// Detect and replace with numbered tokens remembered under `scope` (one per target app),
    /// so the same value keeps the same token and copied answers can be detokenized.
    pub fn redact(&self, text: &str, scope: &str, options: &Options) -> Result<RedactOutcome> {
        let (text, scope, options) = (text.to_owned(), scope.to_owned(), serde_json::to_string(options)?);
        self.run(move |h| h.call_json("redactInScope", None, |ctx| Ok((text, scope, options).into_args(ctx))))
    }

    pub fn detokenize(&self, text: &str, scope: &str) -> Result<Detokenized> {
        let (text, scope) = (text.to_owned(), scope.to_owned());
        self.run(move |h| h.call_json("detokenize", None, |ctx| Ok((text, scope).into_args(ctx))))
    }

    pub fn detect(&self, text: &str, options: &Options) -> Result<DetectOutcome> {
        let (text, options) = (text.to_owned(), serde_json::to_string(options)?);
        self.run(move |h| h.call_json("detect", None, |ctx| Ok((text, options).into_args(ctx))))
    }

    /// Scan a file's bytes. `deadline` bounds the whole call; on expiry the result is
    /// `Err(Timeout)` and the caller decides (the ES client allows, see the plan).
    pub fn scan_bytes(
        &self,
        name: &str,
        mime: &str,
        bytes: Vec<u8>,
        options: &Options,
        deadline: Option<Instant>,
    ) -> Result<FileScan> {
        if bytes.len() as u64 > FILE_MAX_BYTES {
            return Ok(FileScan::Oversized { bytes: bytes.len() as u64 });
        }
        let (name, mime, options) = (name.to_owned(), mime.to_owned(), serde_json::to_string(options)?);
        self.run(move |h| {
            h.call_json("scanFile", deadline, move |ctx| {
                let array = TypedArray::<u8>::new(ctx.clone(), bytes).map_err(js_error)?;
                Ok(vec![
                    name.into_js_value(ctx),
                    mime.into_js_value(ctx),
                    array.into_value(),
                    options.into_js_value(ctx),
                ])
            })
        })
    }

    /// Scan a file on disk. The MIME type is left empty: the engine resolves by extension, as
    /// for a drop with no type.
    pub fn scan_path(&self, path: &Path, options: &Options, deadline: Option<Instant>) -> Result<FileScan> {
        let name = path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
        if !self.is_supported(&name)? {
            return Ok(FileScan::Unsupported { kind: String::new() });
        }
        let size = std::fs::metadata(path)?.len();
        if size > FILE_MAX_BYTES {
            return Ok(FileScan::Oversized { bytes: size });
        }
        self.scan_bytes(&name, "", std::fs::read(path)?, options, deadline)
    }

    /// Whether the engine scans files with this name (by extension).
    pub fn is_supported(&self, name: &str) -> Result<bool> {
        let name = name.to_owned();
        self.run(move |h| {
            h.ctx.with(|ctx| {
                let f: Function = host_fn(&ctx, "supportedFileFormat")?;
                f.call((name, "")).catch(&ctx).map_err(caught)
            })
        })
    }

    pub fn heap_stats(&self) -> Result<HeapStats> {
        self.run(|h| {
            let usage = h.rt.memory_usage();
            Ok(HeapStats { malloc_size: usage.malloc_size, memory_used_size: usage.memory_used_size })
        })
    }

    /// Evaluate an extra script in the engine's context and await the promise (or value) the
    /// expression `call` returns, as a string. Used by the conformance tests to run the
    /// extension's corpus against this exact engine instance.
    #[doc(hidden)]
    pub fn eval_and_call(
        &self,
        script: String,
        fixtures_dir: std::path::PathBuf,
        call: String,
        timeout: Duration,
    ) -> Result<String> {
        self.run(move |h| {
            h.ctx.with(|ctx| -> Result<()> {
                let reader = Object::new(ctx.clone()).map_err(js_error)?;
                FIXTURES_DIR.with(|d| *d.borrow_mut() = fixtures_dir.clone());
                let read = Function::new(ctx.clone(), read_fixture).map_err(js_error)?;
                reader.set("readFixture", read).map_err(js_error)?;
                ctx.globals().set("__riotConformance", reader).map_err(js_error)?;
                ctx.eval::<(), _>(script).catch(&ctx).map_err(caught)
            })?;
            h.with_deadline(Some(Instant::now() + timeout), |ctx| {
                let value: Value = ctx.eval(call).catch(ctx).map_err(caught)?;
                settle::<String>(ctx, value)
            })
        })
    }
}

thread_local! {
    static FIXTURES_DIR: std::cell::RefCell<std::path::PathBuf> = std::cell::RefCell::default();
}

fn read_fixture<'js>(ctx: Ctx<'js>, path: String) -> rquickjs::Result<TypedArray<'js, u8>> {
    let full = FIXTURES_DIR.with(|d| d.borrow().join(&path));
    let bytes = std::fs::read(full).map_err(|e| rquickjs::Exception::throw_message(&ctx, &format!("{path}: {e}")))?;
    TypedArray::<u8>::new(ctx, bytes)
}

/// Lets the job closures build argument lists without naming lifetimes.
trait IntoArgs {
    fn into_args<'js>(self, ctx: &Ctx<'js>) -> Vec<Value<'js>>;
}
impl IntoArgs for (String, String) {
    fn into_args<'js>(self, ctx: &Ctx<'js>) -> Vec<Value<'js>> {
        vec![self.0.into_js_value(ctx), self.1.into_js_value(ctx)]
    }
}
impl IntoArgs for (String, String, String) {
    fn into_args<'js>(self, ctx: &Ctx<'js>) -> Vec<Value<'js>> {
        vec![self.0.into_js_value(ctx), self.1.into_js_value(ctx), self.2.into_js_value(ctx)]
    }
}
trait IntoJsValue {
    fn into_js_value<'js>(self, ctx: &Ctx<'js>) -> Value<'js>;
}
impl IntoJsValue for String {
    fn into_js_value<'js>(self, ctx: &Ctx<'js>) -> Value<'js> {
        rquickjs::String::from_str(ctx.clone(), &self).map(|s| s.into_value()).unwrap_or_else(|_| Value::new_undefined(ctx.clone()))
    }
}

struct Host {
    rt: Runtime,
    ctx: Context,
    /// Nanoseconds since `epoch` after which the interrupt handler aborts JS; 0 = no deadline.
    deadline: Arc<AtomicU64>,
    epoch: Instant,
}

impl Host {
    fn new(config: &EngineConfig) -> Result<Self> {
        let rt = Runtime::new().map_err(js_error)?;
        rt.set_memory_limit(config.memory_limit);
        rt.set_max_stack_size(8 * 1024 * 1024);
        let epoch = Instant::now();
        let deadline = Arc::new(AtomicU64::new(0));
        {
            let deadline = deadline.clone();
            rt.set_interrupt_handler(Some(Box::new(move || {
                let d = deadline.load(Ordering::Relaxed);
                d != 0 && epoch.elapsed().as_nanos() as u64 > d
            })));
        }
        let ctx = Context::full(&rt).map_err(js_error)?;
        ctx.with(|ctx| -> Result<()> {
            install_natives(&ctx, epoch).map_err(js_error)?;
            ctx.eval::<(), _>(DETECTION_JS).catch(&ctx).map_err(caught)
        })?;
        let host = Self { rt, ctx, deadline, epoch };
        if config.warm_up {
            let started = Instant::now();
            let _: DetectOutcome = host.call_json("detect", None, |ctx| {
                Ok(("Bonjour Jean Dupont, IBAN FR7630006000011234567890189".to_owned(), "{}".to_owned()).into_args(ctx))
            })?;
            tracing::debug!(elapsed_ms = started.elapsed().as_millis() as u64, "detection engine warmed up");
        }
        Ok(host)
    }

    fn with_deadline<T>(&self, deadline: Option<Instant>, f: impl FnOnce(&Ctx<'_>) -> Result<T>) -> Result<T> {
        let nanos = deadline.map_or(0, |d| d.saturating_duration_since(self.epoch).as_nanos().max(1) as u64);
        self.deadline.store(nanos, Ordering::Relaxed);
        let result = self.ctx.with(|ctx| f(&ctx));
        self.deadline.store(0, Ordering::Relaxed);
        match result {
            Err(Error::Js(_)) if deadline.is_some_and(|d| Instant::now() >= d) => Err(Error::Timeout),
            other => other,
        }
    }

    /// Call `Sonar.host[name](...args)`, await it, and decode the JSON string it resolves to.
    fn call_json<T: DeserializeOwned>(
        &self,
        name: &str,
        deadline: Option<Instant>,
        args: impl for<'js> FnOnce(&Ctx<'js>) -> Result<Vec<Value<'js>>>,
    ) -> Result<T> {
        let json = self.with_deadline(deadline, |ctx| {
            let f: Function = host_fn(ctx, name)?;
            let mut call_args = rquickjs::function::Args::new(ctx.clone(), 4);
            for a in args(ctx)? {
                call_args.push_arg(a).map_err(js_error)?;
            }
            let value: Value = f.call_arg(call_args).catch(ctx).map_err(caught)?;
            settle::<String>(ctx, value)
        })?;
        Ok(serde_json::from_str(&json)?)
    }
}

fn host_fn<'js>(ctx: &Ctx<'js>, name: &str) -> Result<Function<'js>> {
    let sonar: Object = ctx.globals().get("Sonar").map_err(js_error)?;
    let host: Object = sonar.get("host").map_err(js_error)?;
    host.get(name).map_err(js_error)
}

/// A value, or the result of the promise it is, once the job queue has run it to completion.
fn settle<'js, T: rquickjs::FromJs<'js>>(ctx: &Ctx<'js>, value: Value<'js>) -> Result<T> {
    match value.as_promise() {
        Some(promise) => {
            let promise: &Promise = promise;
            promise.finish::<T>().catch(ctx).map_err(caught)
        }
        None => T::from_js(ctx, value).map_err(js_error),
    }
}

fn install_natives(ctx: &Ctx<'_>, epoch: Instant) -> rquickjs::Result<()> {
    let riot = Object::new(ctx.clone())?;

    riot.set(
        "utf8Decode",
        Function::new(ctx.clone(), |ctx: Ctx<'_>, bytes: TypedArray<'_, u8>, fatal: bool| -> rquickjs::Result<String> {
            // SAFETY: the bytes are copied out before any JS can run and detach the buffer.
            let data = unsafe { bytes.as_bytes() }.unwrap_or(&[]);
            let data = data.strip_prefix(&[0xef, 0xbb, 0xbf]).unwrap_or(data); // TextDecoder drops a BOM
            if fatal {
                std::str::from_utf8(data)
                    .map(str::to_owned)
                    .map_err(|_| rquickjs::Exception::throw_type(&ctx, "The encoded data was not valid for encoding utf-8"))
            } else {
                Ok(String::from_utf8_lossy(data).into_owned())
            }
        })?,
    )?;

    riot.set("nowMs", Function::new(ctx.clone(), move || epoch.elapsed().as_secs_f64() * 1000.0)?)?;

    riot.set(
        "log",
        Function::new(ctx.clone(), |level: String, message: String| match level.as_str() {
            "error" => tracing::error!(target: "riot_detect::js", "{message}"),
            _ => tracing::warn!(target: "riot_detect::js", "{message}"),
        })?,
    )?;

    riot.set(
        "pdfText",
        Function::new(ctx.clone(), |ctx: Ctx<'_>, bytes: TypedArray<'_, u8>| -> rquickjs::Result<String> {
            // SAFETY: as above; copied before extraction.
            let data = unsafe { bytes.as_bytes() }.unwrap_or(&[]).to_vec();
            match pdf::segments(&data) {
                Ok(segments) => Ok(serde_json::to_string(&segments).unwrap_or_else(|_| "[]".into())),
                Err(message) => Err(rquickjs::Exception::throw_message(&ctx, &message)),
            }
        })?,
    )?;

    ctx.globals().set("__riot", riot)
}

fn js_error(e: rquickjs::Error) -> Error {
    Error::Js(e.to_string())
}

fn caught(e: CaughtError<'_>) -> Error {
    match e {
        CaughtError::Exception(ex) => {
            let message = ex.message().unwrap_or_default();
            match ex.stack() {
                Some(stack) if !stack.is_empty() => Error::Js(format!("{message}\n{stack}")),
                _ => Error::Js(message),
            }
        }
        CaughtError::Value(v) => Error::Js(format!("{v:?}")),
        CaughtError::Error(e) => Error::Js(e.to_string()),
    }
}

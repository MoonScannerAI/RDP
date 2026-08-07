//! WASAPI shared-mode playback for the client's system-audio path.
//!
//! Pipeline: interleaved 16-bit PCM from [`crate::audio_decoder`] → an
//! `IAudioClient` shared-mode render stream on the default console endpoint.
//!
//! Nothing in this module is wired up yet: there is no thread and no channel.
//! It is the output half of the audio path, landed on its own.
//!
//! # We do not ship a resampler
//!
//! The stream is opened asking for **the host's** format — whatever
//! [`AudioFormat`] the current packet says — with
//! `AUDCLNT_STREAMFLAGS_AUTOCONVERTPCM | AUDCLNT_STREAMFLAGS_SRC_DEFAULT_QUALITY`.
//! The Windows audio engine then converts into the endpoint's own mix format
//! for free: a 44.1 kHz host played into a 48 kHz endpoint is resampled by the
//! same code path that already resamples every other application on the box.
//!
//! That is the whole reason the wire format can afford a per-packet `format`
//! byte (see [`directdesk_shared::audio`]). A format change mid-session costs a
//! new decoder and a new render stream, not a resampler we would have to write,
//! tune and defend.
//!
//! # Latency is not modelled, it is read
//!
//! `IAudioClient::GetCurrentPadding` returns the number of frames already
//! queued in the endpoint buffer. That number **is** the fill level and
//! therefore **is** the output latency — there is nothing to estimate. It is
//! exposed as [`PcmSink::padding_frames`] because the drift controller consumes
//! exactly that number.
//!
//! Consequently there is **no PCM ring buffer in this module**. The endpoint
//! buffer is the ring buffer; a second one in front of it would add latency that
//! `GetCurrentPadding` cannot see, which is precisely the number the drift
//! controller is steering on. [`PcmSink::write`] therefore writes what fits and
//! reports what it took, leaving the remainder with the caller.
//!
//! # Timer-driven, not event-driven
//!
//! No `SetEventHandle`, no waitable handle. With a
//! [`RENDER_BUFFER_MS`]-deep buffer, a [`POLL_INTERVAL_MS`] poll refills it two
//! orders of magnitude more often than it can drain, so the event handle would
//! buy nothing but a handle to leak and a wait to get wrong.
//!
//! # COM
//!
//! [`ensure_com_initialized`] is per-thread, MTA, and **deliberately never
//! calls `CoUninitialize`** — see its docs for why that is the safe choice here
//! rather than the lazy one.
//!
//! [`AudioFormat`]: directdesk_shared::audio::AudioFormat

use directdesk_shared::audio::AudioFormat;
use directdesk_shared::error::{Error, Result};

// ---------------------------------------------------------------------------
// Tunables
// ---------------------------------------------------------------------------

/// Requested endpoint buffer depth, milliseconds.
///
/// 400 ms is deliberately far deeper than the latency we intend to run at. The
/// buffer is a *ceiling*, not a target: the drift controller keeps the actual
/// fill (and therefore the actual latency) far below it, and the headroom is
/// what absorbs a scheduling stall on the decode thread without a dropout. A
/// tight buffer would make the ceiling the thing that limits us instead of the
/// controller, and there is no cost to the depth we do not use.
pub const RENDER_BUFFER_MS: u32 = 400;

/// [`RENDER_BUFFER_MS`] in the 100-nanosecond units `IAudioClient::Initialize`
/// takes.
pub const RENDER_BUFFER_HNS: i64 = RENDER_BUFFER_MS as i64 * 10_000;

/// Suggested poll period for a timer-driven render loop.
///
/// Anything in 5..=10 ms works against a [`RENDER_BUFFER_MS`] buffer; 5 ms is
/// the low end, chosen because the cost of a wakeup that finds nothing to do is
/// one `GetCurrentPadding` call.
pub const POLL_INTERVAL_MS: u64 = 5;

// ---------------------------------------------------------------------------
// Pure format / admission arithmetic (platform independent, unit tested)
// ---------------------------------------------------------------------------

/// The `WAVEFORMATEX` fields for one wire format, as plain integers.
///
/// Split out from the Win32 struct so the arithmetic — which is where a wrong
/// `nBlockAlign` would make the engine read frames at the wrong stride and play
/// noise — is testable on any platform.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WaveFormatFields {
    pub channels: u16,
    pub sample_rate: u32,
    pub bits_per_sample: u16,
    /// Bytes in one frame: all channels of one sample instant.
    pub block_align: u16,
    pub avg_bytes_per_sec: u32,
}

/// Bits per PCM sample everywhere on this path. The AAC decoder emits 16-bit
/// integer PCM and nothing else, so the render side asks for the same rather
/// than converting.
pub const PCM_BITS_PER_SAMPLE: u16 = 16;

/// Derive the `WAVEFORMATEX` fields for a wire format.
pub fn wave_format_fields(format: AudioFormat) -> WaveFormatFields {
    let channels = u16::from(format.channels());
    let sample_rate = format.sample_rate();
    let block_align = channels * (PCM_BITS_PER_SAMPLE / 8);
    WaveFormatFields {
        channels,
        sample_rate,
        bits_per_sample: PCM_BITS_PER_SAMPLE,
        block_align,
        avg_bytes_per_sec: sample_rate * u32::from(block_align),
    }
}

/// Frames of audio in a duration. Used to state the buffer depth in frames for
/// logging and for [`RecordingSink`], which has no endpoint to ask.
pub fn ms_to_frames(ms: u32, sample_rate: u32) -> u32 {
    ((u64::from(ms) * u64::from(sample_rate)) / 1000) as u32
}

/// Milliseconds of audio in a frame count — i.e. the output latency, given
/// [`PcmSink::padding_frames`].
pub fn frames_to_ms(frames: u32, sample_rate: u32) -> u32 {
    if sample_rate == 0 {
        return 0;
    }
    ((u64::from(frames) * 1000) / u64::from(sample_rate)) as u32
}

/// How many frames a write may place, given the buffer depth, what is already
/// queued, and what is on offer.
///
/// Saturating rather than wrapping: `GetCurrentPadding` can legitimately report
/// a padding equal to the buffer size (the buffer is full), and a build that
/// reported one *more* than the buffer size would, with plain subtraction,
/// produce a colossal frame count and a heap overflow inside `GetBuffer`.
pub fn writable_frames(buffer_frames: u32, padding_frames: u32, offered_frames: u32) -> u32 {
    buffer_frames
        .saturating_sub(padding_frames)
        .min(offered_frames)
}

/// Wrap a render-side failure.
///
/// [`directdesk_shared::error::Error`] has no audio variant yet; adding one is a
/// shared-crate change and this commit does not touch that crate. The prefix
/// keeps these distinguishable in a log until it does.
fn render_err(msg: impl std::fmt::Display) -> Error {
    Error::Other(format!("audio render: {msg}"))
}

// ---------------------------------------------------------------------------
// The sink seam
// ---------------------------------------------------------------------------

/// Somewhere interleaved 16-bit PCM can be played.
///
/// The seam exists so the playback loop, and the drift controller that steers
/// it, can be exercised headless. [`RecordingSink`] is the implementation that
/// records instead of playing.
pub trait PcmSink: Send {
    /// The format this sink was opened for. PCM handed to [`PcmSink::write`]
    /// must be interleaved at this rate and channel count.
    fn format(&self) -> AudioFormat;

    /// Total endpoint buffer depth in frames — the ceiling
    /// [`PcmSink::padding_frames`] can reach.
    fn buffer_frames(&self) -> u32;

    /// Frames still queued for playback: the fill level, and therefore the
    /// output latency. This is the number the drift controller reads.
    fn padding_frames(&self) -> Result<u32>;

    /// Write as much of `pcm` as fits, returning the number of **frames**
    /// taken. The caller keeps the remainder — this deliberately does not
    /// buffer, see the module docs.
    ///
    /// `pcm` must be a whole number of frames (a multiple of the channel
    /// count); anything else is rejected rather than truncated, because a
    /// partial frame taken now would swap the channels of everything after it.
    fn write(&mut self, pcm: &[i16]) -> Result<u32>;

    /// Begin playback. Idempotent.
    fn start(&mut self) -> Result<()>;

    /// Stop playback, leaving whatever is queued in place.
    fn stop(&mut self) -> Result<()>;

    /// Times the buffer was found empty at write time on a stream that had
    /// already been fed — i.e. audible gaps.
    fn underruns(&self) -> u64;

    /// Human-readable description for logs and the self-test.
    fn describe(&self) -> String;

    /// Current output latency in milliseconds. Provided, not implemented:
    /// there is exactly one way to compute it from
    /// [`PcmSink::padding_frames`], and a second one would be a second answer.
    fn latency_ms(&self) -> Result<u32> {
        Ok(frames_to_ms(
            self.padding_frames()?,
            self.format().sample_rate(),
        ))
    }
}

// ---------------------------------------------------------------------------
// WASAPI implementation
// ---------------------------------------------------------------------------

#[cfg(windows)]
mod wasapi {
    use super::*;

    use windows::core::HRESULT;
    use windows::Win32::Media::Audio::{
        eConsole, eRender, IAudioClient, IAudioRenderClient, IMMDeviceEnumerator,
        MMDeviceEnumerator, AUDCLNT_SHAREMODE_SHARED, AUDCLNT_STREAMFLAGS_AUTOCONVERTPCM,
        AUDCLNT_STREAMFLAGS_SRC_DEFAULT_QUALITY, WAVEFORMATEX, WAVE_FORMAT_PCM,
    };
    use windows::Win32::System::Com::{
        CoCreateInstance, CoInitializeEx, CoTaskMemFree, CLSCTX_ALL, CLSCTX_INPROC_SERVER,
        COINIT_MULTITHREADED,
    };

    /// Another apartment model was already chosen on this thread — harmless,
    /// COM stays usable.
    const RPC_E_CHANGED_MODE: HRESULT = HRESULT(0x8001_0106_u32 as i32);

    thread_local! {
        static COM_READY: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    }

    /// Idempotent per-thread COM(MTA) startup for the render path.
    ///
    /// # Why there is no guard type and no `CoUninitialize`
    ///
    /// The obvious shape — an RAII guard that calls `CoUninitialize` on drop —
    /// is a use-after-free waiting to happen here. `CoUninitialize` tears the
    /// apartment down; any `IAudioClient` / `IAudioRenderClient` still alive at
    /// that moment is a pointer into freed proxy state, and the crash lands
    /// somewhere else entirely (often in the audio engine's own thread) with
    /// nothing pointing back at the guard that caused it. Getting it right
    /// means guaranteeing that *every* WASAPI interface is dropped before the
    /// guard, on every path including panics — a property that holds until
    /// someone adds a field.
    ///
    /// So we do not create the hazard. COM is initialized once per thread and
    /// never uninitialized: with no teardown there is no ordering to get wrong,
    /// and the process is exiting anyway. This is the same call the H.264
    /// decoder makes for the same reason (see [`crate::decoder`]) — kept
    /// separate only so the render path does not drag `MFStartup` in behind it.
    ///
    /// `Drop for WasapiRenderer` still releases its interfaces in a deliberate
    /// order; that is about the endpoint, not about COM.
    pub fn ensure_com_initialized() -> Result<()> {
        COM_READY.with(|ready| {
            if ready.get() {
                return Ok(());
            }
            // SAFETY: standard COM init; documented as safe from any thread.
            unsafe {
                let hr = CoInitializeEx(None, COINIT_MULTITHREADED);
                if hr.is_err() && hr != RPC_E_CHANGED_MODE {
                    return Err(render_err(format!("CoInitializeEx failed: {hr:?}")));
                }
            }
            ready.set(true);
            tracing::debug!("COM (MTA) initialized on this thread for WASAPI render");
            Ok(())
        })
    }

    /// A shared-mode WASAPI render stream on the default console endpoint.
    pub struct WasapiRenderer {
        // Declaration order is drop order. The render client is a service
        // obtained from the audio client, so it is released first; COM
        // refcounting makes this correct either way, but the order that matches
        // the dependency is the one that stays correct if either type ever
        // grows a destructor with an opinion.
        render: IAudioRenderClient,
        client: IAudioClient,
        format: AudioFormat,
        buffer_frames: u32,
        /// Bytes per frame: channels x 2. Cached because it is on the hot path.
        frame_bytes: usize,
        /// The endpoint's own mix format, for logging only. The engine converts
        /// into it; we never speak it.
        endpoint_mix: String,
        started: bool,
        underruns: u64,
        frames_written: u64,
    }

    // SAFETY: every interface here is created and used through this struct
    // only, and `ensure_com_initialized` runs before any of them exist, so
    // whichever thread owns the renderer has COM initialized as MTA. MTA
    // objects may legally be called from any MTA thread, so transferring
    // ownership (which is all `Send` permits) is sound. Same argument as
    // `crate::decoder::MfH264Decoder`.
    unsafe impl Send for WasapiRenderer {}

    impl WasapiRenderer {
        /// Open the default render endpoint asking for `format`.
        ///
        /// The endpoint is *not* asked whether it supports the format:
        /// `AUDCLNT_STREAMFLAGS_AUTOCONVERTPCM` makes the engine convert, so an
        /// `IsFormatSupported` probe would only tell us about the endpoint's
        /// native capability, which is not the question.
        pub fn new(format: AudioFormat) -> Result<Self> {
            ensure_com_initialized()?;

            let fields = wave_format_fields(format);
            let wfx = WAVEFORMATEX {
                wFormatTag: WAVE_FORMAT_PCM as u16,
                nChannels: fields.channels,
                nSamplesPerSec: fields.sample_rate,
                nAvgBytesPerSec: fields.avg_bytes_per_sec,
                nBlockAlign: fields.block_align,
                wBitsPerSample: fields.bits_per_sample,
                // Plain WAVEFORMATEX, no extension bytes follow. Must be 0 for
                // WAVE_FORMAT_PCM; a nonzero value here makes the engine read
                // past the struct.
                cbSize: 0,
            };

            // SAFETY: standard WASAPI activation sequence; every call is on an
            // object the previous one returned, and failures are HRESULTs.
            unsafe {
                let enumerator: IMMDeviceEnumerator =
                    CoCreateInstance(&MMDeviceEnumerator, None, CLSCTX_INPROC_SERVER).map_err(
                        |e| render_err(format!("CoCreateInstance(MMDeviceEnumerator): {e}")),
                    )?;
                let device = enumerator
                    .GetDefaultAudioEndpoint(eRender, eConsole)
                    .map_err(|e| render_err(format!("GetDefaultAudioEndpoint: {e}")))?;
                let client: IAudioClient = device
                    .Activate(CLSCTX_ALL, None)
                    .map_err(|e| render_err(format!("IMMDevice::Activate(IAudioClient): {e}")))?;

                // Diagnostic only, and freed immediately: GetMixFormat hands
                // back a CoTaskMem allocation that is ours to release.
                let endpoint_mix = match client.GetMixFormat() {
                    Ok(mix) if !mix.is_null() => {
                        // Copied out field by field: WAVEFORMATEX is
                        // `#[repr(C, packed(1))]`, so `format!` — which takes
                        // its arguments by reference — cannot be pointed at the
                        // fields directly.
                        let rate = (*mix).nSamplesPerSec;
                        let channels = (*mix).nChannels;
                        let bits = (*mix).wBitsPerSample;
                        CoTaskMemFree(Some(mix as *const _));
                        format!("{rate} Hz {channels} ch {bits}-bit")
                    }
                    _ => "unknown".to_string(),
                };

                client
                    .Initialize(
                        AUDCLNT_SHAREMODE_SHARED,
                        // AUTOCONVERTPCM is what lets us ask for the host's
                        // format on an endpoint that runs at another one; MSDN
                        // requires SRC_DEFAULT_QUALITY alongside it.
                        AUDCLNT_STREAMFLAGS_AUTOCONVERTPCM
                            | AUDCLNT_STREAMFLAGS_SRC_DEFAULT_QUALITY,
                        RENDER_BUFFER_HNS,
                        // Periodicity must be 0 in shared mode.
                        0,
                        &wfx,
                        None,
                    )
                    .map_err(|e| {
                        render_err(format!(
                            "IAudioClient::Initialize({} Hz, {} ch, {RENDER_BUFFER_MS} ms): {e}",
                            fields.sample_rate, fields.channels
                        ))
                    })?;

                // In frames of OUR format, not the endpoint's — the conversion
                // happens downstream of this buffer, so padding and depth are
                // both denominated in what we write.
                let buffer_frames = client
                    .GetBufferSize()
                    .map_err(|e| render_err(format!("GetBufferSize: {e}")))?;
                let render: IAudioRenderClient = client
                    .GetService()
                    .map_err(|e| render_err(format!("GetService(IAudioRenderClient): {e}")))?;

                tracing::info!(
                    "WASAPI render open: {} Hz {} ch, buffer {} frames ({} ms), endpoint mix {}",
                    fields.sample_rate,
                    fields.channels,
                    buffer_frames,
                    frames_to_ms(buffer_frames, fields.sample_rate),
                    endpoint_mix
                );

                Ok(Self {
                    render,
                    client,
                    format,
                    buffer_frames,
                    frame_bytes: usize::from(fields.block_align),
                    endpoint_mix,
                    started: false,
                    underruns: 0,
                    frames_written: 0,
                })
            }
        }

        pub fn frames_written(&self) -> u64 {
            self.frames_written
        }
    }

    impl PcmSink for WasapiRenderer {
        fn format(&self) -> AudioFormat {
            self.format
        }

        fn buffer_frames(&self) -> u32 {
            self.buffer_frames
        }

        fn padding_frames(&self) -> Result<u32> {
            // SAFETY: our own initialized client.
            unsafe { self.client.GetCurrentPadding() }
                .map_err(|e| render_err(format!("GetCurrentPadding: {e}")))
        }

        fn write(&mut self, pcm: &[i16]) -> Result<u32> {
            let channels = usize::from(self.format.channels());
            if !pcm.len().is_multiple_of(channels) {
                return Err(render_err(format!(
                    "{} samples is not a whole number of {channels}-channel frames",
                    pcm.len()
                )));
            }
            let offered = (pcm.len() / channels) as u32;
            if offered == 0 {
                return Ok(0);
            }

            let padding = self.padding_frames()?;
            // An empty buffer on a stream we have already fed means the engine
            // played everything and then had nothing: an audible gap. Before
            // the first write it is just an empty buffer.
            if padding == 0 && self.started && self.frames_written > 0 {
                self.underruns += 1;
                tracing::debug!(
                    "audio underrun #{}: endpoint buffer ran dry",
                    self.underruns
                );
            }

            let frames = writable_frames(self.buffer_frames, padding, offered);
            if frames == 0 {
                return Ok(0);
            }
            let bytes = frames as usize * self.frame_bytes;

            // SAFETY: `GetBuffer` hands back a writable region of exactly
            // `frames` frames, which `bytes` is computed from; it stays valid
            // until the matching `ReleaseBuffer`, which runs on every path.
            unsafe {
                let dst = self
                    .render
                    .GetBuffer(frames)
                    .map_err(|e| render_err(format!("GetBuffer({frames}): {e}")))?;
                std::ptr::copy_nonoverlapping(pcm.as_ptr().cast::<u8>(), dst, bytes);
                if let Err(e) = self.render.ReleaseBuffer(frames, 0) {
                    // The region is STILL ACQUIRED here. `IAudioRenderClient`
                    // permits exactly one outstanding acquisition, so returning
                    // now without giving it back makes every later `GetBuffer`
                    // fail `AUDCLNT_E_OUT_OF_ORDER` for the life of this object
                    // — a wedge that no amount of retrying upstream can clear,
                    // because nothing upstream is holding the buffer.
                    //
                    // Releasing zero frames is the documented way to say "never
                    // mind" about an acquisition, so that is the second attempt.
                    // If it fails too the endpoint itself is gone, which the
                    // caller learns from the error we are about to return; it is
                    // not new information, so it is logged at debug.
                    if let Err(second) = self.render.ReleaseBuffer(0, 0) {
                        tracing::debug!(
                            "relinquishing the render buffer after a failed \
                             ReleaseBuffer also failed: {second}"
                        );
                    }
                    return Err(render_err(format!("ReleaseBuffer({frames}): {e}")));
                }
            }

            self.frames_written += u64::from(frames);
            Ok(frames)
        }

        fn start(&mut self) -> Result<()> {
            if self.started {
                return Ok(());
            }
            // SAFETY: our own initialized client.
            unsafe { self.client.Start() }.map_err(|e| render_err(format!("Start: {e}")))?;
            self.started = true;
            Ok(())
        }

        fn stop(&mut self) -> Result<()> {
            if !self.started {
                return Ok(());
            }
            // SAFETY: our own started client.
            unsafe { self.client.Stop() }.map_err(|e| render_err(format!("Stop: {e}")))?;
            self.started = false;
            Ok(())
        }

        fn underruns(&self) -> u64 {
            self.underruns
        }

        fn describe(&self) -> String {
            format!(
                "WASAPI shared render, {} Hz {} ch → endpoint {} (buffer {} frames, {} underruns)",
                self.format.sample_rate(),
                self.format.channels(),
                self.endpoint_mix,
                self.buffer_frames,
                self.underruns
            )
        }
    }

    impl Drop for WasapiRenderer {
        fn drop(&mut self) {
            if self.started {
                // SAFETY: our own client; failure at teardown is not actionable.
                if let Err(e) = unsafe { self.client.Stop() } {
                    tracing::debug!("WASAPI Stop at drop failed: {e}");
                }
                self.started = false;
            }
            // The interfaces are released by the field drops that follow, in
            // declaration order (render, then client). COM is NOT uninitialized
            // here — see `ensure_com_initialized`.
        }
    }

    /// Open the default endpoint for each wire format and report what WASAPI
    /// gave back. Touches real hardware, so it is a self-test, not a unit test.
    pub fn self_test() -> String {
        let mut report = String::new();
        for format in AudioFormat::ALL {
            match WasapiRenderer::new(format) {
                Ok(sink) => {
                    report.push_str(&format!("{format:?}: {}\n", sink.describe()));
                    match sink.padding_frames() {
                        Ok(p) => report.push_str(&format!(
                            "  padding {p} frames ({} ms) before start\n",
                            frames_to_ms(p, format.sample_rate())
                        )),
                        Err(e) => report.push_str(&format!("  GetCurrentPadding failed: {e}\n")),
                    }
                }
                Err(e) => report.push_str(&format!("{format:?}: FAILED: {e}\n")),
            }
        }
        report
    }
}

#[cfg(windows)]
pub use wasapi::{ensure_com_initialized, self_test, WasapiRenderer};

/// Build the platform PCM sink for one wire format.
///
/// A sink is bound to its format for the same reason the decoder is: the
/// stream's `WAVEFORMATEX` is fixed at `Initialize` time. A packet carrying a
/// different `format` code needs a new sink.
pub fn new_pcm_sink(format: AudioFormat) -> Result<Box<dyn PcmSink>> {
    #[cfg(windows)]
    {
        Ok(Box::new(WasapiRenderer::new(format)?))
    }
    #[cfg(not(windows))]
    {
        let _ = format;
        Err(render_err("no audio endpoint on this platform"))
    }
}

// ---------------------------------------------------------------------------
// Test double
// ---------------------------------------------------------------------------

/// [`PcmSink`] that records PCM instead of touching WASAPI.
///
/// It is a faithful double, not a stub: it enforces the same whole-frame rule,
/// admits frames through the same [`writable_frames`] function the real sink
/// uses, and counts underruns by the same test. What it adds is
/// [`RecordingSink::drain`] — a stand-in for the audio engine consuming frames
/// — which is what lets a test drive the fill level up and down and watch the
/// drift controller respond, deterministically and in no time at all.
///
/// `pub` rather than `#[cfg(test)]` for the same reason
/// [`directdesk_shared::traits::NullDecoder`] is: tests in other crates need it.
pub struct RecordingSink {
    format: AudioFormat,
    buffer_frames: u32,
    padding: u32,
    written: Vec<i16>,
    started: bool,
    underruns: u64,
    frames_written: u64,
}

impl RecordingSink {
    /// A sink with the same buffer depth the real one asks for.
    pub fn new(format: AudioFormat) -> Self {
        Self::with_buffer_frames(format, ms_to_frames(RENDER_BUFFER_MS, format.sample_rate()))
    }

    /// A sink with a chosen depth, for tests that want the buffer to fill in a
    /// handful of writes.
    pub fn with_buffer_frames(format: AudioFormat, buffer_frames: u32) -> Self {
        Self {
            format,
            buffer_frames,
            padding: 0,
            written: Vec::new(),
            started: false,
            underruns: 0,
            frames_written: 0,
        }
    }

    /// Simulate the audio engine playing `frames` out of the buffer.
    /// Saturates at empty, as the endpoint does.
    pub fn drain(&mut self, frames: u32) {
        self.padding = self.padding.saturating_sub(frames);
    }

    /// Everything ever written, interleaved, in order.
    pub fn written(&self) -> &[i16] {
        &self.written
    }

    /// Take the recording, leaving the sink otherwise untouched.
    pub fn take_written(&mut self) -> Vec<i16> {
        std::mem::take(&mut self.written)
    }

    pub fn is_started(&self) -> bool {
        self.started
    }

    pub fn frames_written(&self) -> u64 {
        self.frames_written
    }
}

impl PcmSink for RecordingSink {
    fn format(&self) -> AudioFormat {
        self.format
    }

    fn buffer_frames(&self) -> u32 {
        self.buffer_frames
    }

    fn padding_frames(&self) -> Result<u32> {
        Ok(self.padding)
    }

    fn write(&mut self, pcm: &[i16]) -> Result<u32> {
        let channels = usize::from(self.format.channels());
        if !pcm.len().is_multiple_of(channels) {
            return Err(render_err(format!(
                "{} samples is not a whole number of {channels}-channel frames",
                pcm.len()
            )));
        }
        let offered = (pcm.len() / channels) as u32;
        if offered == 0 {
            return Ok(0);
        }
        if self.padding == 0 && self.started && self.frames_written > 0 {
            self.underruns += 1;
        }
        let frames = writable_frames(self.buffer_frames, self.padding, offered);
        if frames == 0 {
            return Ok(0);
        }
        self.written
            .extend_from_slice(&pcm[..frames as usize * channels]);
        self.padding += frames;
        self.frames_written += u64::from(frames);
        Ok(frames)
    }

    fn start(&mut self) -> Result<()> {
        self.started = true;
        Ok(())
    }

    fn stop(&mut self) -> Result<()> {
        self.started = false;
        Ok(())
    }

    fn underruns(&self) -> u64 {
        self.underruns
    }

    fn describe(&self) -> String {
        format!(
            "recording sink (test double), {} Hz {} ch, buffer {} frames",
            self.format.sample_rate(),
            self.format.channels(),
            self.buffer_frames
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wave_format_fields_are_derived_not_guessed() {
        let stereo48 = wave_format_fields(AudioFormat::Stereo48k);
        assert_eq!(
            stereo48,
            WaveFormatFields {
                channels: 2,
                sample_rate: 48_000,
                bits_per_sample: 16,
                block_align: 4,
                avg_bytes_per_sec: 192_000,
            }
        );
        let mono44 = wave_format_fields(AudioFormat::Mono44k1);
        assert_eq!(
            mono44,
            WaveFormatFields {
                channels: 1,
                sample_rate: 44_100,
                bits_per_sample: 16,
                block_align: 2,
                avg_bytes_per_sec: 88_200,
            }
        );
        // The two relationships WASAPI actually enforces, for every format.
        for format in AudioFormat::ALL {
            let f = wave_format_fields(format);
            assert_eq!(
                f.block_align,
                f.channels * (f.bits_per_sample / 8),
                "{format:?}: nBlockAlign"
            );
            assert_eq!(
                f.avg_bytes_per_sec,
                f.sample_rate * u32::from(f.block_align),
                "{format:?}: nAvgBytesPerSec"
            );
        }
    }

    #[test]
    fn frame_and_millisecond_conversions_agree() {
        assert_eq!(ms_to_frames(RENDER_BUFFER_MS, 48_000), 19_200);
        assert_eq!(ms_to_frames(RENDER_BUFFER_MS, 44_100), 17_640);
        assert_eq!(frames_to_ms(19_200, 48_000), RENDER_BUFFER_MS);
        assert_eq!(frames_to_ms(17_640, 44_100), RENDER_BUFFER_MS);
        // One AAC frame at 48 kHz is 21 ms (21.33, truncated).
        assert_eq!(frames_to_ms(1024, 48_000), 21);
        assert_eq!(frames_to_ms(0, 48_000), 0);
        // A zero rate cannot happen through `AudioFormat`, but the function is
        // public and must not divide by it.
        assert_eq!(frames_to_ms(1024, 0), 0);
        // No overflow at a full buffer's worth of frames.
        assert_eq!(
            frames_to_ms(u32::MAX, 48_000),
            (u32::MAX as u64 / 48) as u32
        );
    }

    #[test]
    fn buffer_duration_constants_are_consistent() {
        // 100-nanosecond units: the one conversion in this file that a reader
        // is most likely to get wrong by a factor of ten.
        assert_eq!(RENDER_BUFFER_HNS, 4_000_000);
        assert_eq!(RENDER_BUFFER_HNS / 10_000, i64::from(RENDER_BUFFER_MS));
        assert!(
            (5..=10).contains(&POLL_INTERVAL_MS),
            "the poll period must stay in the range the buffer depth was chosen for"
        );
        assert!(
            u64::from(RENDER_BUFFER_MS) > POLL_INTERVAL_MS * 10,
            "a poll must refill the buffer far faster than it can drain"
        );
    }

    #[test]
    fn writable_frames_never_exceeds_the_space_or_the_offer() {
        assert_eq!(writable_frames(1000, 0, 480), 480, "plenty of room");
        assert_eq!(writable_frames(1000, 800, 480), 200, "space limits");
        assert_eq!(writable_frames(1000, 1000, 480), 0, "buffer full");
        // The saturating case: a padding above the buffer size must yield zero,
        // not a wrapped four-billion-frame write straight into `GetBuffer`.
        assert_eq!(writable_frames(1000, 1001, 480), 0);
        assert_eq!(writable_frames(0, 0, 480), 0);
        assert_eq!(writable_frames(1000, 0, 0), 0);
    }

    fn ramp(frames: usize, channels: usize) -> Vec<i16> {
        (0..frames * channels).map(|i| i as i16).collect()
    }

    #[test]
    fn recording_sink_takes_what_fits_and_leaves_the_rest() {
        let mut sink = RecordingSink::with_buffer_frames(AudioFormat::Stereo48k, 100);
        sink.start().unwrap();

        // Fits entirely.
        assert_eq!(sink.write(&ramp(40, 2)).unwrap(), 40);
        assert_eq!(sink.padding_frames().unwrap(), 40);
        assert_eq!(sink.written().len(), 80);

        // Only 60 frames of room left, so a 100-frame offer takes 60 and the
        // caller keeps the remainder. This is the whole reason `write` returns
        // a count instead of swallowing the buffer.
        let pcm = ramp(100, 2);
        assert_eq!(sink.write(&pcm).unwrap(), 60);
        assert_eq!(sink.padding_frames().unwrap(), 100);
        assert_eq!(sink.written().len(), 80 + 120);
        // And it took the FRONT of the offer, not a slice from anywhere else.
        assert_eq!(&sink.written()[80..200], &pcm[..120]);

        // Full: nothing more goes in, and that is not an error.
        assert_eq!(sink.write(&ramp(10, 2)).unwrap(), 0);

        // The engine plays some, and room reappears.
        sink.drain(30);
        assert_eq!(sink.padding_frames().unwrap(), 70);
        assert_eq!(sink.write(&ramp(10, 2)).unwrap(), 10);
    }

    #[test]
    fn padding_is_the_latency() {
        let mut sink = RecordingSink::new(AudioFormat::Stereo48k);
        assert_eq!(sink.buffer_frames(), 19_200, "400 ms at 48 kHz");
        sink.start().unwrap();
        assert_eq!(sink.latency_ms().unwrap(), 0, "empty buffer, no latency");

        // 4800 frames at 48 kHz is exactly 100 ms of queued audio.
        assert_eq!(sink.write(&ramp(4800, 2)).unwrap(), 4800);
        assert_eq!(sink.latency_ms().unwrap(), 100);
        sink.drain(2400);
        assert_eq!(sink.latency_ms().unwrap(), 50);
    }

    #[test]
    fn an_empty_buffer_is_an_underrun_only_after_the_stream_has_been_fed() {
        let mut sink = RecordingSink::with_buffer_frames(AudioFormat::Mono48k, 100);

        // Before start: an empty buffer is just an unstarted stream.
        assert_eq!(sink.write(&ramp(10, 1)).unwrap(), 10);
        assert_eq!(sink.underruns(), 0);

        sink.start().unwrap();
        // Still not an underrun — there is audio queued.
        assert_eq!(sink.write(&ramp(10, 1)).unwrap(), 10);
        assert_eq!(sink.underruns(), 0);

        // The engine consumes everything and we arrive to find nothing left.
        // That is an audible gap.
        sink.drain(u32::MAX);
        assert_eq!(sink.padding_frames().unwrap(), 0);
        assert_eq!(sink.write(&ramp(10, 1)).unwrap(), 10);
        assert_eq!(sink.underruns(), 1);

        // Counted per occurrence, not latched.
        sink.drain(u32::MAX);
        assert_eq!(sink.write(&ramp(10, 1)).unwrap(), 10);
        assert_eq!(sink.underruns(), 2);
    }

    #[test]
    fn a_partial_frame_is_rejected_rather_than_truncated() {
        let mut sink = RecordingSink::new(AudioFormat::Stereo48k);
        sink.start().unwrap();
        let err = sink
            .write(&[1, 2, 3])
            .expect_err("3 samples is one and a half stereo frames");
        assert!(err.to_string().contains("whole number"), "got: {err}");
        assert!(sink.written().is_empty(), "nothing may have been recorded");
        // Mono, where every sample count is a whole number of frames.
        let mut mono = RecordingSink::new(AudioFormat::Mono48k);
        mono.start().unwrap();
        assert_eq!(mono.write(&[1, 2, 3]).unwrap(), 3);
    }

    #[test]
    fn an_empty_write_is_a_no_op() {
        let mut sink = RecordingSink::new(AudioFormat::Stereo48k);
        sink.start().unwrap();
        assert_eq!(sink.write(&[]).unwrap(), 0);
        assert_eq!(sink.underruns(), 0, "nothing offered is not an underrun");
        assert_eq!(sink.frames_written(), 0);
    }

    #[test]
    fn start_and_stop_are_idempotent() {
        let mut sink = RecordingSink::new(AudioFormat::Mono44k1);
        assert!(!sink.is_started());
        sink.start().unwrap();
        sink.start().unwrap();
        assert!(sink.is_started());
        sink.stop().unwrap();
        sink.stop().unwrap();
        assert!(!sink.is_started());
    }

    /// A `Box<dyn PcmSink>` is what the playback loop will hold.
    #[test]
    fn the_double_satisfies_the_object_safe_trait() {
        let mut sink: Box<dyn PcmSink> = Box::new(RecordingSink::new(AudioFormat::Stereo44k1));
        assert_eq!(sink.format(), AudioFormat::Stereo44k1);
        assert_eq!(sink.buffer_frames(), 17_640, "400 ms at 44.1 kHz");
        assert!(sink.describe().contains("44100"));
        sink.start().unwrap();
        assert_eq!(sink.write(&ramp(64, 2)).unwrap(), 64);
        assert_eq!(sink.latency_ms().unwrap(), 1);
        sink.stop().unwrap();
    }

    /// The factory must not silently succeed where there is no endpoint.
    #[cfg(not(windows))]
    #[test]
    fn there_is_no_endpoint_off_windows() {
        assert!(new_pcm_sink(AudioFormat::Stereo48k).is_err());
    }
}

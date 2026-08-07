//! Windows system-audio capture: WASAPI shared-mode loopback off the default
//! render endpoint, plus a synthetic tone source that needs no hardware.
//!
//! Two implementations of [`AudioSource`] live here:
//!
//! * [`LoopbackCapture`] — what the user actually hears. `MMDeviceEnumerator`
//!   → `GetDefaultAudioEndpoint(eRender, eConsole)` → an `IAudioClient`
//!   initialised with `AUDCLNT_STREAMFLAGS_LOOPBACK`, **plus a second
//!   `IAudioClient` on the same device rendering silence** (see
//!   `SilentKeepAlive`, and read that doc comment before touching it).
//! * [`TestTone`] — a sine generator with the same interface. Not scaffolding:
//!   it is the field diagnostic for "is the audio pipe working at all?" on a
//!   machine nobody is sitting in front of, and it is what the interop tests
//!   use so they are deterministic rather than dependent on whatever the host
//!   happened to be playing.
//!
//! Everything in this module is wired to nothing yet. A later commit connects
//! it to a thread, a config flag and the transport.
//!
//! # What this module refuses
//!
//! The pipeline supports exactly four formats: 48 kHz and 44.1 kHz, mono and
//! stereo. That is not laziness, it is the AAC encoder's accepted input set
//! ([`crate::audio_encoder`]) and the four `AudioSpecificConfig` blobs the
//! client decoder can be handed. A 5.1 or 96 kHz endpoint is refused by
//! [`classify_mix_format`] with a log line naming what it found, and audio is
//! then simply off for that user. The alternative — quietly reinterpreting six
//! channels as two — is a stream at the wrong pitch and the wrong speed, which
//! is far worse than no stream because nobody can tell what went wrong.
//!
//! # Threading and COM
//!
//! [`ComMta`] is a local, minimal, MTA-only apartment guard. It deliberately
//! does **not** reuse [`crate::mfinit::MfThread`]: that guard also runs
//! `MFStartup(MFSTARTUP_FULL)`, which WASAPI has no use for, and its `Drop`
//! calls `CoUninitialize` on a thread whose apartment it may never have owned.
//! [`ComMta`] is modelled on `service::winutil::ComGuard`, which tracks
//! ownership correctly.
//!
//! [`LoopbackCapture`] owns its guard as its **last field**, so Rust's
//! declaration-order field drop releases every WASAPI interface before the
//! apartment goes away. It is `!Send` as a result: build it on the thread that
//! will pump it.

use std::marker::PhantomData;
use std::time::{Duration, Instant};

use directdesk_shared::{Error, Result};
use windows::core::HRESULT;
use windows::Win32::Foundation::RPC_E_CHANGED_MODE;
use windows::Win32::Media::Audio::{
    eConsole, eRender, IAudioCaptureClient, IAudioClient, IAudioRenderClient, IMMDevice,
    IMMDeviceEnumerator, MMDeviceEnumerator, AUDCLNT_BUFFERFLAGS_DATA_DISCONTINUITY,
    AUDCLNT_BUFFERFLAGS_SILENT, AUDCLNT_E_DEVICE_INVALIDATED, AUDCLNT_E_RESOURCES_INVALIDATED,
    AUDCLNT_E_SERVICE_NOT_RUNNING, AUDCLNT_SHAREMODE_SHARED, AUDCLNT_STREAMFLAGS_LOOPBACK,
    WAVEFORMATEX, WAVEFORMATEXTENSIBLE, WAVE_FORMAT_PCM,
};
use windows::Win32::Media::MediaFoundation::{MFAudioFormat_Float, MFAudioFormat_PCM};
use windows::Win32::System::Com::{
    CoCreateInstance, CoInitializeEx, CoTaskMemFree, CoUninitialize, CLSCTX_ALL,
    COINIT_MULTITHREADED,
};

/// `WAVE_FORMAT_EXTENSIBLE` from mmreg.h. Defined here rather than imported
/// because the `windows` crate puts it in `Win32_Media_KernelStreaming` — a
/// whole extra binding module for one `u16` whose value has been fixed by the
/// format spec since Windows 2000. Same story for [`WAVE_FORMAT_IEEE_FLOAT`],
/// which lives under `Win32_Media_Multimedia`. `WAVE_FORMAT_PCM` happens to be
/// re-exported from `Win32_Media_Audio`, so that one is imported.
const WAVE_FORMAT_EXTENSIBLE: u16 = 0xFFFE;
/// `WAVE_FORMAT_IEEE_FLOAT` from mmreg.h. See [`WAVE_FORMAT_EXTENSIBLE`].
const WAVE_FORMAT_IEEE_FLOAT: u16 = 3;

/// How much audio the engine buffers for us, in 100-ns units — 40 ms.
///
/// This is the knob that decides whether capture needs a real-time thread. A
/// 10 ms buffer must be drained inside 10 ms or the engine overwrites it, which
/// on a machine that is also capturing and encoding a screen means asking the
/// Windows scheduler for a favour. At 40 ms an ordinary thread that gets
/// descheduled for a couple of frames loses nothing, and the extra latency is
/// inaudible next to the ~258 ms RTT this product already carries.
const BUFFER_DURATION_HNS: i64 = 40 * 10_000;

// ---- formats -----------------------------------------------------------------

/// How the endpoint hands us samples. Shared mode is float in practice on every
/// modern Windows; the 16-bit case exists because a driver is allowed to offer
/// it and silently mis-reading it would be a wall of noise.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SampleKind {
    /// 32-bit IEEE float, nominally in [-1.0, 1.0] but *not* clamped by the
    /// engine — see [`f32_to_i16`].
    F32,
    /// 16-bit signed integer, already the encoder's input format.
    I16,
}

impl SampleKind {
    pub fn bytes_per_sample(self) -> usize {
        match self {
            SampleKind::F32 => 4,
            SampleKind::I16 => 2,
        }
    }
}

/// One of the four (sample rate, channel count) pairs the pipeline supports.
///
/// Construct only via [`AudioFormat::new`], which is the single gate that keeps
/// an unsupported endpoint from reaching the encoder.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AudioFormat {
    /// 44100 or 48000. Nothing else exists as far as this pipeline is concerned.
    pub sample_rate: u32,
    /// 1 or 2.
    pub channels: u16,
}

impl AudioFormat {
    /// The complete supported set, in the order the rest of the code talks
    /// about it. Exhaustive by construction: [`AudioFormat::new`] accepts a
    /// pair if and only if it appears here, and `audio_encoder` pins an
    /// `AudioSpecificConfig` for each entry.
    pub const SUPPORTED: [AudioFormat; 4] = [
        AudioFormat {
            sample_rate: 48_000,
            channels: 2,
        },
        AudioFormat {
            sample_rate: 44_100,
            channels: 2,
        },
        AudioFormat {
            sample_rate: 48_000,
            channels: 1,
        },
        AudioFormat {
            sample_rate: 44_100,
            channels: 1,
        },
    ];

    /// The 48 kHz stereo default — what a Windows render endpoint mixes at
    /// unless someone has changed it in Sound Control Panel.
    pub const DEFAULT: AudioFormat = AudioFormat::SUPPORTED[0];

    /// Validate a (rate, channels) pair against [`AudioFormat::SUPPORTED`].
    ///
    /// Pure, so the whole refusal policy is testable without an audio device.
    pub fn new(sample_rate: u32, channels: u16) -> Result<Self> {
        let want = AudioFormat {
            sample_rate,
            channels,
        };
        if AudioFormat::SUPPORTED.contains(&want) {
            Ok(want)
        } else {
            Err(Error::Capture(format!(
                "unsupported audio format: {sample_rate} Hz x {channels} channel(s). \
                 DirectDesk streams 48000/44100 Hz in mono or stereo only; set the \
                 default playback device to one of those in Sound Control Panel, or \
                 leave audio disabled"
            )))
        }
    }

    /// Bytes one frame of *encoder input* (16-bit interleaved) occupies.
    pub fn bytes_per_frame(&self) -> usize {
        self.channels as usize * 2
    }

    /// Frames in `d` at this rate, rounded down.
    pub fn frames_in(&self, d: Duration) -> usize {
        (d.as_secs_f64() * self.sample_rate as f64) as usize
    }

    /// `"48000 Hz stereo"`.
    pub fn label(&self) -> String {
        let layout = if self.channels == 1 { "mono" } else { "stereo" };
        format!("{} Hz {layout}", self.sample_rate)
    }
}

/// What the endpoint's mix format turned out to be: the validated
/// [`AudioFormat`] plus the machine-level detail needed to read its bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MixFormat {
    pub format: AudioFormat,
    pub sample_kind: SampleKind,
    /// `nBlockAlign` as the engine reports it — bytes per frame *in the
    /// endpoint's own representation*, which is 8 for float stereo and 4 for
    /// 16-bit stereo. Not the same number as [`AudioFormat::bytes_per_frame`].
    pub block_align: u16,
}

/// Classify a `WAVEFORMATEX` (or `WAVEFORMATEXTENSIBLE`) into the supported set.
///
/// This is where a 5.1 endpoint, a 96 kHz endpoint, or a 24-bit-packed endpoint
/// is turned away. The error is descriptive on purpose: it is the only thing a
/// user or a support log will have to explain why audio never arrived.
///
/// The `WAVEFORMATEXTENSIBLE` case is the normal one — shared-mode Windows
/// hands back extensible float almost universally — and it is detected the
/// documented way: `wFormatTag == WAVE_FORMAT_EXTENSIBLE` **and** `cbSize >= 22`,
/// because a driver that sets the tag without the extension bytes would
/// otherwise have us read a `SubFormat` GUID off the end of its allocation.
///
/// The `SubFormat` GUIDs are compared against `MFAudioFormat_PCM` and
/// `MFAudioFormat_Float`. Those are byte-for-byte the same values as
/// `KSDATAFORMAT_SUBTYPE_PCM` (`00000001-0000-0010-8000-00AA00389B71`) and
/// `KSDATAFORMAT_SUBTYPE_IEEE_FLOAT` (`00000003-...`) — the KS names just live
/// in two `windows` feature modules this crate does not otherwise need. Verified
/// against the bindings, not assumed.
///
/// # Safety
/// `wfx` must point at a live, correctly sized `WAVEFORMATEX`. If `wFormatTag`
/// is `WAVE_FORMAT_EXTENSIBLE` and `cbSize >= 22`, the allocation must extend to
/// a full `WAVEFORMATEXTENSIBLE` — which is what that pair of fields asserts,
/// and what `IAudioClient::GetMixFormat` guarantees.
pub unsafe fn classify_mix_format(wfx: *const WAVEFORMATEX) -> Result<MixFormat> {
    if wfx.is_null() {
        return Err(Error::Capture("GetMixFormat returned a null format".into()));
    }
    // SAFETY: caller guarantees a live WAVEFORMATEX. Read by value — the struct
    // is `#[repr(C, packed(1))]`, so nothing may hold a reference into it.
    let base = unsafe { wfx.read_unaligned() };
    let tag = base.wFormatTag;
    let channels = base.nChannels;
    let rate = base.nSamplesPerSec;
    let bits = base.wBitsPerSample;
    let block_align = base.nBlockAlign;
    let cb_size = base.cbSize;

    let sample_kind = if tag == WAVE_FORMAT_EXTENSIBLE {
        if cb_size < 22 {
            return Err(Error::Capture(format!(
                "endpoint reports WAVE_FORMAT_EXTENSIBLE but only {cb_size} extension \
                 bytes (need 22); refusing to read a SubFormat that may not be there"
            )));
        }
        // SAFETY: tag + cbSize together assert the allocation is a full
        // WAVEFORMATEXTENSIBLE; read by value for the same packed-struct reason.
        let ext = unsafe { wfx.cast::<WAVEFORMATEXTENSIBLE>().read_unaligned() };
        let sub = ext.SubFormat;
        if sub == MFAudioFormat_Float {
            SampleKind::F32
        } else if sub == MFAudioFormat_PCM {
            SampleKind::I16
        } else {
            return Err(Error::Capture(format!(
                "unsupported endpoint sample format {sub:?}: DirectDesk reads \
                 IEEE-float or 16-bit PCM only"
            )));
        }
    } else if tag == WAVE_FORMAT_IEEE_FLOAT {
        SampleKind::F32
    } else if tag as u32 == WAVE_FORMAT_PCM {
        SampleKind::I16
    } else {
        return Err(Error::Capture(format!(
            "unsupported endpoint wFormatTag {tag:#06x}: DirectDesk reads \
             IEEE-float or 16-bit PCM only"
        )));
    };

    // The tag says how to interpret bits; disagreement means we would read the
    // buffer at the wrong stride, i.e. noise. Refuse rather than guess.
    let want_bits = (sample_kind.bytes_per_sample() * 8) as u16;
    if bits != want_bits {
        return Err(Error::Capture(format!(
            "endpoint claims {sample_kind:?} but {bits} bits per sample (expected \
             {want_bits}); refusing to read it at the wrong stride"
        )));
    }
    let want_align = sample_kind.bytes_per_sample() * channels as usize;
    if block_align as usize != want_align {
        return Err(Error::Capture(format!(
            "endpoint nBlockAlign is {block_align}, expected {want_align} for \
             {channels} x {sample_kind:?}"
        )));
    }

    let format = AudioFormat::new(rate, channels)?;
    Ok(MixFormat {
        format,
        sample_kind,
        block_align,
    })
}

// ---- pure sample maths -------------------------------------------------------

/// Convert 32-bit float samples to the 16-bit PCM the AAC encoder accepts.
///
/// Mandatory, not a convenience: WASAPI shared mode delivers float and
/// `AACMFTEncoder` takes 16-bit integer only, so this conversion sits on the
/// only path between them.
///
/// Clamping is the whole point. The float the engine hands back is **not**
/// guaranteed to be inside [-1.0, 1.0] — a shared-mode mix of several loud
/// applications routinely exceeds it, and any "loudness enhancement" APO can
/// push it further. Without the clamp, `1.5 * 32767.0` wraps to a large
/// negative i16 and the listener gets a hard click on every peak. With it the
/// peak flattens, which is exactly what a real limiter would do.
///
/// The scale is 32767, not 32768, so full scale maps symmetrically: `+1.0` →
/// `32767` and `-1.0` → `-32767`. Rust's float-to-int `as` cast saturates
/// rather than wrapping, so a NaN (which no comparison clamps) lands on `0`
/// and an infinity lands on the rail — neither panics, which the "never panic"
/// rule for this module requires.
pub fn f32_to_i16(samples: &[f32]) -> Vec<i16> {
    samples.iter().copied().map(sample_f32_to_i16).collect()
}

/// The scalar body of [`f32_to_i16`]. Split out so [`TestTone::generate`] can
/// use the identical conversion without allocating a one-element `Vec` per
/// sample — at 48 kHz that would be 48 000 allocations a second for a
/// diagnostic that is supposed to be cheap.
#[inline]
fn sample_f32_to_i16(s: f32) -> i16 {
    // NaN survives `clamp` unchanged (it is neither `<` nor `>`), and then
    // saturates to 0 in the cast. That is the right answer: a NaN sample is a
    // dead sample, and silence beats a click.
    (s.clamp(-1.0, 1.0) * 32767.0).round() as i16
}

/// Turn one WASAPI packet's raw bytes into interleaved 16-bit PCM.
///
/// Byte-oriented rather than slice-cast on purpose: the pointer
/// `IAudioCaptureClient::GetBuffer` hands back carries no alignment guarantee
/// this code is entitled to rely on, and `from_raw_parts::<f32>` on a
/// misaligned pointer is undefined behaviour even when it happens to work.
/// Copying bytes and decoding them costs a few hundred KB/s of memcpy on a
/// stream that is already 384 KB/s, which is not a budget worth defending.
///
/// A trailing partial sample (a packet whose length is not a whole number of
/// samples, which should never happen) is dropped rather than treated as an
/// error: it is one sample, and refusing the packet would take the whole
/// stream down over a driver quirk.
pub fn packet_to_i16(bytes: &[u8], kind: SampleKind) -> Vec<i16> {
    match kind {
        SampleKind::F32 => {
            let floats: Vec<f32> = bytes
                .chunks_exact(4)
                .map(|c| f32::from_le_bytes([c[0], c[1], c[2], c[3]]))
                .collect();
            f32_to_i16(&floats)
        }
        SampleKind::I16 => bytes
            .chunks_exact(2)
            .map(|c| i16::from_le_bytes([c[0], c[1]]))
            .collect(),
    }
}

/// Did WASAPI itself mark this packet silent?
///
/// The engine sets `AUDCLNT_BUFFERFLAGS_SILENT` when nothing is being rendered,
/// and when it does, **the buffer contents are undefined** — reading it is not
/// merely wasteful, it can produce noise. So this is checked before the data is
/// touched, never after.
pub fn buffer_flags_say_silent(flags: u32) -> bool {
    flags & (AUDCLNT_BUFFERFLAGS_SILENT.0 as u32) != 0
}

/// Is this packet silent, by either of the two ways a packet can be silent?
///
/// The flag is not sufficient on its own. An application that is actively
/// rendering literal zeros — a paused media player holding its stream open, a
/// game with its volume at zero — produces a packet the engine considers real
/// audio and marks as data. Encoding those is a steady trickle of AAC frames
/// carrying nothing, forever. The explicit scan catches them.
///
/// An empty packet is silent, trivially. That matters because it is the case a
/// caller hits when the loopback stream is idle and no keep-alive is running.
pub fn is_silent(flags: u32, pcm: &[i16]) -> bool {
    buffer_flags_say_silent(flags) || pcm.iter().all(|&s| s == 0)
}

/// Is this HRESULT the "your endpoint went away, build a new one" condition
/// rather than "audio is broken on this machine"?
///
/// Headphones plugged in, a Bluetooth headset connecting, an exclusive-mode
/// application seizing the device, the Windows Audio service restarting — all
/// of these invalidate a live `IAudioClient` and all of them are followed,
/// moments later, by a perfectly good new default endpoint.
///
/// The recovery is to drop the whole [`LoopbackCapture`] and construct another.
/// That is deliberately cheaper than implementing `IMMNotificationClient`: the
/// notification interface requires an STA-friendly COM object, careful
/// registration/unregistration lifetimes, and a callback that must not block —
/// all to learn something a failed call tells us for free, at the exact moment
/// it becomes relevant.
pub fn is_recoverable_hresult(hr: HRESULT) -> bool {
    hr == AUDCLNT_E_DEVICE_INVALIDATED
        || hr == AUDCLNT_E_RESOURCES_INVALIDATED
        || hr == AUDCLNT_E_SERVICE_NOT_RUNNING
}

// ---- COM apartment -----------------------------------------------------------

/// RAII MTA apartment guard. Uninitializes only if *we* initialized.
///
/// Modelled on `service::winutil::ComGuard`. Deliberately **not**
/// [`crate::mfinit::MfThread`]: that one additionally runs
/// `MFStartup(MFSTARTUP_FULL)`, which WASAPI neither needs nor benefits from,
/// and its `Drop` calls `CoUninitialize` unconditionally at depth 1 even on a
/// thread whose apartment it inherited rather than created.
///
/// `!Send` by construction: a COM apartment belongs to the thread that entered
/// it, so the guard must be dropped there too.
pub struct ComMta {
    owned: bool,
    _not_send: PhantomData<*const ()>,
}

impl ComMta {
    /// Enter the multithreaded apartment on the calling thread.
    ///
    /// `S_FALSE` (already initialized MTA on this thread) still counts as
    /// owned — every successful `CoInitializeEx`, `S_OK` or `S_FALSE`, needs
    /// exactly one matching `CoUninitialize`. `RPC_E_CHANGED_MODE` means the
    /// thread is already an STA: usable, but not ours to tear down.
    pub fn enter() -> Result<Self> {
        // SAFETY: plain per-thread COM init, balanced in Drop.
        let hr = unsafe { CoInitializeEx(None, COINIT_MULTITHREADED) };
        if hr.is_ok() {
            Ok(Self {
                owned: true,
                _not_send: PhantomData,
            })
        } else if hr == RPC_E_CHANGED_MODE {
            Ok(Self {
                owned: false,
                _not_send: PhantomData,
            })
        } else {
            Err(Error::Capture(format!(
                "CoInitializeEx(MTA) failed: {hr:?}"
            )))
        }
    }
}

impl Drop for ComMta {
    fn drop(&mut self) {
        if self.owned {
            // SAFETY: balanced against our own successful CoInitializeEx.
            unsafe { CoUninitialize() };
        }
    }
}

// ---- the source abstraction --------------------------------------------------

/// One packet of captured audio, already converted to the encoder's format.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AudioPacket {
    /// Interleaved 16-bit PCM: `frames * channels` samples.
    pub pcm: Vec<i16>,
    /// Frames (sample groups), i.e. `pcm.len() / channels`.
    pub frames: usize,
    /// True when nothing audible is in here — see [`is_silent`]. The caller may
    /// skip encoding these, but must still advance its timestamp by `frames`.
    pub silent: bool,
    /// True when the engine reported a glitch before this packet, i.e. audio
    /// was lost. Worth logging; the stream continues either way.
    pub discontinuity: bool,
}

/// Something that produces system audio.
///
/// Both implementations are poll-driven and non-blocking: `next_packet` returns
/// `Ok(None)` when nothing is ready yet. That keeps the eventual capture thread
/// a plain loop with a sleep rather than a set of waitable-handle callbacks, and
/// it is why the module's engine buffer duration is as generous as it is.
pub trait AudioSource {
    /// The format every packet from this source is in. Fixed for the source's
    /// lifetime — a format change means the endpoint changed, which surfaces as
    /// an error and a rebuild, not as a silently different packet.
    fn format(&self) -> AudioFormat;

    /// Take whatever is ready. `Ok(None)` means "nothing yet, come back".
    fn next_packet(&mut self) -> Result<Option<AudioPacket>>;

    /// Honest one-line description for the log and the status UI.
    fn describe(&self) -> String;
}

// ---- the silent keep-alive ---------------------------------------------------

/// A second `IAudioClient` on the same endpoint, rendering nothing but silence,
/// purely so the loopback capture has something to capture.
///
/// **This is not optional and it is the single most surprising thing about
/// WASAPI loopback.** A loopback capture stream attached to an *idle* render
/// endpoint delivers no packets at all — not silence, not zero-filled buffers,
/// *nothing*. `GetNextPacketSize` returns 0 forever and the audio engine for
/// that endpoint stays powered down.
///
/// The consequence is not "silence is missing", which nobody would notice. It
/// is that the engine takes 50–200 ms to spin up once something *does* start
/// playing, and every one of those milliseconds is clipped off the front of the
/// sound. Since the sounds a remote user most wants to hear are exactly the
/// short ones — a notification chime, an error beep, a Teams call starting —
/// the practical effect is that short sounds arrive as a truncated stub or not
/// at all, intermittently, in a way that looks like a network problem.
///
/// Keeping a render stream open holds the engine running, so loopback delivers
/// a continuous stream of (mostly silent) packets and a real sound starts
/// arriving from its first sample.
///
/// Nothing is ever written into the render buffer. `ReleaseBuffer` is called
/// with `AUDCLNT_BUFFERFLAGS_SILENT`, which tells the engine to treat the
/// buffer as silence *regardless of its contents* — so the uninitialised memory
/// `GetBuffer` hands back is never played and never read.
struct SilentKeepAlive {
    render: IAudioRenderClient,
    client: IAudioClient,
    buffer_frames: u32,
}

impl SilentKeepAlive {
    /// Open and start a silent render stream on `device`.
    ///
    /// # Safety
    /// `device` must be a live `IMMDevice` and COM must be initialized on this
    /// thread for the lifetime of the returned value.
    unsafe fn open(device: &IMMDevice) -> Result<Self> {
        // SAFETY: live device; every out-param is checked, and the mix format
        // pointer is freed on both the success and the failure path below.
        unsafe {
            let client: IAudioClient = device
                .Activate(CLSCTX_ALL, None)
                .map_err(cap_err("IMMDevice::Activate(keep-alive IAudioClient)"))?;
            let wfx = client
                .GetMixFormat()
                .map_err(cap_err("GetMixFormat(keep-alive)"))?;
            // Initialize copies the format, so it may be freed immediately
            // after. Take the result first so the free happens either way.
            let init = client.Initialize(
                AUDCLNT_SHAREMODE_SHARED,
                0,
                BUFFER_DURATION_HNS,
                0,
                wfx,
                None,
            );
            CoTaskMemFree(Some(wfx as *const std::ffi::c_void));
            init.map_err(cap_err("IAudioClient::Initialize(keep-alive render)"))?;

            let buffer_frames = client
                .GetBufferSize()
                .map_err(cap_err("GetBufferSize(keep-alive)"))?;
            let render: IAudioRenderClient = client
                .GetService()
                .map_err(cap_err("GetService(IAudioRenderClient)"))?;

            let me = Self {
                render,
                client,
                buffer_frames,
            };
            // Pre-fill before Start so the engine never sees an underrun on the
            // very first period; an underrun on a stream whose only job is to
            // exist would be an odd thing to log forever.
            me.top_up()
                .map_err(cap_err("IAudioRenderClient(keep-alive pre-fill)"))?;
            me.client
                .Start()
                .map_err(cap_err("IAudioClient::Start(keep-alive render)"))?;
            Ok(me)
        }
    }

    /// Refill the render buffer with silence.
    ///
    /// Called from the same poll that drains capture, which is why the
    /// keep-alive needs no thread of its own: with a 40 ms buffer, any polling
    /// interval comfortably under 40 ms keeps the engine fed.
    ///
    /// Returns the raw `windows::core::Error` rather than [`Error::Capture`] on
    /// purpose: the caller in [`AudioSource::next_packet`] has to inspect
    /// the HRESULT with [`is_recoverable_hresult`] to decide whether this is an
    /// endpoint that went away (rebuild) or a machine on which audio is simply
    /// broken (carry on, quietly). A pre-formatted string cannot be asked that.
    fn top_up(&self) -> windows::core::Result<()> {
        // SAFETY: live client and render service; `free` is bounded by the
        // buffer size the client itself reported, and the buffer we ask for is
        // handed straight back unwritten under the SILENT flag.
        unsafe {
            let padding = self.client.GetCurrentPadding()?;
            let free = self.buffer_frames.saturating_sub(padding);
            if free == 0 {
                return Ok(());
            }
            // THE INVARIANT, the same one stated over the capture path's own
            // GetBuffer: a successful GetBuffer must ALWAYS be followed by a
            // ReleaseBuffer. Results are bound to locals and no `?` is allowed
            // between the two, because an early return with the render buffer
            // still acquired is not a lost period — it is permanent. Every
            // later GetBuffer on this stream then fails
            // `AUDCLNT_E_OUT_OF_ORDER`, the keep-alive stops feeding the
            // engine, and loopback capture goes silent for the rest of the
            // session.
            let got = self.render.GetBuffer(free);
            // Nothing was acquired, so there is nothing to hand back.
            got?;
            // The returned pointer is deliberately never written to; see the
            // struct doc. The SILENT flag is what makes an unwritten buffer
            // legal to release.
            let released = self
                .render
                .ReleaseBuffer(free, AUDCLNT_BUFFERFLAGS_SILENT.0 as u32);
            if let Err(e) = released {
                // The release itself failing is the one path that can still
                // strand the buffer. Handing back zero frames is the documented
                // way to abandon a packet obtained from GetBuffer, so try that
                // once before giving up; if it fails too the endpoint is gone
                // anyway and the error being returned gets the whole capture
                // rebuilt.
                let _ = self.render.ReleaseBuffer(0, 0);
                return Err(e);
            }
            Ok(())
        }
    }
}

impl Drop for SilentKeepAlive {
    fn drop(&mut self) {
        // SAFETY: mirror of the Start in `open`; a failure at teardown is not
        // actionable and the interfaces are released immediately after.
        unsafe {
            let _ = self.client.Stop();
        }
    }
}

// ---- loopback capture --------------------------------------------------------

/// WASAPI shared-mode loopback capture of the default render endpoint.
///
/// Field order is load-bearing: Rust drops struct fields in declaration order,
/// so every COM interface here is released before `_com` uninitializes the
/// apartment. Do not move `_com`.
pub struct LoopbackCapture {
    capture: IAudioCaptureClient,
    client: IAudioClient,
    keepalive: SilentKeepAlive,
    mix: MixFormat,
    /// Sticky: set by any call that failed with a [`is_recoverable_hresult`]
    /// code. Once true this instance is finished — the caller should drop it
    /// and build a new one.
    invalidated: bool,
    /// Whether the last [`SilentKeepAlive::top_up`] failed, so the warning is
    /// logged once per run of failures rather than on every poll. The keep-alive
    /// is topped up ~100 times a second; a fault that is not recoverable (and so
    /// does not set `invalidated`) would otherwise print 100 lines a second for
    /// the rest of the session.
    keepalive_failed: bool,
    /// Reusable byte buffer for one packet, so a steady stream of packets does
    /// not allocate one `Vec<u8>` per 10 ms forever.
    scratch: Vec<u8>,
    _com: ComMta,
}

impl LoopbackCapture {
    /// Open loopback capture on the default console render endpoint.
    ///
    /// Enters the MTA on the calling thread if it is not already in one. The
    /// returned value is `!Send` (it owns the apartment guard), so build it on
    /// the thread that will pump [`AudioSource::next_packet`].
    pub fn new() -> Result<Self> {
        let com = ComMta::enter()?;

        // SAFETY: every interface below is checked; the mix format pointer is
        // CoTaskMemFree'd exactly once, on both paths.
        unsafe {
            let enumerator: IMMDeviceEnumerator =
                CoCreateInstance(&MMDeviceEnumerator, None, CLSCTX_ALL)
                    .map_err(cap_err("CoCreateInstance(MMDeviceEnumerator)"))?;
            let device = enumerator
                .GetDefaultAudioEndpoint(eRender, eConsole)
                .map_err(cap_err("GetDefaultAudioEndpoint(eRender, eConsole)"))?;

            let client: IAudioClient = device
                .Activate(CLSCTX_ALL, None)
                .map_err(cap_err("IMMDevice::Activate(loopback IAudioClient)"))?;

            let wfx = client.GetMixFormat().map_err(cap_err("GetMixFormat"))?;
            let classified = classify_mix_format(wfx);
            // Loopback capture must be initialised with the endpoint's *own*
            // mix format — shared mode does not resample a loopback stream, so
            // asking for anything else is refused. That is precisely why the
            // supported set is a refusal policy and not a conversion: the
            // format is the endpoint's to choose.
            let init = client.Initialize(
                AUDCLNT_SHAREMODE_SHARED,
                AUDCLNT_STREAMFLAGS_LOOPBACK,
                BUFFER_DURATION_HNS,
                0,
                wfx,
                None,
            );
            CoTaskMemFree(Some(wfx as *const std::ffi::c_void));

            let mix = match classified {
                Ok(m) => m,
                Err(e) => {
                    // The loud refusal. This is the line that explains to a
                    // human why their remote session has no sound.
                    tracing::warn!("system audio disabled: {e}");
                    return Err(e);
                }
            };
            init.map_err(cap_err("IAudioClient::Initialize(loopback)"))?;

            let capture: IAudioCaptureClient = client
                .GetService()
                .map_err(cap_err("GetService(IAudioCaptureClient)"))?;

            // Order matters: bring the keep-alive up before starting capture,
            // so the engine is already running when the first packet is asked
            // for rather than spinning up underneath us.
            let keepalive = SilentKeepAlive::open(&device)?;
            client
                .Start()
                .map_err(cap_err("IAudioClient::Start(loopback)"))?;

            tracing::info!(
                sample_kind = ?mix.sample_kind,
                block_align = mix.block_align,
                "WASAPI loopback capture ready ({}), {} ms engine buffer, \
                 silent keep-alive render stream running",
                mix.format.label(),
                BUFFER_DURATION_HNS / 10_000
            );

            Ok(Self {
                capture,
                client,
                keepalive,
                mix,
                invalidated: false,
                keepalive_failed: false,
                scratch: Vec::new(),
                _com: com,
            })
        }
    }

    /// True once a call has failed with a device-invalidation code. The caller's
    /// response is to drop this and call [`LoopbackCapture::new`] again — see
    /// [`is_recoverable_hresult`].
    pub fn needs_rebuild(&self) -> bool {
        self.invalidated
    }

    /// How the endpoint represents samples, before conversion.
    pub fn mix_format(&self) -> MixFormat {
        self.mix
    }

    /// Note a COM failure, marking this instance dead if the code says the
    /// endpoint went away, and turn it into our error type.
    fn fault(&mut self, what: &'static str, e: windows::core::Error) -> Error {
        if is_recoverable_hresult(e.code()) {
            self.invalidated = true;
            tracing::info!(
                "audio endpoint invalidated during {what} ({e}); capture will be rebuilt"
            );
        }
        Error::Capture(format!("{what}: {e}"))
    }
}

impl AudioSource for LoopbackCapture {
    fn format(&self) -> AudioFormat {
        self.mix.format
    }

    fn next_packet(&mut self) -> Result<Option<AudioPacket>> {
        if self.invalidated {
            return Err(Error::Capture(
                "audio endpoint was invalidated; rebuild the capture".into(),
            ));
        }

        // A keep-alive that cannot top up is NOT cosmetic, and it does NOT
        // surface as a capture error on the next line.
        //
        // That was the old claim here and it is false for the one case that
        // matters. The keep-alive's entire job is to keep the render engine
        // powered so that loopback has something to capture (read
        // `SilentKeepAlive`'s doc comment). Once it stops feeding the engine,
        // an idle loopback stream does not fail — it returns `Ok(None)`
        // forever. So the failure mode is not an error anywhere, it is silence:
        // exactly the truncated notification chime this whole class exists to
        // prevent, with nothing above `debug` to say why.
        //
        // So it is treated as what it is, a capture failure: `fault` marks the
        // instance dead when the HRESULT says the endpoint went away, which
        // gets the next `next_packet` to refuse and the sender to rebuild. A
        // code that is *not* recoverable leaves the capture running — degraded
        // audio beats none — but is still said out loud, once.
        //
        // Bound to a local before `fault` is called on it for the same reason
        // the capture calls below are: `fault` takes `&mut self`, and leaving
        // the call inside an expression that still borrows `self.keepalive` is
        // the shape the borrow checker rejects.
        let topped_up = self.keepalive.top_up();
        if let Err(e) = topped_up {
            let first = !self.keepalive_failed;
            self.keepalive_failed = true;
            let err = self.fault("silent keep-alive top-up", e);
            if first {
                tracing::warn!("{err}; system audio may go silent");
            } else {
                tracing::debug!("{err}");
            }
        } else {
            // A run of failures that clears is worth hearing about if it comes
            // back, so the next one is loud again.
            self.keepalive_failed = false;
        }

        // Each COM result is bound to a local before `self.fault` is called on
        // it. That is not style: `fault` takes `&mut self`, and leaving the
        // call inside a `.map_err(..)` on the same expression that borrows
        // `self.capture` is the shape the borrow checker rejects.
        // SAFETY: live capture client.
        let available = match unsafe { self.capture.GetNextPacketSize() } {
            Ok(n) => n,
            Err(e) => return Err(self.fault("GetNextPacketSize", e)),
        };
        if available == 0 {
            return Ok(None);
        }

        let mut data: *mut u8 = std::ptr::null_mut();
        let mut frames: u32 = 0;
        let mut flags: u32 = 0;
        // SAFETY: live capture client; the three out-params are stack locals.
        let got = unsafe {
            self.capture
                .GetBuffer(&mut data, &mut frames, &mut flags, None, None)
        };
        if let Err(e) = got {
            return Err(self.fault("IAudioCaptureClient::GetBuffer", e));
        }

        // THE INVARIANT: a successful GetBuffer must ALWAYS be followed by
        // ReleaseBuffer, or the engine's ring buffer stalls and the stream dies
        // silently. So the only thing that happens in between is a memcpy into
        // `scratch` — no `?`, no early return, no fallible call.
        self.scratch.clear();
        // A SILENT packet's contents are undefined and may be a stale buffer;
        // a null pointer is also legal for one. In both cases the right read is
        // no read at all — `scratch` stays empty and the packet is materialised
        // as zeros below.
        if !data.is_null() && !buffer_flags_say_silent(flags) {
            let len = frames as usize * self.mix.block_align as usize;
            // SAFETY: `data` is the engine's buffer, valid for exactly `frames`
            // frames of `block_align` bytes until ReleaseBuffer below.
            let src = unsafe { std::slice::from_raw_parts(data, len) };
            self.scratch.extend_from_slice(src);
        }
        // SAFETY: pairs with the GetBuffer above.
        let released = unsafe { self.capture.ReleaseBuffer(frames) };
        if let Err(e) = released {
            return Err(self.fault("IAudioCaptureClient::ReleaseBuffer", e));
        }

        let channels = (self.mix.format.channels as usize).max(1);
        let pcm = if self.scratch.is_empty() {
            // Silent packet: synthesise the zeros rather than return nothing,
            // so the caller's timeline still advances by `frames`.
            vec![0i16; frames as usize * channels]
        } else {
            // Take and put back so the decode borrows `scratch` immutably while
            // `self` stays otherwise untouched, and the allocation is reused.
            let scratch = std::mem::take(&mut self.scratch);
            let pcm = packet_to_i16(&scratch, self.mix.sample_kind);
            self.scratch = scratch;
            pcm
        };

        Ok(Some(AudioPacket {
            silent: is_silent(flags, &pcm),
            frames: pcm.len() / channels,
            discontinuity: flags & (AUDCLNT_BUFFERFLAGS_DATA_DISCONTINUITY.0 as u32) != 0,
            pcm,
        }))
    }

    fn describe(&self) -> String {
        format!(
            "WASAPI loopback — {} ({:?}), silent keep-alive on",
            self.mix.format.label(),
            self.mix.sample_kind
        )
    }
}

impl Drop for LoopbackCapture {
    fn drop(&mut self) {
        // SAFETY: mirror of the Start in `new`; teardown failures are not
        // actionable. The keep-alive stops itself in its own Drop, which runs
        // after this one but before `_com` — see the struct's field order note.
        unsafe {
            let _ = self.client.Stop();
        }
    }
}

// ---- synthetic tone ----------------------------------------------------------

/// Default tone frequency: A above middle C. Chosen because it is unmistakably
/// a test tone to a human ear and sits in the middle of every codec's comfort
/// zone, so a distorted or pitch-shifted result is obvious rather than subtle.
pub const TEST_TONE_HZ: f32 = 440.0;
/// Default amplitude — about -6 dBFS. Loud enough to hear over a bad link,
/// quiet enough that clipping anywhere downstream is a bug and not the signal.
pub const TEST_TONE_AMPLITUDE: f32 = 0.5;

/// A synthetic sine source with the same interface as [`LoopbackCapture`].
///
/// This is a product feature, not test scaffolding. The question "is audio
/// working?" on a host in another state, with nobody in the room and nothing
/// playing, is otherwise unanswerable: silence at the client could be a dead
/// capture, a dead encoder, a dead transport, a dead decoder, or simply nothing
/// playing on the host. Switching the source to a tone collapses all of that to
/// one bit — either you hear 440 Hz or you do not, and where it stops being
/// audible tells you which stage failed.
///
/// It also makes the interop tests deterministic: a fixed number of frames of a
/// known waveform, with no dependence on what the machine happened to be
/// playing or on whether it has an audio device at all.
pub struct TestTone {
    format: AudioFormat,
    freq_hz: f32,
    amplitude: f32,
    /// Phase in cycles, kept in f64 so a long run does not accumulate the
    /// rounding error an f32 phase would (at 48 kHz an f32 phase loses its low
    /// bits within minutes and the tone audibly drifts).
    phase: f64,
    /// Wall clock the source started, for the paced `next_packet`. `generate`
    /// ignores it entirely.
    started: Instant,
    frames_emitted: u64,
}

impl TestTone {
    /// A 440 Hz tone in `format`.
    pub fn new(format: AudioFormat) -> Self {
        Self::with_tone(format, TEST_TONE_HZ, TEST_TONE_AMPLITUDE)
    }

    /// A tone at an explicit frequency and amplitude. `amplitude` is clamped
    /// into [0.0, 1.0] — a caller asking for 2.0 gets full scale, not a square
    /// wave from the clamp in [`f32_to_i16`].
    pub fn with_tone(format: AudioFormat, freq_hz: f32, amplitude: f32) -> Self {
        Self {
            format,
            freq_hz,
            amplitude: amplitude.clamp(0.0, 1.0),
            phase: 0.0,
            started: Instant::now(),
            frames_emitted: 0,
        }
    }

    /// Generate exactly `frames` frames, advancing the phase.
    ///
    /// Deterministic: no clock, no hardware, no allocation beyond the packet.
    /// Two `TestTone`s constructed identically and asked for the same frame
    /// counts produce byte-identical output, which is what makes it usable as
    /// an interop-test fixture.
    pub fn generate(&mut self, frames: usize) -> AudioPacket {
        let channels = self.format.channels as usize;
        let step = self.freq_hz as f64 / self.format.sample_rate as f64;
        let mut pcm = Vec::with_capacity(frames * channels);
        for _ in 0..frames {
            let s = (self.phase * std::f64::consts::TAU).sin() as f32 * self.amplitude;
            let sample = sample_f32_to_i16(s);
            for _ in 0..channels {
                pcm.push(sample);
            }
            // Wrap rather than grow without bound: sin is periodic, so keeping
            // the phase in [0, 1) is exact and keeps the f64 at full precision
            // no matter how long the stream runs.
            self.phase = (self.phase + step).fract();
        }
        self.frames_emitted += frames as u64;
        AudioPacket {
            // `<= 0.0` rather than `== 0.0`: the constructor clamps into
            // [0.0, 1.0], so this is exact, and it keeps an equality comparison
            // on a float out of the code.
            silent: self.amplitude <= 0.0,
            frames,
            pcm,
            discontinuity: false,
        }
    }

    /// Frames produced so far.
    pub fn frames_emitted(&self) -> u64 {
        self.frames_emitted
    }
}

impl AudioSource for TestTone {
    fn format(&self) -> AudioFormat {
        self.format
    }

    /// Produce however many frames wall-clock time says are due.
    ///
    /// Paced against the source's own start instant rather than "one buffer per
    /// call", so a caller that polls irregularly still gets a stream at real
    /// speed — which is the point, since the whole exercise is to hear whether
    /// the pipeline delivers audio at the right rate.
    fn next_packet(&mut self) -> Result<Option<AudioPacket>> {
        let due = self.format.frames_in(self.started.elapsed()) as u64;
        let owed = due.saturating_sub(self.frames_emitted);
        if owed == 0 {
            return Ok(None);
        }
        Ok(Some(self.generate(owed as usize)))
    }

    fn describe(&self) -> String {
        format!(
            "synthetic {} Hz test tone — {} (DIAGNOSTIC, not system audio)",
            self.freq_hz,
            self.format.label()
        )
    }
}

// ---- helpers -----------------------------------------------------------------

fn cap_err(what: &'static str) -> impl Fn(windows::core::Error) -> Error {
    move |e| Error::Capture(format!("{what}: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    // Only the hand-built format fixtures below need the extensible struct's
    // `Samples` union, so it is imported here rather than at module scope where
    // it would be an unused import in a product build.
    use windows::Win32::Media::Audio::WAVEFORMATEXTENSIBLE_0;

    // ---- f32 -> i16 ----------------------------------------------------------

    #[test]
    fn f32_to_i16_maps_full_scale_symmetrically() {
        assert_eq!(f32_to_i16(&[0.0]), vec![0]);
        assert_eq!(f32_to_i16(&[1.0]), vec![32767]);
        assert_eq!(f32_to_i16(&[-1.0]), vec![-32767]);
    }

    #[test]
    fn f32_to_i16_clamps_beyond_full_scale() {
        // The whole reason the clamp exists: a shared-mode mix of several loud
        // applications routinely leaves [-1.0, 1.0], and without the clamp
        // these wrap to the opposite rail and click.
        assert_eq!(f32_to_i16(&[1.5]), vec![32767]);
        assert_eq!(f32_to_i16(&[-1.5]), vec![-32767]);
        assert_eq!(f32_to_i16(&[1000.0]), vec![32767]);
        assert_eq!(f32_to_i16(&[-1000.0]), vec![-32767]);
    }

    #[test]
    fn f32_to_i16_survives_infinities_and_nan() {
        // Never a panic, never a wrap. NaN is silence; infinity is a rail.
        assert_eq!(f32_to_i16(&[f32::INFINITY]), vec![32767]);
        assert_eq!(f32_to_i16(&[f32::NEG_INFINITY]), vec![-32767]);
        assert_eq!(f32_to_i16(&[f32::NAN]), vec![0]);
    }

    #[test]
    fn f32_to_i16_rounds_rather_than_truncates() {
        // 0.5 * 32767 = 16383.5; truncation would give 16383 and bias the whole
        // signal toward zero.
        assert_eq!(f32_to_i16(&[0.5]), vec![16384]);
        assert_eq!(f32_to_i16(&[-0.5]), vec![-16384]);
        assert_eq!(f32_to_i16(&[0.0001]), vec![3]);
    }

    #[test]
    fn f32_to_i16_preserves_length_and_order() {
        let out = f32_to_i16(&[0.0, 1.0, -1.0, 0.25]);
        assert_eq!(out.len(), 4);
        assert_eq!(out[1], 32767);
        assert_eq!(out[2], -32767);
        assert_eq!(f32_to_i16(&[]), Vec::<i16>::new());
    }

    // ---- packet decode -------------------------------------------------------

    #[test]
    fn packet_to_i16_decodes_little_endian_floats() {
        let mut bytes = Vec::new();
        for s in [0.0f32, 1.0, -1.0, 0.5] {
            bytes.extend_from_slice(&s.to_le_bytes());
        }
        let want = vec![0i16, 32767, -32767, 16384];
        assert_eq!(packet_to_i16(&bytes, SampleKind::F32), want);
    }

    #[test]
    fn packet_to_i16_passes_16_bit_pcm_through() {
        let mut bytes = Vec::new();
        for s in [0i16, 32767, -32768, -1] {
            bytes.extend_from_slice(&s.to_le_bytes());
        }
        let want = vec![0i16, 32767, -32768, -1];
        assert_eq!(packet_to_i16(&bytes, SampleKind::I16), want);
    }

    #[test]
    fn packet_to_i16_drops_a_trailing_partial_sample() {
        // One stray byte must not take the stream down.
        let bytes = [0u8, 0, 0, 0, 0x7F];
        assert_eq!(packet_to_i16(&bytes, SampleKind::F32).len(), 1);
        assert_eq!(packet_to_i16(&[0u8, 0, 1], SampleKind::I16).len(), 1);
        assert!(packet_to_i16(&[], SampleKind::F32).is_empty());
    }

    // ---- silence -------------------------------------------------------------

    #[test]
    fn wasapi_silent_flag_is_recognised() {
        let silent = AUDCLNT_BUFFERFLAGS_SILENT.0 as u32;
        assert!(buffer_flags_say_silent(silent));
        // Set alongside the discontinuity bit, as the engine may do.
        assert!(buffer_flags_say_silent(silent | 1));
        assert!(!buffer_flags_say_silent(0));
        assert!(!buffer_flags_say_silent(1));
    }

    #[test]
    fn literal_zeros_count_as_silence_without_the_flag() {
        // A paused player rendering real zeros: the engine calls this data, and
        // encoding it forever is the bug this scan prevents.
        assert!(is_silent(0, &[0, 0, 0, 0]));
        assert!(!is_silent(0, &[0, 0, 1, 0]));
    }

    #[test]
    fn the_flag_wins_even_over_nonzero_bytes() {
        // A SILENT packet's contents are undefined, so whatever is in the
        // buffer must not make it "not silent".
        let silent = AUDCLNT_BUFFERFLAGS_SILENT.0 as u32;
        assert!(is_silent(silent, &[999, -999]));
    }

    #[test]
    fn an_empty_packet_is_silent() {
        assert!(is_silent(0, &[]));
    }

    // ---- recoverable errors --------------------------------------------------

    #[test]
    fn device_invalidation_is_recoverable_and_other_faults_are_not() {
        assert!(is_recoverable_hresult(AUDCLNT_E_DEVICE_INVALIDATED));
        assert!(is_recoverable_hresult(AUDCLNT_E_RESOURCES_INVALIDATED));
        assert!(is_recoverable_hresult(AUDCLNT_E_SERVICE_NOT_RUNNING));
        // An unsupported format is not going to fix itself on a retry.
        assert!(!is_recoverable_hresult(
            windows::Win32::Media::Audio::AUDCLNT_E_UNSUPPORTED_FORMAT
        ));
        assert!(!is_recoverable_hresult(windows::Win32::Foundation::E_FAIL));
        assert!(!is_recoverable_hresult(HRESULT(0)));
    }

    // ---- format policy -------------------------------------------------------

    #[test]
    fn the_four_supported_formats_are_accepted() {
        for f in AudioFormat::SUPPORTED {
            let got = AudioFormat::new(f.sample_rate, f.channels).expect("must be supported");
            assert_eq!(got, f);
        }
        assert_eq!(AudioFormat::DEFAULT.sample_rate, 48_000);
        assert_eq!(AudioFormat::DEFAULT.channels, 2);
    }

    #[test]
    fn everything_outside_the_supported_set_is_refused() {
        // 5.1 — the case the whole refusal policy exists for.
        assert!(AudioFormat::new(48_000, 6).is_err());
        assert!(AudioFormat::new(48_000, 8).is_err());
        assert!(AudioFormat::new(96_000, 2).is_err());
        assert!(AudioFormat::new(192_000, 2).is_err());
        assert!(AudioFormat::new(32_000, 2).is_err());
        assert!(AudioFormat::new(0, 0).is_err());
    }

    #[test]
    fn the_refusal_names_what_it_found() {
        // The error text is the only diagnostic a user gets; it must contain
        // the offending numbers rather than a generic complaint.
        let e = AudioFormat::new(96_000, 6).unwrap_err().to_string();
        assert!(e.contains("96000"), "{e}");
        assert!(e.contains('6'), "{e}");
    }

    #[test]
    fn format_arithmetic_matches_the_wire_layout() {
        let stereo = AudioFormat::DEFAULT;
        assert_eq!(stereo.bytes_per_frame(), 4);
        assert_eq!(stereo.frames_in(Duration::from_secs(1)), 48_000);
        assert_eq!(stereo.frames_in(Duration::from_millis(20)), 960);
        let mono = AudioFormat::new(44_100, 1).unwrap();
        assert_eq!(mono.bytes_per_frame(), 2);
        assert_eq!(mono.frames_in(Duration::from_secs(1)), 44_100);
        assert_eq!(mono.label(), "44100 Hz mono");
        assert_eq!(stereo.label(), "48000 Hz stereo");
    }

    // ---- WAVEFORMATEX classification (hand-built structs, no device) ---------

    fn wave_format_ex(tag: u16, channels: u16, rate: u32, bits: u16) -> WAVEFORMATEX {
        let block_align = channels * (bits / 8);
        WAVEFORMATEX {
            wFormatTag: tag,
            nChannels: channels,
            nSamplesPerSec: rate,
            nAvgBytesPerSec: rate * block_align as u32,
            nBlockAlign: block_align,
            wBitsPerSample: bits,
            cbSize: 0,
        }
    }

    fn wave_format_extensible(
        channels: u16,
        rate: u32,
        bits: u16,
        sub: windows::core::GUID,
    ) -> WAVEFORMATEXTENSIBLE {
        let mut base = wave_format_ex(WAVE_FORMAT_EXTENSIBLE, channels, rate, bits);
        base.cbSize = 22;
        WAVEFORMATEXTENSIBLE {
            Format: base,
            Samples: WAVEFORMATEXTENSIBLE_0 {
                wValidBitsPerSample: bits,
            },
            dwChannelMask: 0,
            SubFormat: sub,
        }
    }

    #[test]
    fn classifies_the_ordinary_windows_endpoint() {
        // 48 kHz float stereo extensible: what practically every shared-mode
        // render endpoint reports.
        let f = wave_format_extensible(2, 48_000, 32, MFAudioFormat_Float);
        // SAFETY: pointer into a live local of the exact declared shape.
        let m = unsafe { classify_mix_format((&f as *const WAVEFORMATEXTENSIBLE).cast()) }
            .expect("48k float stereo must be supported");
        assert_eq!(m.format, AudioFormat::DEFAULT);
        assert_eq!(m.sample_kind, SampleKind::F32);
        assert_eq!(m.block_align, 8);
    }

    #[test]
    fn classifies_extensible_16_bit_pcm() {
        let f = wave_format_extensible(1, 44_100, 16, MFAudioFormat_PCM);
        // SAFETY: as above.
        let m = unsafe { classify_mix_format((&f as *const WAVEFORMATEXTENSIBLE).cast()) }
            .expect("44.1k 16-bit mono must be supported");
        assert_eq!(m.format.sample_rate, 44_100);
        assert_eq!(m.format.channels, 1);
        assert_eq!(m.sample_kind, SampleKind::I16);
        assert_eq!(m.block_align, 2);
    }

    #[test]
    fn classifies_plain_non_extensible_formats() {
        let pcm = wave_format_ex(WAVE_FORMAT_PCM as u16, 2, 44_100, 16);
        // SAFETY: pointer into a live local WAVEFORMATEX; tag is not extensible
        // so nothing past the base struct is read.
        let m = unsafe { classify_mix_format(&pcm) }.expect("plain PCM must be supported");
        assert_eq!(m.sample_kind, SampleKind::I16);
        assert_eq!(m.block_align, 4);

        let flt = wave_format_ex(WAVE_FORMAT_IEEE_FLOAT, 2, 48_000, 32);
        // SAFETY: as above.
        let m = unsafe { classify_mix_format(&flt) }.expect("plain float must be supported");
        assert_eq!(m.sample_kind, SampleKind::F32);
    }

    #[test]
    fn refuses_a_five_point_one_endpoint() {
        // The headline case: six channels must be turned away, not folded.
        let f = wave_format_extensible(6, 48_000, 32, MFAudioFormat_Float);
        // SAFETY: pointer into a live local of the exact declared shape.
        let e = unsafe { classify_mix_format((&f as *const WAVEFORMATEXTENSIBLE).cast()) }
            .expect_err("5.1 must be refused");
        assert!(e.to_string().contains('6'), "{e}");
    }

    #[test]
    fn refuses_unsupported_sample_rates() {
        let f = wave_format_extensible(2, 96_000, 32, MFAudioFormat_Float);
        // SAFETY: pointer into a live local of the exact declared shape.
        assert!(
            unsafe { classify_mix_format((&f as *const WAVEFORMATEXTENSIBLE).cast()) }.is_err()
        );
    }

    #[test]
    fn refuses_unknown_sample_representations() {
        // 24-bit packed, ADPCM, and anything else exotic.
        let f = wave_format_extensible(2, 48_000, 24, windows::core::GUID::zeroed());
        // SAFETY: pointer into a live local of the exact declared shape.
        assert!(
            unsafe { classify_mix_format((&f as *const WAVEFORMATEXTENSIBLE).cast()) }.is_err()
        );

        let odd = wave_format_ex(0x0011, 2, 48_000, 4); // IMA ADPCM
                                                        // SAFETY: pointer into a live local WAVEFORMATEX.
        assert!(unsafe { classify_mix_format(&odd) }.is_err());
    }

    #[test]
    fn refuses_extensible_without_the_extension_bytes() {
        // A driver that sets the tag but not cbSize would otherwise have us
        // read a GUID off the end of its allocation.
        let mut f = wave_format_ex(WAVE_FORMAT_EXTENSIBLE, 2, 48_000, 32);
        f.cbSize = 0;
        // SAFETY: only the base struct is read on this path — that is what the
        // test asserts.
        let e = unsafe { classify_mix_format(&f) }.expect_err("must refuse");
        assert!(e.to_string().contains("22"), "{e}");
    }

    #[test]
    fn refuses_a_format_whose_bit_depth_contradicts_its_tag() {
        // Float with 16 bits per sample: reading it as f32 would halve the
        // frame count and pitch the stream down an octave.
        let f = wave_format_extensible(2, 48_000, 16, MFAudioFormat_Float);
        // SAFETY: pointer into a live local of the exact declared shape.
        assert!(
            unsafe { classify_mix_format((&f as *const WAVEFORMATEXTENSIBLE).cast()) }.is_err()
        );
    }

    #[test]
    fn refuses_a_null_format_pointer() {
        // SAFETY: null is explicitly handled before any dereference.
        assert!(unsafe { classify_mix_format(std::ptr::null()) }.is_err());
    }

    // ---- test tone -----------------------------------------------------------

    #[test]
    fn test_tone_generates_the_requested_frame_count() {
        let mut t = TestTone::new(AudioFormat::DEFAULT);
        let p = t.generate(480);
        assert_eq!(p.frames, 480);
        assert_eq!(p.pcm.len(), 480 * 2);
        assert!(!p.silent);
        assert!(!p.discontinuity);
        assert_eq!(t.frames_emitted(), 480);
    }

    #[test]
    fn test_tone_duplicates_the_sample_across_channels() {
        let mut t = TestTone::new(AudioFormat::DEFAULT);
        let p = t.generate(16);
        for pair in p.pcm.chunks_exact(2) {
            assert_eq!(pair[0], pair[1], "stereo test tone must be identical L/R");
        }
        let mut mono = TestTone::new(AudioFormat::new(48_000, 1).unwrap());
        assert_eq!(mono.generate(16).pcm.len(), 16);
    }

    #[test]
    fn test_tone_is_deterministic() {
        // The property the interop tests depend on.
        let mut a = TestTone::new(AudioFormat::DEFAULT);
        let mut b = TestTone::new(AudioFormat::DEFAULT);
        assert_eq!(a.generate(1000).pcm, b.generate(1000).pcm);
        // And splitting the request must not change the waveform.
        let mut c = TestTone::new(AudioFormat::DEFAULT);
        let mut d = TestTone::new(AudioFormat::DEFAULT);
        let split: Vec<i16> = c
            .generate(400)
            .pcm
            .into_iter()
            .chain(c.generate(600).pcm)
            .collect();
        assert_eq!(split, d.generate(1000).pcm);
    }

    #[test]
    fn test_tone_completes_one_cycle_at_the_expected_period() {
        // 480 Hz at 48 kHz is exactly 100 frames per cycle, so frame 0 and
        // frame 100 must be the same sample. This is what catches a phase step
        // computed against the wrong rate — the bug that makes a remote tone
        // come out at the wrong pitch.
        let mut t = TestTone::with_tone(AudioFormat::new(48_000, 1).unwrap(), 480.0, 1.0);
        let p = t.generate(201);
        assert_eq!(p.pcm[0], p.pcm[100]);
        assert_eq!(p.pcm[0], p.pcm[200]);
        // Quarter cycle is the positive peak.
        assert_eq!(p.pcm[25], 32767);
        // Three-quarters is the negative peak.
        assert_eq!(p.pcm[75], -32767);
    }

    #[test]
    fn test_tone_amplitude_is_clamped_and_zero_reads_as_silence() {
        let mut loud = TestTone::with_tone(AudioFormat::DEFAULT, 440.0, 99.0);
        let p = loud.generate(200);
        assert!(p.pcm.iter().all(|&s| (-32767..=32767).contains(&s)));

        let mut quiet = TestTone::with_tone(AudioFormat::DEFAULT, 440.0, 0.0);
        let p = quiet.generate(200);
        assert!(p.silent);
        assert!(p.pcm.iter().all(|&s| s == 0));
    }

    #[test]
    fn test_tone_reports_its_format_and_describes_itself_honestly() {
        let t = TestTone::new(AudioFormat::DEFAULT);
        assert_eq!(t.format(), AudioFormat::DEFAULT);
        let d = t.describe();
        // The description must make clear this is NOT system audio, or a
        // support log reading "audio working" would be actively misleading.
        assert!(d.contains("DIAGNOSTIC"), "{d}");
        assert!(d.contains("440"), "{d}");
    }

    #[test]
    fn test_tone_paces_itself_against_the_clock() {
        let mut t = TestTone::new(AudioFormat::DEFAULT);
        // Immediately after construction essentially no frames are due; the
        // source must say "nothing yet" rather than dump a buffer.
        let first = t.next_packet().expect("never fails");
        let emitted = first.map(|p| p.frames).unwrap_or(0);
        assert!(emitted < 4_800, "one poll produced {emitted} frames");
    }

    // ---- COM guard -----------------------------------------------------------

    #[test]
    fn com_mta_guard_initializes_and_releases() {
        let g = ComMta::enter().expect("MTA init should succeed for a normal user");
        drop(g);
        // Re-entering after release must also work — the ownership tracking is
        // the entire reason this guard exists rather than mfinit::MfThread.
        let g = ComMta::enter().expect("second MTA init should succeed");
        // And nesting must not double-uninitialize.
        let inner = ComMta::enter().expect("nested MTA init should succeed");
        drop(inner);
        drop(g);
    }
}

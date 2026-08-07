//! Media Foundation AAC-LC encoder.
//!
//! One CLSID, one sync MFT, one feed-then-drain loop — structurally the simple
//! half of [`crate::mf_encoder`], with none of the hardware selection, adapter
//! LUID matching or async-credit machinery. There is exactly one AAC encoder on
//! Windows, it is software, and it is fast enough that nobody has ever wanted a
//! hardware one for a 128 kbps stereo stream.
//!
//! Wired to nothing in this commit. A later commit connects it to
//! [`crate::audio_capture`] and the transport.
//!
//! # Two things here are worth reading before changing anything
//!
//! **The output type is enumerated, never assumed — and the enumeration is not
//! taken on trust either.** The documented accepted bitrates are
//! [`DOCUMENTED_BYTES_PER_SECOND`], but that list is a statement about the
//! encoder Microsoft shipped, not a contract every SKU honours. A hardcoded
//! `MF_MT_AUDIO_AVG_BYTES_PER_SECOND` that the local MFT happens not to offer
//! fails `SetOutputType` with `MF_E_INVALIDMEDIATYPE` — an error that says
//! nothing at all about the cause. So [`AacEncoder::new`] walks
//! `GetOutputAvailableType`, logs the whole enumeration at INFO, and picks with
//! [`choose_output_type`]. When a machine does something unexpected, the log
//! says what it offered.
//!
//! The trap underneath that: `SetInputType` runs first (see
//! [`AacEncoder::set_input_type`]) and this MFT is documented to constrain its
//! output enumeration to the installed input type — but *observed behaviour on a
//! real machine says otherwise*. With a 48 kHz stereo input type installed and
//! accepted, `GetOutputAvailableType` still enumerated 44.1 kHz **mono** types,
//! and the selection, which looked only at bitrate, picked one and got
//! `MF_E_INVALIDMEDIATYPE` (0xC00D36B4, "inconsistent") back from
//! `SetOutputType`. Ordering the calls correctly is necessary and not
//! sufficient. Every offer's `MF_MT_AUDIO_SAMPLES_PER_SECOND` and
//! `MF_MT_AUDIO_NUM_CHANNELS` are therefore checked against the input, a
//! mismatched type is never installed on any path, and if nothing matches the
//! encoder fails loudly naming both sides rather than guessing.
//!
//! **The `AudioSpecificConfig` is derived, not copied.** [`audio_specific_config`]
//! builds the two bytes the client's decoder needs as `MF_MT_USER_DATA` from the
//! bit layout in the spec, and the tests pin the result against the four known
//! answers. This is the highest-consequence, lowest-visibility part of the
//! feature: a wrong sample-rate index does not fail, it decodes at the wrong
//! speed, and a wrong channel config does not fail either, it decodes as noise
//! or mono. Neither produces an error anywhere in the pipeline.
//!
//! # Requirements on the caller
//!
//! Media Foundation must be started on the calling thread — hold a
//! [`crate::mfinit::MfThread`] for the encoder's whole lifetime. `MFCreateSample`
//! and `MFCreateMediaType` live in mfplat and require the platform to be up;
//! `CoCreateInstance` requires the apartment the same guard enters.

use std::mem::ManuallyDrop;

use directdesk_shared::{Error, Result};
use windows::Win32::Media::MediaFoundation::*;
use windows::Win32::System::Com::{CoCreateInstance, CLSCTX_INPROC_SERVER};

use crate::audio_capture::AudioFormat;

/// MPEG-4 audio object type for AAC Low Complexity — the only profile the
/// Windows AAC encoder produces and the only one this pipeline decodes.
/// ISO/IEC 14496-3, Table 1.17.
pub const AAC_OBJECT_TYPE_LC: u8 = 2;

/// The MPEG-4 `samplingFrequencyIndex` table, ISO/IEC 14496-3 Table 1.18.
///
/// Written out in full rather than as the two entries this pipeline can reach.
/// The index is a position in a fixed standard table; spelling the table out is
/// what makes [`audio_specific_config`] auditable against the spec instead of
/// two magic numbers that happen to work.
pub const MPEG4_SAMPLE_RATES: [u32; 13] = [
    96_000, 88_200, 64_000, 48_000, 44_100, 32_000, 24_000, 22_050, 16_000, 12_000, 11_025, 8_000,
    7_350,
];

/// `samplingFrequencyIndex` for a rate, or `None` if the rate has no index.
///
/// Pure. `None` is not reachable from a validated [`AudioFormat`] — both 48000
/// and 44100 are in the table — but it is returned rather than asserted so a
/// future format addition fails as an error rather than a panic.
pub fn sample_rate_index(hz: u32) -> Option<u8> {
    MPEG4_SAMPLE_RATES
        .iter()
        .position(|&r| r == hz)
        .map(|i| i as u8)
}

/// Build the 2-byte `AudioSpecificConfig` for `format`.
///
/// This is what the client hands its AAC decoder as `MF_MT_USER_DATA`: the
/// entire description of the stream, in sixteen bits.
///
/// Layout (ISO/IEC 14496-3 §1.6.2.1, then GASpecificConfig §4.4.1):
///
/// ```text
///   bits 15..11  audioObjectType        5 bits   = 2 (AAC LC)
///   bits 10..7   samplingFrequencyIndex 4 bits   = 3 (48k) or 4 (44.1k)
///   bits  6..3   channelConfiguration   4 bits   = 1 (mono) or 2 (stereo)
///   bit      2   frameLengthFlag        1 bit    = 0 (1024-sample frames)
///   bit      1   dependsOnCoreCoder     1 bit    = 0
///   bit      0   extensionFlag          1 bit    = 0
/// ```
///
/// `channelConfiguration` happens to equal the channel count for 1 and 2, which
/// is a coincidence of the table's first two entries and not a general rule —
/// it stops being true at 8 channels. Since this pipeline refuses everything
/// above stereo (see [`AudioFormat::new`]), the identity holds for every input
/// this function can receive, and the tests pin all four.
///
/// Pure, with the four results pinned in the tests below. If you change
/// anything here and a pinned constant moves, the constant is right and the
/// change is wrong.
pub fn audio_specific_config(format: AudioFormat) -> Result<[u8; 2]> {
    let sfi = sample_rate_index(format.sample_rate).ok_or_else(|| {
        Error::Encoder(format!(
            "{} Hz has no MPEG-4 samplingFrequencyIndex; cannot describe the \
             AAC stream to a decoder",
            format.sample_rate
        ))
    })?;
    if format.channels == 0 || format.channels > 2 {
        return Err(Error::Encoder(format!(
            "channelConfiguration is only derivable from the channel count up to \
             stereo; got {} channels",
            format.channels
        )));
    }
    let packed: u16 = ((AAC_OBJECT_TYPE_LC as u16 & 0x1F) << 11)
        | ((sfi as u16 & 0x0F) << 7)
        | ((format.channels & 0x0F) << 3);
    Ok([(packed >> 8) as u8, (packed & 0xFF) as u8])
}

/// The encoded rates the Windows AAC encoder MFT is *documented* to accept, in
/// bytes per second: 96, 128, 160 and 192 kbps.
///
/// Reference material for the log line and a sane default only. Nothing in this
/// module branches on it — see the module docs on why enumeration beats trust.
pub const DOCUMENTED_BYTES_PER_SECOND: [u32; 4] = [12_000, 16_000, 20_000, 24_000];

/// Default target: 16000 bytes/sec = 128 kbps.
///
/// Transparent enough for desktop audio (notification sounds, speech, the
/// occasional video) and a rounding error next to the 12 Mbps the video path
/// budgets. There is no case for spending less here and no audible case for
/// spending more.
pub const DEFAULT_BYTES_PER_SECOND: u32 = 16_000;

/// One entry of the MFT's `GetOutputAvailableType` enumeration, reduced to the
/// three attributes selection depends on.
///
/// The rate and channel count are carried alongside the bitrate because they
/// are not decoration: an output type whose sample rate or channel count
/// disagrees with the installed *input* type is refused by `SetOutputType` with
/// `MF_E_INVALIDMEDIATYPE`, and the error names nothing. Selecting on bitrate
/// alone is how a 44.1 kHz mono type gets chosen for a 48 kHz stereo input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OutputCandidate {
    /// `MF_MT_AUDIO_AVG_BYTES_PER_SECOND`, or 0 when the type does not declare one.
    pub bytes_per_second: u32,
    /// `MF_MT_AUDIO_SAMPLES_PER_SECOND`, or 0 when absent.
    pub sample_rate: u32,
    /// `MF_MT_AUDIO_NUM_CHANNELS`, or 0 when absent.
    pub channels: u32,
}

impl OutputCandidate {
    /// Whether this type can legally be installed against `input`.
    ///
    /// A missing attribute reads as 0 and therefore never matches, which is the
    /// intended direction: a type that cannot be checked is not installed.
    pub fn matches(&self, input: AudioFormat) -> bool {
        self.sample_rate == input.sample_rate && self.channels == input.channels as u32
    }
}

/// Render an enumeration for an error or log line.
fn describe_offers(available: &[OutputCandidate]) -> String {
    if available.is_empty() {
        return "nothing at all".to_string();
    }
    available
        .iter()
        .enumerate()
        .map(|(i, c)| {
            format!(
                "[{i}] {} kbps {} Hz x{}",
                kbps(c.bytes_per_second),
                c.sample_rate,
                c.channels
            )
        })
        .collect::<Vec<_>>()
        .join(", ")
}

/// Pick which enumerated output type to install for `input`.
///
/// Returns an index into `available` (what `GetOutputAvailableType` offered, in
/// enumeration order).
///
/// # The rate/channel filter comes first, and it is not negotiable
///
/// Only types whose `MF_MT_AUDIO_SAMPLES_PER_SECOND` and
/// `MF_MT_AUDIO_NUM_CHANNELS` equal `input`'s are eligible. The rest are not
/// ranked, not fallen back to, and not reachable by any path through this
/// function. An MFT that offers `[96 kbps 44100 Hz x1, 128 kbps 44100 Hz x1]`
/// for a 48 kHz stereo input is offering nothing usable, and saying so is the
/// whole job: installing one anyway is an `MF_E_INVALIDMEDIATYPE` out of
/// `SetOutputType` whose text explains none of this.
///
/// # Among the eligible ones
///
/// The **lowest offer at or above `target`** — the cheapest type that still
/// meets the quality we asked for. When no *matching* type reaches `target`,
/// the closest matching one (the highest below it) is used rather than failing:
/// a machine whose AAC encoder tops out at 96 kbps should stream audio at
/// 96 kbps, not stream none. Ties resolve to the lowest index so two runs on
/// one machine install the same type.
///
/// # When nothing matches
///
/// `Err`, naming the input format and the entire enumeration. A loud failure
/// beats a wrong selection: a mismatched output type that *were* somehow
/// accepted would produce a stream the client decodes at the wrong speed or as
/// noise, since the `AudioSpecificConfig` already sent describes `input`.
///
/// Pure, so the policy is testable without an MFT.
pub fn choose_output_type(
    available: &[OutputCandidate],
    input: AudioFormat,
    target: u32,
) -> Result<usize> {
    let matching: Vec<usize> = available
        .iter()
        .enumerate()
        .filter(|(_, c)| c.matches(input))
        .map(|(i, _)| i)
        .collect();

    if matching.is_empty() {
        return Err(Error::Encoder(format!(
            "the AAC encoder MFT offered no output type matching the input format \
             {}; it offered {}. Refusing to install a mismatched type — that is \
             exactly what fails SetOutputType with MF_E_INVALIDMEDIATYPE \
             (0xC00D36B4, \"inconsistent\")",
            input.label(),
            describe_offers(available)
        )));
    }

    let mut best_at_or_above: Option<usize> = None;
    let mut highest: Option<usize> = None;
    for &i in &matching {
        let v = available[i].bytes_per_second;
        if v >= target {
            let better = match best_at_or_above {
                None => true,
                Some(b) => v < available[b].bytes_per_second,
            };
            if better {
                best_at_or_above = Some(i);
            }
        }
        let taller = match highest {
            None => true,
            Some(h) => v > available[h].bytes_per_second,
        };
        if taller {
            highest = Some(i);
        }
    }
    // `matching` is non-empty, so `highest` is always `Some`; the `unwrap_or`
    // keeps that fact from being a panic if it ever stops being true.
    Ok(best_at_or_above.or(highest).unwrap_or(matching[0]))
}

/// bytes/sec to kbps, for log lines. Integer maths on purpose: every value in
/// play is a multiple of 125, so nothing is lost.
fn kbps(bytes_per_second: u32) -> u32 {
    bytes_per_second * 8 / 1000
}

/// AAC-LC encoder over the Media Foundation `AACMFTEncoder` transform.
pub struct AacEncoder {
    transform: IMFTransform,
    format: AudioFormat,
    /// What the MFT actually accepted, which may not be what was asked for —
    /// see [`choose_output_type`].
    bytes_per_second: u32,
    asc: [u8; 2],
    out_provides_samples: bool,
    out_buf_size: u32,
    /// Frames fed so far, the source of the sample timestamps. A monotonically
    /// derived timestamp (rather than a wall clock) is what keeps the encoder's
    /// notion of time exactly equal to the number of samples it has seen.
    frames_submitted: u64,
    started: bool,
}

impl AacEncoder {
    /// Build an AAC encoder for `format` targeting `target_bytes_per_second`.
    ///
    /// Media Foundation must already be started on this thread — see the module
    /// docs.
    pub fn new(format: AudioFormat, target_bytes_per_second: u32) -> Result<Self> {
        // The AAC MFT has no `CLSID_` prefix in the `windows` crate: the
        // constant is spelled `AACMFTEncoder`, verified against the binding
        // (Win32::Media::MediaFoundation), unlike its H.264 neighbours
        // `CLSID_MSH264DecoderMFT` / `CLSID_MSH264EncoderMFT`.
        //
        // SAFETY: plain COM activation of an in-process server.
        let transform: IMFTransform =
            unsafe { CoCreateInstance(&AACMFTEncoder, None, CLSCTX_INPROC_SERVER) }
                .map_err(enc_err("CoCreateInstance(AACMFTEncoder)"))?;

        let asc = audio_specific_config(format)?;

        let mut me = Self {
            transform,
            format,
            bytes_per_second: 0,
            asc,
            out_provides_samples: false,
            out_buf_size: 0,
            frames_submitted: 0,
            started: false,
        };

        me.set_input_type()?;
        me.negotiate_output_type(target_bytes_per_second)?;
        me.read_output_stream_info()?;
        me.begin_streaming()?;

        tracing::info!(
            asc = format!("{:02X} {:02X}", asc[0], asc[1]),
            "AAC-LC encoder ready ({}, {} kbps)",
            format.label(),
            kbps(me.bytes_per_second)
        );
        Ok(me)
    }

    /// The format this encoder was built for.
    pub fn format(&self) -> AudioFormat {
        self.format
    }

    /// The encoded rate the MFT settled on, in bytes per second. May differ
    /// from the target — see [`choose_output_type`].
    pub fn bytes_per_second(&self) -> u32 {
        self.bytes_per_second
    }

    /// The 2-byte `AudioSpecificConfig` describing this stream.
    ///
    /// The client needs exactly these bytes as `MF_MT_USER_DATA` before it can
    /// decode a single access unit, so they belong in whatever "audio starts
    /// now" message the transport eventually carries.
    pub fn audio_specific_config(&self) -> [u8; 2] {
        self.asc
    }

    /// Feed interleaved 16-bit PCM and take whatever access units come out.
    ///
    /// Zero or more: AAC codes 1024 samples per frame, so a 10 ms packet at
    /// 48 kHz (480 frames) usually produces nothing and every third or fourth
    /// one produces two. That is normal and not back-pressure.
    ///
    /// The returned buffers are raw AAC access units with no ADTS header, which
    /// is what `MF_MT_AAC_PAYLOAD_TYPE = 0` selects. The decoder is configured
    /// from the `AudioSpecificConfig`, so the seven bytes of per-frame ADTS
    /// header would be pure overhead on a link that is already the bottleneck.
    pub fn submit(&mut self, pcm: &[i16]) -> Result<Vec<Vec<u8>>> {
        let channels = self.format.channels as usize;
        if channels == 0 || !pcm.len().is_multiple_of(channels) {
            return Err(Error::Encoder(format!(
                "PCM length {} is not a whole number of {channels}-channel frames",
                pcm.len()
            )));
        }
        if pcm.is_empty() {
            return Ok(Vec::new());
        }

        let sample = self.build_sample(pcm)?;
        // SAFETY: sync MFT contract — feed one sample, then drain until it asks
        // for more input. MF_E_NOTACCEPTING means the MFT wants draining first,
        // which the loop below does; the sample is then re-offered.
        let accepted = unsafe { self.transform.ProcessInput(0, &sample, 0) };
        let mut out = Vec::new();
        match accepted {
            Ok(()) => {}
            Err(e) if e.code() == MF_E_NOTACCEPTING => {
                out.append(&mut self.drain_available()?);
                // SAFETY: as above; after a drain the MFT accepts input again.
                unsafe { self.transform.ProcessInput(0, &sample, 0) }
                    .map_err(enc_err("ProcessInput(after drain)"))?;
            }
            Err(e) => return Err(Error::Encoder(format!("ProcessInput: {e}"))),
        }
        self.frames_submitted += (pcm.len() / channels) as u64;

        out.append(&mut self.drain_available()?);
        Ok(out)
    }

    // ---- construction ---------------------------------------------------------

    /// Install the PCM input type.
    ///
    /// Set **before** the output type, and not interchangeably: the AAC MFT's
    /// list of available output types is derived from the input type, so
    /// `GetOutputAvailableType` before `SetInputType` enumerates nothing (or
    /// fails with `MF_E_TRANSFORM_TYPE_NOT_SET`). This is the opposite of the
    /// H.264 MFTs in [`crate::mf_encoder`], which require the output type first.
    ///
    /// Do not read that as a guarantee that the enumeration which follows is
    /// *constrained* to this type. It is not, at least not on every machine —
    /// see the module docs. The ordering buys a non-empty enumeration, nothing
    /// more; [`choose_output_type`] is what makes the result safe to install.
    fn set_input_type(&mut self) -> Result<()> {
        let rate = self.format.sample_rate;
        let channels = self.format.channels as u32;
        let block_align = channels * 2;

        // SAFETY: freshly created media type; every setter takes a static GUID
        // key and a plain scalar.
        unsafe {
            let t = MFCreateMediaType().map_err(enc_err("MFCreateMediaType(in)"))?;
            t.SetGUID(&MF_MT_MAJOR_TYPE, &MFMediaType_Audio).ok();
            t.SetGUID(&MF_MT_SUBTYPE, &MFAudioFormat_PCM).ok();
            t.SetUINT32(&MF_MT_AUDIO_BITS_PER_SAMPLE, 16).ok();
            t.SetUINT32(&MF_MT_AUDIO_SAMPLES_PER_SECOND, rate).ok();
            t.SetUINT32(&MF_MT_AUDIO_NUM_CHANNELS, channels).ok();
            t.SetUINT32(&MF_MT_AUDIO_BLOCK_ALIGNMENT, block_align).ok();
            t.SetUINT32(&MF_MT_AUDIO_AVG_BYTES_PER_SECOND, rate * block_align)
                .ok();
            t.SetUINT32(&MF_MT_ALL_SAMPLES_INDEPENDENT, 1).ok();
            // As in mf_encoder: the individual attribute setters are
            // `.ok()`-swallowed because an attribute store refusing a write
            // tells us nothing. SetInputType is the real gate.
            self.transform
                .SetInputType(0, &t, 0)
                .map_err(enc_err("SetInputType(PCM 16-bit)"))?;
        }
        Ok(())
    }

    /// Install the output type, warning if the MFT could not reach `target`.
    ///
    /// Runs strictly *after* [`Self::set_input_type`] — see that function, and
    /// [`Self::install_matching_output_type`] for why the ordering alone is not
    /// enough.
    fn negotiate_output_type(&mut self, target: u32) -> Result<()> {
        let rate = self.install_matching_output_type(target)?;
        if rate < target {
            tracing::warn!(
                "AAC encoder offers nothing at or above {} kbps for {}; using {} kbps",
                kbps(target),
                self.format.label(),
                kbps(rate)
            );
        }
        self.bytes_per_second = rate;
        Ok(())
    }

    /// Enumerate every output type the MFT offers, log them all against the
    /// input format, and install the one [`choose_output_type`] picks.
    ///
    /// Returns the installed `MF_MT_AUDIO_AVG_BYTES_PER_SECOND`.
    ///
    /// # The enumeration is not trustworthy on its own
    ///
    /// This runs after `SetInputType`, which is the documented order for this
    /// MFT — but the order is not sufficient. Observed on a real machine: with a
    /// 48 kHz stereo input type successfully installed, `GetOutputAvailableType`
    /// still enumerated 44.1 kHz *mono* types, and picking one on bitrate alone
    /// produced `MF_E_INVALIDMEDIATYPE` from `SetOutputType`. So the rate and
    /// channel count of each offer are read and matched against the input rather
    /// than assumed to already agree with it; see [`choose_output_type`].
    fn install_matching_output_type(&mut self, target: u32) -> Result<u32> {
        // SAFETY: live transform with an input type installed; enumeration ends
        // at MF_E_NO_MORE_TYPES.
        let types: Vec<IMFMediaType> = unsafe {
            let mut v = Vec::new();
            // Bounded rather than `0..`: an MFT that never returns
            // MF_E_NO_MORE_TYPES would otherwise spin until `i` overflows. The
            // real encoder offers a handful; 64 is far past any plausible list.
            for i in 0..64u32 {
                match self.transform.GetOutputAvailableType(0, i) {
                    Ok(t) => v.push(t),
                    Err(e) if e.code() == MF_E_NO_MORE_TYPES => break,
                    Err(e) => {
                        if v.is_empty() {
                            return Err(Error::Encoder(format!(
                                "GetOutputAvailableType(0, {i}): {e}"
                            )));
                        }
                        // Some types enumerated fine; a failure partway through
                        // is a reason to stop looking, not to give up.
                        tracing::warn!("AAC output type enumeration stopped at {i}: {e}");
                        break;
                    }
                }
            }
            v
        };

        if types.is_empty() {
            return Err(Error::Encoder(format!(
                "AAC encoder MFT offered no output types at all for input {}",
                self.format.label()
            )));
        }

        // SAFETY: types came from the MFT itself; a missing attribute reads as
        // `0`, which `OutputCandidate::matches` treats as "cannot be checked,
        // therefore not selectable".
        let candidates: Vec<OutputCandidate> = types
            .iter()
            .map(|t| unsafe {
                OutputCandidate {
                    bytes_per_second: t.GetUINT32(&MF_MT_AUDIO_AVG_BYTES_PER_SECOND).unwrap_or(0),
                    sample_rate: t.GetUINT32(&MF_MT_AUDIO_SAMPLES_PER_SECOND).unwrap_or(0),
                    channels: t.GetUINT32(&MF_MT_AUDIO_NUM_CHANNELS).unwrap_or(0),
                }
            })
            .collect();

        // The whole enumeration, at INFO, logged after the input type is set so
        // the list printed is the list actually being chosen from, and carrying
        // the input format so the two can be compared without a second log line.
        // When a machine refuses the bitrate we wanted, this is what says what it
        // offered instead — which beats an MF_E_INVALIDMEDIATYPE with no context.
        for (i, c) in candidates.iter().enumerate() {
            let verdict = if c.matches(self.format) {
                ""
            } else {
                "  <- MISMATCHES INPUT, not selectable"
            };
            tracing::info!(
                "AAC output type {i} for input {}: {} B/s ({} kbps), {} Hz x {}{verdict}",
                self.format.label(),
                c.bytes_per_second,
                kbps(c.bytes_per_second),
                c.sample_rate,
                c.channels
            );
        }

        let pick = choose_output_type(&candidates, self.format, target)?;

        // SAFETY: the type came from the MFT; the payload-type write is
        // advisory and SetOutputType is the gate.
        unsafe {
            let t = &types[pick];
            // 0 = raw AAC access units. 1 would be ADTS, whose 7-byte per-frame
            // header buys nothing here: the decoder is configured out of band
            // from the AudioSpecificConfig, and the datagram already delimits
            // the unit.
            t.SetUINT32(&MF_MT_AAC_PAYLOAD_TYPE, 0).ok();
            self.transform
                .SetOutputType(0, t, 0)
                .map_err(enc_err("SetOutputType(AAC)"))?;
        }
        Ok(candidates[pick].bytes_per_second)
    }

    fn read_output_stream_info(&mut self) -> Result<()> {
        // SAFETY: live transform with both types installed.
        unsafe {
            let info = self
                .transform
                .GetOutputStreamInfo(0)
                .map_err(enc_err("GetOutputStreamInfo"))?;
            let provides = MFT_OUTPUT_STREAM_PROVIDES_SAMPLES.0 as u32
                | MFT_OUTPUT_STREAM_CAN_PROVIDE_SAMPLES.0 as u32;
            self.out_provides_samples = info.dwFlags & provides != 0;
            // Generous floor: an AAC access unit at 192 kbps is well under 1 KB,
            // and a too-small buffer is an MF_E_BUFFERTOOSMALL on every frame.
            self.out_buf_size = info.cbSize.max(8192);
        }
        Ok(())
    }

    fn begin_streaming(&mut self) -> Result<()> {
        // SAFETY: live transform; the documented start sequence.
        unsafe {
            self.transform
                .ProcessMessage(MFT_MESSAGE_NOTIFY_BEGIN_STREAMING, 0)
                .map_err(enc_err("NOTIFY_BEGIN_STREAMING"))?;
            self.transform
                .ProcessMessage(MFT_MESSAGE_NOTIFY_START_OF_STREAM, 0)
                .map_err(enc_err("NOTIFY_START_OF_STREAM"))?;
        }
        self.started = true;
        Ok(())
    }

    // ---- the loop -------------------------------------------------------------

    fn build_sample(&self, pcm: &[i16]) -> Result<IMFSample> {
        let bytes = pcm.len() * 2;
        // SAFETY: MF object creation with checked results; the buffer length is
        // set to exactly what was written.
        unsafe {
            let sample = MFCreateSample().map_err(enc_err("MFCreateSample(in)"))?;
            let buf =
                MFCreateMemoryBuffer(bytes as u32).map_err(enc_err("MFCreateMemoryBuffer(in)"))?;
            let mut ptr: *mut u8 = std::ptr::null_mut();
            buf.Lock(&mut ptr, None, None)
                .map_err(enc_err("Lock(in buffer)"))?;
            // `&[i16]` is always suitably aligned to read as bytes (u8 has
            // alignment 1), and x86 is little-endian, which is the byte order
            // MF_MT_AUDIO PCM is defined in. This is a Windows-only crate, so
            // there is no big-endian case to handle.
            std::ptr::copy_nonoverlapping(pcm.as_ptr().cast::<u8>(), ptr, bytes);
            let _ = buf.Unlock();
            buf.SetCurrentLength(bytes as u32)
                .map_err(enc_err("SetCurrentLength(in)"))?;
            sample.AddBuffer(&buf).map_err(enc_err("AddBuffer(in)"))?;

            // Timestamps derived from the running frame count, not a clock:
            // the encoder's timeline must equal the number of samples it has
            // been given, or a scheduling hiccup on the capture thread turns
            // into drift the client can hear.
            let frames = (pcm.len() / self.format.channels.max(1) as usize) as u64;
            let _ = sample.SetSampleTime(self.hns_at(self.frames_submitted));
            let _ = sample.SetSampleDuration(
                self.hns_at(self.frames_submitted + frames) - self.hns_at(self.frames_submitted),
            );
            Ok(sample)
        }
    }

    /// Presentation time of frame `n`, in 100-ns units.
    ///
    /// Computed from the absolute frame index rather than by accumulating
    /// per-packet durations, so the rounding error stays bounded at one tick
    /// instead of growing with the length of the session — which is what makes
    /// 44.1 kHz (where 10 000 000 / 44 100 is not an integer) safe.
    fn hns_at(&self, frame: u64) -> i64 {
        (frame.saturating_mul(10_000_000) / self.format.sample_rate.max(1) as u64) as i64
    }

    /// Pull access units until the MFT asks for more input.
    fn drain_available(&mut self) -> Result<Vec<Vec<u8>>> {
        let mut out = Vec::new();
        loop {
            match self.process_output() {
                Ok(Some(au)) => out.push(au),
                Ok(None) => break,
                Err(e) => {
                    tracing::warn!("AAC ProcessOutput: {e}");
                    break;
                }
            }
        }
        Ok(out)
    }

    fn process_output(&mut self) -> Result<Option<Vec<u8>>> {
        let mut bufs = [MFT_OUTPUT_DATA_BUFFER {
            dwStreamID: 0,
            ..Default::default()
        }];

        // SAFETY: when the MFT does not allocate we supply a sample whose
        // buffer is at least `cbSize`; the ManuallyDrop fields are taken
        // exactly once below so refcounts stay balanced. Same shape as
        // mf_encoder::process_output.
        unsafe {
            if !self.out_provides_samples {
                let sample = MFCreateSample().map_err(enc_err("MFCreateSample(out)"))?;
                let buf = MFCreateMemoryBuffer(self.out_buf_size)
                    .map_err(enc_err("MFCreateMemoryBuffer(out)"))?;
                sample.AddBuffer(&buf).map_err(enc_err("AddBuffer(out)"))?;
                bufs[0].pSample = ManuallyDrop::new(Some(sample));
            }

            let mut status = 0u32;
            let res = self.transform.ProcessOutput(0, &mut bufs, &mut status);
            let sample = ManuallyDrop::take(&mut bufs[0].pSample);
            let events = ManuallyDrop::take(&mut bufs[0].pEvents);
            drop(events);

            match res {
                Ok(()) => {}
                Err(e) if e.code() == MF_E_TRANSFORM_NEED_MORE_INPUT => return Ok(None),
                Err(e) if e.code() == MF_E_TRANSFORM_STREAM_CHANGE => {
                    self.renegotiate_output()?;
                    return Ok(None);
                }
                Err(e) => return Err(Error::Encoder(format!("ProcessOutput: {e}"))),
            }

            let Some(sample) = sample else {
                return Ok(None);
            };
            let buffer = sample
                .ConvertToContiguousBuffer()
                .map_err(enc_err("ConvertToContiguousBuffer"))?;
            let mut ptr: *mut u8 = std::ptr::null_mut();
            let mut len = 0u32;
            buffer
                .Lock(&mut ptr, None, Some(&mut len))
                .map_err(enc_err("IMFMediaBuffer::Lock"))?;
            let au = std::slice::from_raw_parts(ptr, len as usize).to_vec();
            let _ = buffer.Unlock();

            if au.is_empty() {
                return Ok(None);
            }
            Ok(Some(au))
        }
    }

    /// Re-install an output type after `MF_E_TRANSFORM_STREAM_CHANGE`.
    ///
    /// Goes back through [`Self::install_matching_output_type`] rather than
    /// adopting `GetOutputAvailableType(0, 0)` wholesale, for the same reason
    /// construction does: entry 0 of that enumeration is not guaranteed to
    /// agree with the installed input type, and on the machine that motivated
    /// this it is 44.1 kHz mono. Adopting it mid-stream is worse than failing
    /// at startup — the `AudioSpecificConfig` describing the *old* format has
    /// already reached the client, so the receiver would decode the rest of the
    /// session at the wrong speed with no error anywhere.
    ///
    /// Re-stamping the payload type is part of the shared path too: the MFT's
    /// preferred type carries the MFT's attributes and not ours, and adopting
    /// it unstamped is how a stream silently acquires ADTS headers the client
    /// is not expecting.
    ///
    /// The current bitrate is passed as the target so the rate the session
    /// settled on is preserved where the MFT can still offer it, and re-read
    /// from what actually installed where it cannot.
    fn renegotiate_output(&mut self) -> Result<()> {
        let target = if self.bytes_per_second > 0 {
            self.bytes_per_second
        } else {
            DEFAULT_BYTES_PER_SECOND
        };
        let rate = self.install_matching_output_type(target)?;
        if rate != self.bytes_per_second {
            tracing::info!(
                "AAC output type changed mid-stream: {} -> {} kbps",
                kbps(self.bytes_per_second),
                kbps(rate)
            );
            self.bytes_per_second = rate;
        }
        self.read_output_stream_info()
    }

    /// Honest one-line description for the log and the status UI.
    pub fn describe(&self) -> String {
        format!(
            "MF AAC-LC — {} at {} kbps (raw access units)",
            self.format.label(),
            kbps(self.bytes_per_second)
        )
    }
}

/// # The tail is discarded, deliberately
///
/// `MFT_MESSAGE_COMMAND_FLUSH` below *drops* whatever the MFT is still holding
/// rather than `MFT_MESSAGE_COMMAND_DRAIN`ing it out, and that is the intended
/// behaviour rather than an oversight. AAC codes in fixed 1024-sample blocks,
/// so at most one block is ever buffered: 21 ms at 48 kHz, 23 ms at 44.1 kHz.
///
/// There were two places that tail could have been recovered and neither is
/// worth the code. At session end the host's `net::audio::audio_pump` thread is
/// being joined so the connection can close, and a datagram emitted into a closing
/// connection is a race, not a feature. On an endpoint rebuild (a headset
/// arriving mid-session) the samples predate the switch, the successor stream
/// already sets `FLAG_DISCONTINUITY` to tell the receiver to reset rather than
/// bridge, and 21 ms of pre-switch audio arriving after that flag is worse than
/// nothing.
///
/// A `pub fn drain()` doing the `COMMAND_DRAIN` half of this used to live here
/// with no caller anywhere in the workspace, which read as an oversight in the
/// send path rather than as a decision. Recovering the tail would mean lifting
/// `net::audio::pump`'s per-unit send body — sequence numbers, the access-unit
/// clock, the reserve check, the redundancy slot — out into something callable
/// twice, i.e. restructuring the verified packet path to buy one frame of audio
/// nobody hears. If that ever becomes worth doing, the missing piece is one
/// `ProcessMessage(MFT_MESSAGE_COMMAND_DRAIN, 0)` followed by
/// `drain_available()`.
impl Drop for AacEncoder {
    fn drop(&mut self) {
        if !self.started {
            return;
        }
        // SAFETY: mirror of begin_streaming(); teardown failures are ignored.
        unsafe {
            let _ = self
                .transform
                .ProcessMessage(MFT_MESSAGE_NOTIFY_END_OF_STREAM, 0);
            let _ = self
                .transform
                .ProcessMessage(MFT_MESSAGE_NOTIFY_END_STREAMING, 0);
            let _ = self.transform.ProcessMessage(MFT_MESSAGE_COMMAND_FLUSH, 0);
        }
    }
}

// SAFETY: the encoder is created on and used from a single media thread; it is
// only ever *moved* across threads, never shared. The MFT is a free-threaded
// (MTA) in-process object. Same reasoning as mf_encoder::MfH264Encoder.
unsafe impl Send for AacEncoder {}

// ---- helpers -----------------------------------------------------------------

fn enc_err(what: &'static str) -> impl Fn(windows::core::Error) -> Error {
    move |e| Error::Encoder(format!("{what}: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- AudioSpecificConfig: the pinned constants --------------------------
    //
    // These four byte pairs are the contract with the client's decoder. They are
    // written here as literals, derived independently in `audio_specific_config`,
    // and compared. If a change makes these disagree, the literals are right:
    // they come from the spec's bit layout, not from this implementation.

    #[test]
    fn asc_48k_stereo_is_11_90() {
        let f = AudioFormat::new(48_000, 2).unwrap();
        assert_eq!(audio_specific_config(f).unwrap(), [0x11, 0x90]);
    }

    #[test]
    fn asc_44100_stereo_is_12_10() {
        let f = AudioFormat::new(44_100, 2).unwrap();
        assert_eq!(audio_specific_config(f).unwrap(), [0x12, 0x10]);
    }

    #[test]
    fn asc_48k_mono_is_11_88() {
        let f = AudioFormat::new(48_000, 1).unwrap();
        assert_eq!(audio_specific_config(f).unwrap(), [0x11, 0x88]);
    }

    #[test]
    fn asc_44100_mono_is_12_08() {
        let f = AudioFormat::new(44_100, 1).unwrap();
        assert_eq!(audio_specific_config(f).unwrap(), [0x12, 0x08]);
    }

    #[test]
    fn every_supported_format_has_an_asc() {
        // No format the capture side can hand us may fail to be describable to
        // the decoder — that would be a stream nobody can play.
        for f in AudioFormat::SUPPORTED {
            audio_specific_config(f).unwrap_or_else(|e| panic!("{}: {e}", f.label()));
        }
    }

    #[test]
    fn asc_decodes_back_to_its_fields() {
        // Read the packed bits back out, so the test checks the *layout* and not
        // just four memorised numbers.
        for f in AudioFormat::SUPPORTED {
            let a = audio_specific_config(f).unwrap();
            let packed = u16::from_be_bytes(a);
            let object_type = (packed >> 11) & 0x1F;
            let sfi = ((packed >> 7) & 0x0F) as u8;
            let channel_config = (packed >> 3) & 0x0F;
            let ga_bits = packed & 0x07;
            assert_eq!(object_type, AAC_OBJECT_TYPE_LC as u16, "{}", f.label());
            assert_eq!(
                sfi,
                sample_rate_index(f.sample_rate).unwrap(),
                "{}",
                f.label()
            );
            assert_eq!(channel_config, f.channels, "{}", f.label());
            // frameLengthFlag / dependsOnCoreCoder / extensionFlag all zero:
            // 1024-sample frames, no core coder, no extension.
            assert_eq!(ga_bits, 0, "{}", f.label());
        }
    }

    #[test]
    fn asc_distinguishes_all_four_formats() {
        // If any two collided, one of the four would decode as the other — a
        // wrong-pitch or wrong-channel stream with no error anywhere.
        let mut seen = Vec::new();
        for f in AudioFormat::SUPPORTED {
            let a = audio_specific_config(f).unwrap();
            assert!(!seen.contains(&a), "{} collides: {a:02X?}", f.label());
            seen.push(a);
        }
        assert_eq!(seen.len(), 4);
    }

    // ---- sample rate index --------------------------------------------------

    #[test]
    fn sample_rate_index_matches_the_mpeg4_table() {
        assert_eq!(sample_rate_index(96_000), Some(0));
        assert_eq!(sample_rate_index(48_000), Some(3));
        assert_eq!(sample_rate_index(44_100), Some(4));
        assert_eq!(sample_rate_index(32_000), Some(5));
        assert_eq!(sample_rate_index(8_000), Some(11));
        assert_eq!(sample_rate_index(7_350), Some(12));
    }

    #[test]
    fn sample_rate_index_rejects_rates_outside_the_table() {
        assert_eq!(sample_rate_index(0), None);
        assert_eq!(sample_rate_index(48_001), None);
        assert_eq!(sample_rate_index(192_000), None);
    }

    #[test]
    fn the_mpeg4_table_is_strictly_descending() {
        // The table is fixed by the standard; a transposition would silently
        // change every ASC. Descending order is a cheap structural check on it.
        for w in MPEG4_SAMPLE_RATES.windows(2) {
            assert!(w[0] > w[1], "{w:?} out of order");
        }
        assert_eq!(MPEG4_SAMPLE_RATES.len(), 13);
    }

    // ---- output type selection ----------------------------------------------
    //
    // `choose_output_type` used to take `&[u32]` (bitrates alone) and return
    // `Option<usize>`. It now takes `&[OutputCandidate]` plus the input format
    // and returns `Result<usize>`, because bitrate alone is not enough to know
    // whether a type can legally be installed — see the live failure pinned in
    // `output_type_refuses_a_list_that_all_mismatches_the_input` below. The
    // bitrate-policy tests are unchanged in intent: they just build their
    // candidates at the input's own rate and channel count.

    /// The format every bitrate-policy test below is choosing for: 48 kHz stereo.
    const IN: AudioFormat = AudioFormat::DEFAULT;

    /// Candidates that all match [`IN`], so only the bitrate policy is in play.
    fn matching(rates: &[u32]) -> Vec<OutputCandidate> {
        rates
            .iter()
            .map(|&bytes_per_second| OutputCandidate {
                bytes_per_second,
                sample_rate: IN.sample_rate,
                channels: IN.channels as u32,
            })
            .collect()
    }

    /// One candidate, spelled out.
    fn offer(bytes_per_second: u32, sample_rate: u32, channels: u32) -> OutputCandidate {
        OutputCandidate {
            bytes_per_second,
            sample_rate,
            channels,
        }
    }

    #[test]
    fn output_type_picks_the_lowest_offer_at_or_above_the_target() {
        let offers = matching(&DOCUMENTED_BYTES_PER_SECOND);
        assert_eq!(choose_output_type(&offers, IN, 16_000).unwrap(), 1);
        assert_eq!(choose_output_type(&offers, IN, 12_000).unwrap(), 0);
        assert_eq!(choose_output_type(&offers, IN, 24_000).unwrap(), 3);
        // A target between two offers rounds *up*, never down.
        assert_eq!(choose_output_type(&offers, IN, 12_001).unwrap(), 1);
        assert_eq!(choose_output_type(&offers, IN, 19_999).unwrap(), 2);
        assert_eq!(choose_output_type(&offers, IN, 0).unwrap(), 0);
    }

    #[test]
    fn output_type_falls_back_to_the_closest_match_when_nothing_reaches_the_target() {
        // A machine whose encoder tops out low should stream audio, not refuse —
        // but only among types it could actually install.
        assert_eq!(
            choose_output_type(&matching(&[12_000, 16_000]), IN, 24_000).unwrap(),
            1
        );
        assert_eq!(
            choose_output_type(&matching(&[12_000]), IN, 999_999).unwrap(),
            0
        );
    }

    #[test]
    fn output_type_does_not_assume_the_offers_are_sorted() {
        // The whole point of enumerating is not trusting the shape of the list.
        let scrambled = matching(&[24_000, 12_000, 20_000, 16_000]);
        assert_eq!(choose_output_type(&scrambled, IN, 16_000).unwrap(), 3);
        assert_eq!(choose_output_type(&scrambled, IN, 21_000).unwrap(), 0);
        assert_eq!(choose_output_type(&scrambled, IN, 99_000).unwrap(), 0);
    }

    #[test]
    fn output_type_of_an_empty_enumeration_is_an_error() {
        // The MFT offered nothing. Nothing is not a candidate.
        assert!(choose_output_type(&[], IN, 16_000).is_err());
    }

    #[test]
    fn output_type_ignores_offers_with_no_declared_bitrate() {
        // A type whose MF_MT_AUDIO_AVG_BYTES_PER_SECOND is missing reads as 0
        // and must never be preferred over a real one.
        assert_eq!(
            choose_output_type(&matching(&[0, 16_000]), IN, 16_000).unwrap(),
            1
        );
        assert_eq!(
            choose_output_type(&matching(&[0, 12_000]), IN, 24_000).unwrap(),
            1
        );
        // If zero is genuinely all there is, it is still the answer — the type
        // is installable (its rate and channels match), it just does not say
        // what it costs. The caller gets a type and a warning, not no audio.
        assert_eq!(choose_output_type(&matching(&[0]), IN, 16_000).unwrap(), 0);
    }

    #[test]
    fn output_type_picks_the_first_of_equal_offers() {
        // Determinism matters: two runs on the same machine must install the
        // same type, or a bug reproduces only half the time.
        assert_eq!(
            choose_output_type(&matching(&[16_000, 16_000, 16_000]), IN, 16_000).unwrap(),
            0
        );
        assert_eq!(
            choose_output_type(&matching(&[8_000, 8_000]), IN, 99_999).unwrap(),
            0
        );
    }

    // ---- output type selection: the rate/channel filter ----------------------

    #[test]
    fn output_type_refuses_a_list_that_all_mismatches_the_input() {
        // The exact live failure this filter exists for, transcribed from the
        // host log: a 48 kHz stereo input, and an enumeration that offers only
        // 44.1 kHz mono. The old policy picked index 1 (16000 B/s reached the
        // 128 kbps target) and SetOutputType answered MF_E_INVALIDMEDIATYPE.
        // There is no correct choice here, so there must be no choice at all.
        let offers = [
            offer(12_000, 44_100, 1),
            offer(16_000, 44_100, 1),
            offer(20_000, 44_100, 1),
            offer(24_000, 44_100, 1),
        ];
        let err = choose_output_type(&offers, IN, 16_000)
            .expect_err("a mismatched enumeration must not yield a selection");

        // The message has to name both sides or it is the same undiagnosable
        // failure in different words.
        let msg = err.to_string();
        assert!(msg.contains("48000 Hz stereo"), "{msg}");
        assert!(msg.contains("44100"), "{msg}");
        assert!(msg.contains("128 kbps"), "{msg}");
    }

    #[test]
    fn output_type_refuses_a_near_miss_on_either_axis() {
        // Right rate, wrong channel count; then right channel count, wrong rate.
        // Neither is closer to acceptable than the other: both are refused.
        assert!(choose_output_type(&[offer(16_000, 48_000, 1)], IN, 16_000).is_err());
        assert!(choose_output_type(&[offer(16_000, 44_100, 2)], IN, 16_000).is_err());
        // And a type that declares neither attribute cannot be checked, so it
        // is not selectable either.
        assert!(choose_output_type(&[offer(16_000, 0, 0)], IN, 16_000).is_err());
    }

    #[test]
    fn output_type_prefers_a_matching_offer_over_a_better_mismatched_one() {
        // The mismatched 128 kbps type hits the target exactly and the matching
        // one does not reach it. The matching one still wins: an installable
        // type at the wrong bitrate is a stream, a mismatched type is an error.
        let offers = [offer(16_000, 44_100, 1), offer(12_000, 48_000, 2)];
        assert_eq!(choose_output_type(&offers, IN, 16_000).unwrap(), 1);
    }

    #[test]
    fn output_type_applies_the_bitrate_policy_only_within_the_matching_subset() {
        // Mismatched entries must not shift the index, the ranking, or the
        // "closest below target" fallback.
        let offers = [
            offer(24_000, 44_100, 1), // mismatch: highest bitrate in the list
            offer(12_000, 48_000, 2), // match
            offer(20_000, 48_000, 1), // mismatch: right rate, mono
            offer(16_000, 48_000, 2), // match, and exactly the target
            offer(24_000, 44_100, 2), // mismatch: right channels, wrong rate
        ];
        assert_eq!(choose_output_type(&offers, IN, 16_000).unwrap(), 3);
        assert_eq!(choose_output_type(&offers, IN, 12_000).unwrap(), 1);
        // Nothing matching reaches 24 kbps, so the closest match below wins —
        // *not* the 24 kbps mismatched entries that do reach it.
        assert_eq!(choose_output_type(&offers, IN, 24_000).unwrap(), 3);
    }

    #[test]
    fn output_type_matches_every_supported_format_against_itself() {
        // Each of the four formats must select its own type out of a list that
        // contains all four, and never a neighbour's.
        let offers: Vec<OutputCandidate> = AudioFormat::SUPPORTED
            .iter()
            .map(|f| offer(16_000, f.sample_rate, f.channels as u32))
            .collect();
        for (i, f) in AudioFormat::SUPPORTED.iter().enumerate() {
            assert_eq!(
                choose_output_type(&offers, *f, 16_000).unwrap(),
                i,
                "{} selected the wrong type",
                f.label()
            );
        }
    }

    #[test]
    fn candidate_match_is_exact_on_both_axes() {
        let c = offer(16_000, 48_000, 2);
        assert!(c.matches(IN));
        assert!(!c.matches(AudioFormat::new(44_100, 2).unwrap()));
        assert!(!c.matches(AudioFormat::new(48_000, 1).unwrap()));
    }

    #[test]
    fn the_offer_description_names_every_entry() {
        // This string is half of the error a user will paste into a bug report.
        assert_eq!(describe_offers(&[]), "nothing at all");
        let d = describe_offers(&[offer(12_000, 44_100, 1), offer(16_000, 48_000, 2)]);
        assert!(d.contains("[0] 96 kbps 44100 Hz x1"), "{d}");
        assert!(d.contains("[1] 128 kbps 48000 Hz x2"), "{d}");
    }

    // ---- misc ----------------------------------------------------------------

    #[test]
    fn documented_rates_are_the_familiar_kbps_values() {
        let as_kbps: Vec<u32> = DOCUMENTED_BYTES_PER_SECOND
            .iter()
            .copied()
            .map(kbps)
            .collect();
        assert_eq!(as_kbps, vec![96, 128, 160, 192]);
        assert_eq!(kbps(DEFAULT_BYTES_PER_SECOND), 128);
    }

    #[test]
    fn the_default_target_is_one_the_encoder_documents() {
        assert!(DOCUMENTED_BYTES_PER_SECOND.contains(&DEFAULT_BYTES_PER_SECOND));
        // And it is reachable by the selection policy on a documented MFT that
        // offers those rates at the format being encoded — for all four formats,
        // since any of them can turn up as the endpoint's mix format.
        for f in AudioFormat::SUPPORTED {
            let offers: Vec<OutputCandidate> = DOCUMENTED_BYTES_PER_SECOND
                .iter()
                .map(|&b| offer(b, f.sample_rate, f.channels as u32))
                .collect();
            let pick = choose_output_type(&offers, f, DEFAULT_BYTES_PER_SECOND)
                .unwrap_or_else(|e| panic!("{}: {e}", f.label()));
            assert_eq!(offers[pick].bytes_per_second, DEFAULT_BYTES_PER_SECOND);
        }
    }
}

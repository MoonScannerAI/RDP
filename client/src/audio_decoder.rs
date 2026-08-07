//! Media Foundation AAC-LC decoder for the client's system-audio path.
//!
//! Pipeline: one raw AAC-LC access unit ([`directdesk_shared::audio::AudioPacket::payload`])
//! → `CLSID_MSAACDecMFT` → interleaved 16-bit PCM at the *host's* rate and
//! channel count.
//!
//! Nothing in this module is wired up yet: there is no thread, no channel and
//! no negotiation. It is the codec half of the audio path, landed on its own so
//! the byte-level configuration can be reviewed and pinned before anything
//! depends on it.
//!
//! # Why the access unit is raw
//!
//! The wire format carries one bare AAC-LC access unit per datagram — no ADTS
//! header, no LATM framing (see [`directdesk_shared::audio`]). That saves 7
//! bytes per 20 ms, but more importantly it means the *stream* carries no
//! configuration at all: sample rate and channel count are not recoverable from
//! the payload. They arrive out of band, in the packet header's `format` byte,
//! and this decoder is constructed for one [`AudioFormat`]. A format change is a
//! new decoder, not a reconfiguration — see [`new_audio_decoder`].
//!
//! That is what makes [`MF_MT_USER_DATA`] load-bearing rather than optional:
//! it is the *only* place the decoder learns what it is decoding.
//!
//! # Threading
//!
//! COM and MF are initialized per thread by [`decoder::ensure_mf_initialized`],
//! reused rather than duplicated so the whole client has exactly one policy:
//! MTA, and deliberately never torn down. See that function's module docs.
//!
//! [`AudioFormat`]: directdesk_shared::audio::AudioFormat
//! [`MF_MT_USER_DATA`]: https://learn.microsoft.com/windows/win32/medfound/mf-mt-user-data-attribute
//! [`decoder::ensure_mf_initialized`]: crate::decoder

use directdesk_shared::audio::AudioFormat;
use directdesk_shared::error::{Error, Result};

// ---------------------------------------------------------------------------
// The decoder seam
// ---------------------------------------------------------------------------

/// Samples per channel in one AAC-LC access unit. Fixed by the codec: AAC-LC
/// has no `frameLengthFlag=1` short-frame mode in anything we emit, and the
/// zero bit is written as such by [`audio_specific_config`].
///
/// At 48 kHz that is 21.33 ms of audio per datagram, which is where the "one
/// access unit per packet, ~20 ms" figure in [`directdesk_shared::audio`] comes
/// from.
pub const AAC_FRAME_SAMPLES: usize = 1024;

/// Decode one AAC-LC access unit at a time into interleaved 16-bit PCM.
///
/// The seam exists for the same reason [`directdesk_shared::traits::Decoder`]'s
/// does: the playback loop must be testable without Media Foundation, an audio
/// endpoint, or a host. [`NullAudioDecoder`] is the headless implementation.
pub trait AudioDecode: Send {
    /// Feed exactly one access unit and drain whatever PCM it produced.
    ///
    /// Returns interleaved samples at [`AudioDecode::format`]'s rate and
    /// channel count. An empty vector is normal and not an error: the MFT
    /// buffers a frame or two before it emits anything.
    fn submit(&mut self, access_unit: &[u8]) -> Result<Vec<i16>>;

    /// Discard decoder state after a discontinuity.
    ///
    /// AAC-LC frames are independently decodable, so unlike the H.264 path
    /// there is no "wait for a keyframe" state to re-enter — the next access
    /// unit decodes cleanly on its own. What flushing buys is dropping the
    /// samples still inside the MFT, which belong *before* the gap and would
    /// otherwise be played after it.
    fn flush(&mut self);

    /// The format this decoder was built for. A packet carrying any other
    /// format code needs a different decoder.
    fn format(&self) -> AudioFormat;

    /// Human-readable description for logs and the self-test.
    fn describe(&self) -> String;
}

// ---------------------------------------------------------------------------
// AudioSpecificConfig (pure, platform independent, unit tested)
// ---------------------------------------------------------------------------

/// `audioObjectType` for AAC Low Complexity, ISO/IEC 14496-3 Table 1.17.
const AUDIO_OBJECT_TYPE_AAC_LC: u8 = 2;

/// ISO/IEC 14496-3 Table 1.18, `samplingFrequencyIndex`.
///
/// Index into this table *is* the 4-bit field; index 13/14 are reserved and 15
/// means "an explicit 24-bit frequency follows", which we never emit because
/// the wire format only carries the two rates below.
const SAMPLING_FREQUENCIES: [u32; 13] = [
    96_000, 88_200, 64_000, 48_000, 44_100, 32_000, 24_000, 22_050, 16_000, 12_000, 11_025, 8_000,
    7_350,
];

/// The 4-bit `samplingFrequencyIndex` for a rate, or `None` if the rate is not
/// one of the thirteen the table can name.
///
/// Returning `None` rather than falling back to the escape value (15) is
/// deliberate: the escape form makes the config 3 bytes instead of 2 and the
/// only rates this path can carry are 48 kHz and 44.1 kHz, both in the table.
/// A rate that lands here is a bug upstream, and a wrong-but-plausible config
/// would be heard as a pitch shift rather than seen as an error.
pub fn sampling_frequency_index(sample_rate: u32) -> Option<u8> {
    SAMPLING_FREQUENCIES
        .iter()
        .position(|&r| r == sample_rate)
        .map(|i| i as u8)
}

/// Build the 2-byte AAC-LC `AudioSpecificConfig`.
///
/// ISO/IEC 14496-3 §1.6.2.1, written MSB-first as a bitstream:
///
/// ```text
/// bits  field                    value
/// 5     audioObjectType          2  (AAC LC)
/// 4     samplingFrequencyIndex   3 for 48 kHz, 4 for 44.1 kHz
/// 4     channelConfiguration     1 (mono) or 2 (stereo)
/// 1     frameLengthFlag          0  (1024-sample frames)
/// 1     dependsOnCoreCoder       0
/// 1     extensionFlag            0
/// ```
///
/// Sixteen bits exactly, so the config is two bytes with no padding to reason
/// about. The three trailing zeros are the `GASpecificConfig` for AAC-LC and
/// are *not* optional — omitting them leaves a 13-bit config that the decoder
/// reads past the end of.
///
/// `channelConfiguration` 0 is legal in the spec (it means "the channel layout
/// is in the program config element") but not here: we have no PCE to point at,
/// and a decoder handed 0 with no PCE produces silence rather than an error.
pub fn audio_specific_config(sample_rate: u32, channels: u8) -> Result<[u8; 2]> {
    let freq_index = sampling_frequency_index(sample_rate).ok_or_else(|| {
        Error::Decoder(format!(
            "no AAC samplingFrequencyIndex for {sample_rate} Hz"
        ))
    })?;
    // 1..=7 are the standard layouts (mono, stereo, 3.0, 4.0, 5.0, 5.1, 7.1);
    // 0 needs a program config element and 8..=15 are reserved.
    if channels == 0 || channels > 7 {
        return Err(Error::Decoder(format!(
            "no AAC channelConfiguration for {channels} channels"
        )));
    }

    let mut bits: u16 = 0;
    bits |= u16::from(AUDIO_OBJECT_TYPE_AAC_LC) << 11; // bits 15..11
    bits |= u16::from(freq_index) << 7; // bits 10..7
    bits |= u16::from(channels) << 3; // bits  6..3
                                      // bits 2..0 stay zero: frameLengthFlag,
                                      // dependsOnCoreCoder, extensionFlag.

    // Big-endian: an AudioSpecificConfig is a bitstream, and bit 15 above is
    // the first bit on the wire.
    Ok(bits.to_be_bytes())
}

/// [`audio_specific_config`] for one of the four wire formats.
pub fn asc_for(format: AudioFormat) -> Result<[u8; 2]> {
    audio_specific_config(format.sample_rate(), format.channels())
}

// ---------------------------------------------------------------------------
// HEAACWAVEINFO tail + MF_MT_USER_DATA (pure, platform independent, tested)
// ---------------------------------------------------------------------------

/// The part of `HEAACWAVEINFO` that follows its `WAVEFORMATEX` member.
///
/// `MF_MT_USER_DATA` on the AAC decoder's *input* type is documented as "the
/// portion of the `HEAACWAVEINFO` structure that appears after the
/// `WAVEFORMATEX` structure, followed by the `AudioSpecificConfig()` data" —
/// i.e. this struct's twelve bytes, then [`audio_specific_config`].
///
/// The layout is verified against `windows::Win32::Media::DirectShow::HEAACWAVEINFO`
/// in the `windows` crate (0.62), which is `#[repr(C, packed(1))]` with exactly
/// these five fields in this order after `wfx`. That binding is not used
/// directly because reaching it would mean enabling the whole
/// `Win32_Media_DirectShow` feature for one POD struct; `size_of` is asserted
/// below and the bytes are pinned by a test, which is the same guarantee for
/// none of the compile time.
///
/// Getting this wrong is the single most consequential mistake available in
/// this feature. `SetInputType` validates the *length* of the blob loosely and
/// the *contents* not at all, so a tail that is short by two bytes shifts the
/// `AudioSpecificConfig` and the MFT reads a different object type and sample
/// rate than the one intended — which either fails to initialize with an
/// unhelpful `E_INVALIDARG`, or succeeds and plays garbage.
/// No `Debug`/`PartialEq` derives: they would take references to fields of a
/// packed struct, which is not allowed. `Copy` is what the by-value field reads
/// in [`HeAacWaveInfoTail::to_bytes`] need.
#[repr(C, packed(1))]
#[derive(Clone, Copy)]
struct HeAacWaveInfoTail {
    /// 0 = raw AAC (the payload is bare access units, configured out of band —
    /// which is exactly our wire format), 1 = ADTS, 2 = ADIF, 3 = LOAS/LATM.
    w_payload_type: u16,
    /// ISO/IEC 14496-3 Table 1.13 `audioProfileLevelIndication`. Informational
    /// for the decoder, which takes the real parameters from the
    /// `AudioSpecificConfig`; 0xFE would mean "unspecified".
    w_audio_profile_level_indication: u16,
    /// Documented as "must be zero".
    w_struct_type: u16,
    w_reserved1: u16,
    dw_reserved2: u32,
}

/// If this ever stops being 12, `MF_MT_USER_DATA` starts carrying a
/// misaligned `AudioSpecificConfig` and the failure is audible, not diagnostic.
const _: () = assert!(std::mem::size_of::<HeAacWaveInfoTail>() == 12);

/// Byte length of the `HEAACWAVEINFO` tail that precedes the config blob.
pub const HEAAC_TAIL_LEN: usize = 12;

/// Raw AAC: the payload is bare access units with no in-band header.
const AAC_PAYLOAD_TYPE_RAW: u16 = 0;

/// "AAC Profile, Level 2" — the profile every rate/channel combination on this
/// path fits inside. The decoder does not act on it, but leaving it unspecified
/// (0xFE) has been observed to make some third-party demuxers guess, so we say
/// what we mean.
const AAC_PROFILE_LEVEL_L2: u16 = 0x29;

impl HeAacWaveInfoTail {
    /// The tail we always send: raw access units, AAC-LC profile L2, reserved
    /// fields zero.
    const fn raw_aac_lc() -> Self {
        Self {
            w_payload_type: AAC_PAYLOAD_TYPE_RAW,
            w_audio_profile_level_indication: AAC_PROFILE_LEVEL_L2,
            w_struct_type: 0,
            w_reserved1: 0,
            dw_reserved2: 0,
        }
    }

    /// Serialize field by field, little-endian, in declaration order.
    ///
    /// Written out rather than transmuted: a `#[repr(C, packed)]` struct is
    /// only byte-identical to the C one if the compiler agrees about padding,
    /// and asserting that in prose is how the two-bytes-short bug above gets
    /// written. Twelve explicit `to_le_bytes` calls cannot drift.
    fn to_bytes(self) -> [u8; HEAAC_TAIL_LEN] {
        let mut out = [0u8; HEAAC_TAIL_LEN];
        out[0..2].copy_from_slice(&self.w_payload_type.to_le_bytes());
        out[2..4].copy_from_slice(&self.w_audio_profile_level_indication.to_le_bytes());
        out[4..6].copy_from_slice(&self.w_struct_type.to_le_bytes());
        out[6..8].copy_from_slice(&self.w_reserved1.to_le_bytes());
        out[8..12].copy_from_slice(&self.dw_reserved2.to_le_bytes());
        out
    }
}

/// The complete `MF_MT_USER_DATA` blob for the AAC decoder's input type:
/// the twelve-byte `HEAACWAVEINFO` tail followed by the `AudioSpecificConfig`.
///
/// Fourteen bytes for every format we support.
pub fn aac_user_data(format: AudioFormat) -> Result<Vec<u8>> {
    let asc = asc_for(format)?;
    let mut blob = Vec::with_capacity(HEAAC_TAIL_LEN + asc.len());
    blob.extend_from_slice(&HeAacWaveInfoTail::raw_aac_lc().to_bytes());
    blob.extend_from_slice(&asc);
    Ok(blob)
}

// ---------------------------------------------------------------------------
// PCM byte plumbing (pure, platform independent, unit tested)
// ---------------------------------------------------------------------------

/// Append little-endian 16-bit PCM bytes to `out` as samples.
///
/// Rejects an odd-length input instead of dropping the trailing byte. A half
/// sample means the MFT handed back a buffer length that is not a whole number
/// of samples, which is not a condition to paper over: silently dropping the
/// byte would rotate every subsequent sample's channel assignment, turning a
/// one-off into permanently swapped stereo.
pub fn append_pcm_le(bytes: &[u8], out: &mut Vec<i16>) -> Result<()> {
    if !bytes.len().is_multiple_of(2) {
        return Err(Error::Decoder(format!(
            "PCM buffer is {} bytes — not a whole number of 16-bit samples",
            bytes.len()
        )));
    }
    out.reserve(bytes.len() / 2);
    out.extend(
        bytes
            .chunks_exact(2)
            .map(|c| i16::from_le_bytes([c[0], c[1]])),
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// Media Foundation implementation
// ---------------------------------------------------------------------------

#[cfg(windows)]
mod mf {
    use super::*;

    use std::mem::ManuallyDrop;

    use windows::core::HRESULT;
    use windows::Win32::Media::MediaFoundation::*;
    use windows::Win32::System::Com::{CoCreateInstance, CLSCTX_INPROC_SERVER};

    use crate::decoder::ensure_mf_initialized;

    /// The MFT cannot take more input until output is drained.
    const MF_E_NOTACCEPTING_HR: HRESULT = HRESULT(0xC00D_36B5_u32 as i32);

    /// Bits per PCM sample. The Microsoft AAC decoder emits 16-bit integer PCM
    /// and nothing else, so this is a fact about the MFT, not a preference.
    const PCM_BITS: u32 = 16;
    const PCM_BYTES: usize = (PCM_BITS / 8) as usize;

    /// Media Foundation AAC-LC decoder.
    ///
    /// One instance decodes one [`AudioFormat`]. The wire format allows the
    /// host to change format mid-session (see [`directdesk_shared::audio`]), and
    /// the response to that is a new decoder — an MFT's input type cannot be
    /// changed while it is streaming, and tearing one down costs less than a
    /// millisecond against a path that is already buffering tens of them.
    pub struct MfAacDecoder {
        transform: IMFTransform,
        format: AudioFormat,
        provides_samples: bool,
        out_sample_bytes: u32,
        out_sample: Option<IMFSample>,
        frames_in: u64,
        samples_out: u64,
    }

    // SAFETY: every MF object here is created and used through this struct
    // only, and `ensure_mf_initialized` runs on entry to `new` and `submit`,
    // so whichever thread owns the decoder has COM initialized as MTA. MTA
    // objects may legally be called from any MTA thread, so transferring
    // ownership (which is all `Send` permits) is sound. This is the same
    // argument, and the same guarantee, as `crate::decoder::MfH264Decoder`.
    unsafe impl Send for MfAacDecoder {}

    impl MfAacDecoder {
        pub fn new(format: AudioFormat) -> Result<Self> {
            ensure_mf_initialized()?;

            let user_data = aac_user_data(format)?;
            let rate = format.sample_rate();
            let channels = u32::from(format.channels());

            // SAFETY: all calls below are on freshly created MF objects with
            // correctly typed arguments; failures come back as HRESULTs.
            unsafe {
                let transform: IMFTransform =
                    CoCreateInstance(&CLSID_MSAACDecMFT, None, CLSCTX_INPROC_SERVER).map_err(
                        |e| Error::Decoder(format!("CoCreateInstance(AAC decoder): {e}")),
                    )?;

                let input = MFCreateMediaType()
                    .map_err(|e| Error::Decoder(format!("MFCreateMediaType(in): {e}")))?;
                input
                    .SetGUID(&MF_MT_MAJOR_TYPE, &MFMediaType_Audio)
                    .map_err(|e| Error::Decoder(format!("set audio major type: {e}")))?;
                input
                    .SetGUID(&MF_MT_SUBTYPE, &MFAudioFormat_AAC)
                    .map_err(|e| Error::Decoder(format!("set AAC subtype: {e}")))?;
                input
                    .SetUINT32(&MF_MT_AUDIO_SAMPLES_PER_SECOND, rate)
                    .map_err(|e| Error::Decoder(format!("set input sample rate: {e}")))?;
                input
                    .SetUINT32(&MF_MT_AUDIO_NUM_CHANNELS, channels)
                    .map_err(|e| Error::Decoder(format!("set input channels: {e}")))?;
                input
                    .SetUINT32(&MF_MT_AUDIO_BITS_PER_SAMPLE, PCM_BITS)
                    .map_err(|e| Error::Decoder(format!("set input bits per sample: {e}")))?;
                // These two duplicate the first two fields of the user data
                // blob. They are optional, and they are set from the *same*
                // constants so the two statements of the same fact cannot drift
                // apart — a decoder that believes the attributes over the blob
                // and one that believes the blob must agree.
                input
                    .SetUINT32(&MF_MT_AAC_PAYLOAD_TYPE, u32::from(AAC_PAYLOAD_TYPE_RAW))
                    .map_err(|e| Error::Decoder(format!("set AAC payload type: {e}")))?;
                input
                    .SetUINT32(
                        &MF_MT_AAC_AUDIO_PROFILE_LEVEL_INDICATION,
                        u32::from(AAC_PROFILE_LEVEL_L2),
                    )
                    .map_err(|e| Error::Decoder(format!("set AAC profile level: {e}")))?;
                // The line everything else depends on. See `aac_user_data`.
                input
                    .SetBlob(&MF_MT_USER_DATA, &user_data)
                    .map_err(|e| Error::Decoder(format!("set MF_MT_USER_DATA: {e}")))?;
                transform
                    .SetInputType(0, &input, 0)
                    .map_err(|e| Error::Decoder(format!("SetInputType(AAC): {e}")))?;

                let mut decoder = Self {
                    transform,
                    format,
                    provides_samples: false,
                    out_sample_bytes: 0,
                    out_sample: None,
                    frames_in: 0,
                    samples_out: 0,
                };
                decoder.configure_output()?;

                decoder
                    .transform
                    .ProcessMessage(MFT_MESSAGE_NOTIFY_BEGIN_STREAMING, 0)
                    .map_err(|e| Error::Decoder(format!("BEGIN_STREAMING: {e}")))?;
                decoder
                    .transform
                    .ProcessMessage(MFT_MESSAGE_NOTIFY_START_OF_STREAM, 0)
                    .map_err(|e| Error::Decoder(format!("START_OF_STREAM: {e}")))?;

                tracing::info!(
                    "Media Foundation AAC-LC decoder ready: {} Hz, {} ch",
                    rate,
                    channels
                );
                Ok(decoder)
            }
        }

        pub fn frames_decoded(&self) -> u64 {
            self.frames_in
        }

        pub fn samples_produced(&self) -> u64 {
            self.samples_out
        }

        /// Select 16-bit PCM output at the input's rate and channel count.
        ///
        /// Tries the explicitly constructed type first, because that is the
        /// contract the MFT documents, and falls back to whatever PCM type it
        /// offers if a build disagrees about some attribute we did not think to
        /// set. The fallback is verified to still be PCM before it is accepted;
        /// silently taking a float type would produce noise at 4x the volume.
        ///
        /// # Safety
        /// Requires an initialized MF apartment on the calling thread.
        unsafe fn configure_output(&mut self) -> Result<()> {
            let rate = self.format.sample_rate();
            let channels = u32::from(self.format.channels());
            let block_align = channels * PCM_BYTES as u32;

            // SAFETY: building a media type with correctly typed arguments;
            // every failure comes back as an HRESULT.
            let constructed = unsafe {
                let ty = MFCreateMediaType()
                    .map_err(|e| Error::Decoder(format!("MFCreateMediaType(out): {e}")))?;
                ty.SetGUID(&MF_MT_MAJOR_TYPE, &MFMediaType_Audio)
                    .map_err(|e| Error::Decoder(format!("set audio major type: {e}")))?;
                ty.SetGUID(&MF_MT_SUBTYPE, &MFAudioFormat_PCM)
                    .map_err(|e| Error::Decoder(format!("set PCM subtype: {e}")))?;
                ty.SetUINT32(&MF_MT_AUDIO_SAMPLES_PER_SECOND, rate)
                    .map_err(|e| Error::Decoder(format!("set output sample rate: {e}")))?;
                ty.SetUINT32(&MF_MT_AUDIO_NUM_CHANNELS, channels)
                    .map_err(|e| Error::Decoder(format!("set output channels: {e}")))?;
                ty.SetUINT32(&MF_MT_AUDIO_BITS_PER_SAMPLE, PCM_BITS)
                    .map_err(|e| Error::Decoder(format!("set output bits per sample: {e}")))?;
                ty.SetUINT32(&MF_MT_AUDIO_BLOCK_ALIGNMENT, block_align)
                    .map_err(|e| Error::Decoder(format!("set output block alignment: {e}")))?;
                ty.SetUINT32(&MF_MT_AUDIO_AVG_BYTES_PER_SECOND, rate * block_align)
                    .map_err(|e| Error::Decoder(format!("set output byte rate: {e}")))?;
                ty
            };

            // SAFETY: setting a type we just built, on stream 0 of our MFT.
            match unsafe { self.transform.SetOutputType(0, &constructed, 0) } {
                Ok(()) => {}
                Err(first) => {
                    tracing::warn!(
                        "AAC MFT rejected the constructed PCM output type ({first}); \
                         falling back to enumeration"
                    );
                    // SAFETY: index-based enumeration; ends with an error.
                    let picked = unsafe { self.first_pcm_output_type() }?;
                    // SAFETY: setting a type the MFT itself offered.
                    unsafe { self.transform.SetOutputType(0, &picked, 0) }.map_err(|e| {
                        Error::Decoder(format!(
                            "SetOutputType(PCM): constructed failed with {first}, \
                             enumerated failed with {e}"
                        ))
                    })?;
                }
            }

            // SAFETY: stream info is valid once the types are negotiated.
            let info = unsafe { self.transform.GetOutputStreamInfo(0) }
                .map_err(|e| Error::Decoder(format!("GetOutputStreamInfo: {e}")))?;
            let provides = MFT_OUTPUT_STREAM_PROVIDES_SAMPLES.0 as u32
                | MFT_OUTPUT_STREAM_CAN_PROVIDE_SAMPLES.0 as u32;
            self.provides_samples = info.dwFlags & provides != 0;
            // Floor: two AAC frames' worth. AAC-LC emits 1024 samples per
            // channel per frame; the doubling is slack for an MFT that batches
            // two frames into one output sample, which costs 4 KiB and removes
            // a whole class of "output buffer too small" failure.
            let floor =
                (2 * AAC_FRAME_SAMPLES * self.format.channels() as usize * PCM_BYTES) as u32;
            self.out_sample_bytes = info.cbSize.max(floor);
            self.out_sample = None;
            tracing::debug!(
                "AAC MFT output: provides_samples={} cbSize={} using={}",
                self.provides_samples,
                info.cbSize,
                self.out_sample_bytes
            );
            Ok(())
        }

        /// # Safety
        /// Requires an initialized MF apartment.
        unsafe fn first_pcm_output_type(&self) -> Result<IMFMediaType> {
            let mut index = 0u32;
            // SAFETY: index-based enumeration; ends with an error HRESULT.
            while let Ok(ty) = unsafe { self.transform.GetOutputAvailableType(0, index) } {
                // SAFETY: `ty` is a valid media type from the MFT.
                let is_pcm = unsafe { ty.GetGUID(&MF_MT_SUBTYPE) }
                    .map(|g| g == MFAudioFormat_PCM)
                    .unwrap_or(false);
                if is_pcm {
                    return Ok(ty);
                }
                index += 1;
                if index > 32 {
                    break;
                }
            }
            Err(Error::Decoder("AAC MFT offers no PCM output type".into()))
        }

        /// A reusable, zero-length output sample.
        ///
        /// # Safety
        /// Requires an initialized MF apartment.
        unsafe fn acquire_out_sample(&mut self) -> Result<IMFSample> {
            if let Some(sample) = self.out_sample.take() {
                // SAFETY: our own sample, always built with exactly one buffer.
                if let Ok(buffer) = unsafe { sample.GetBufferByIndex(0) } {
                    // SAFETY: resetting length on a buffer we own.
                    if unsafe { buffer.SetCurrentLength(0) }.is_ok() {
                        return Ok(sample);
                    }
                }
            }
            let size = self.out_sample_bytes.max(1);
            // SAFETY: plain MF allocation calls.
            unsafe {
                let buffer = MFCreateMemoryBuffer(size)
                    .map_err(|e| Error::Decoder(format!("MFCreateMemoryBuffer({size}): {e}")))?;
                let sample =
                    MFCreateSample().map_err(|e| Error::Decoder(format!("MFCreateSample: {e}")))?;
                sample
                    .AddBuffer(&buffer)
                    .map_err(|e| Error::Decoder(format!("AddBuffer: {e}")))?;
                Ok(sample)
            }
        }

        /// # Safety
        /// Requires an initialized MF apartment.
        unsafe fn make_input_sample(&mut self, data: &[u8]) -> Result<IMFSample> {
            // SAFETY: buffer is sized to `data`, locked, filled, unlocked.
            unsafe {
                let buffer = MFCreateMemoryBuffer(data.len() as u32)
                    .map_err(|e| Error::Decoder(format!("MFCreateMemoryBuffer: {e}")))?;
                let mut ptr: *mut u8 = std::ptr::null_mut();
                buffer
                    .Lock(&mut ptr, None, None)
                    .map_err(|e| Error::Decoder(format!("buffer Lock: {e}")))?;
                std::ptr::copy_nonoverlapping(data.as_ptr(), ptr, data.len());
                let _ = buffer.Unlock();
                buffer
                    .SetCurrentLength(data.len() as u32)
                    .map_err(|e| Error::Decoder(format!("SetCurrentLength: {e}")))?;

                let sample =
                    MFCreateSample().map_err(|e| Error::Decoder(format!("MFCreateSample: {e}")))?;
                sample
                    .AddBuffer(&buffer)
                    .map_err(|e| Error::Decoder(format!("AddBuffer: {e}")))?;
                // No SetSampleTime: nothing downstream of here reads an MF
                // timestamp. Presentation time comes from the packet header's
                // `capture_ms`, which the jitter buffer already owns, and
                // stamping a second clock here would create two answers to the
                // same question.
                Ok(sample)
            }
        }

        /// Pull every ready PCM buffer out of the MFT.
        ///
        /// # Safety
        /// Requires an initialized MF apartment.
        unsafe fn drain_outputs(&mut self, out: &mut Vec<i16>) -> Result<()> {
            let transform = self.transform.clone();
            loop {
                let supplied = if self.provides_samples {
                    None
                } else {
                    // SAFETY: MF apartment is live for the whole call.
                    Some(unsafe { self.acquire_out_sample()? })
                };

                let mut buffers = [MFT_OUTPUT_DATA_BUFFER {
                    dwStreamID: 0,
                    pSample: ManuallyDrop::new(supplied),
                    dwStatus: 0,
                    pEvents: ManuallyDrop::new(None),
                }];
                let mut status = 0u32;
                // SAFETY: one correctly initialized output buffer descriptor.
                let result = unsafe { transform.ProcessOutput(0, &mut buffers, &mut status) };
                // SAFETY: taking ownership back exactly once; `buffers` is not
                // read again afterwards.
                let produced = unsafe { ManuallyDrop::take(&mut buffers[0].pSample) };
                // SAFETY: same, for the (unused) event collection.
                drop(unsafe { ManuallyDrop::take(&mut buffers[0].pEvents) });

                match result {
                    Ok(()) => {
                        if let Some(sample) = produced {
                            // SAFETY: a PCM sample matching the current type.
                            let appended = unsafe { self.append_sample(&sample, out) };
                            if let Err(e) = appended {
                                tracing::warn!("dropping undecodable audio output: {e}");
                            }
                            if !self.provides_samples {
                                self.out_sample = Some(sample); // recycle
                            }
                        }
                    }
                    Err(e) if e.code() == MF_E_TRANSFORM_NEED_MORE_INPUT => break,
                    Err(e) if e.code() == MF_E_TRANSFORM_STREAM_CHANGE => {
                        drop(produced);
                        // The MFT renegotiating its own output. Our input type
                        // is fixed for this decoder's lifetime, so this can only
                        // be a restatement of the same PCM type; re-select it
                        // and carry on rather than tearing the stream down.
                        // SAFETY: renegotiating on the same initialized thread.
                        unsafe { self.configure_output() }?;
                        tracing::info!("AAC MFT output type renegotiated");
                        continue;
                    }
                    Err(e) => {
                        drop(produced);
                        return Err(Error::Decoder(format!("ProcessOutput: {e}")));
                    }
                }
            }
            Ok(())
        }

        /// # Safety
        /// `sample` must be a PCM output sample matching the current type.
        unsafe fn append_sample(&mut self, sample: &IMFSample, out: &mut Vec<i16>) -> Result<()> {
            // SAFETY: contiguous view of the sample's buffers, then locked for
            // the duration of the copy and unlocked on every path below.
            let buffer = unsafe { sample.ConvertToContiguousBuffer() }
                .map_err(|e| Error::Decoder(format!("ConvertToContiguousBuffer: {e}")))?;

            let mut ptr: *mut u8 = std::ptr::null_mut();
            let mut current: u32 = 0;
            // SAFETY: Lock hands back a pointer valid until Unlock.
            unsafe { buffer.Lock(&mut ptr, None, Some(&mut current)) }
                .map_err(|e| Error::Decoder(format!("output Lock: {e}")))?;
            // SAFETY: `ptr`/`current` describe the locked region.
            let bytes = unsafe { std::slice::from_raw_parts(ptr, current as usize) };
            let before = out.len();
            let appended = append_pcm_le(bytes, out);
            // SAFETY: matching Unlock for the Lock above; runs on both paths.
            let _ = unsafe { buffer.Unlock() };

            appended?;
            self.samples_out += (out.len() - before) as u64;
            Ok(())
        }
    }

    impl AudioDecode for MfAacDecoder {
        fn submit(&mut self, access_unit: &[u8]) -> Result<Vec<i16>> {
            ensure_mf_initialized()?;
            if access_unit.is_empty() {
                return Err(Error::Decoder("empty AAC access unit".into()));
            }
            self.frames_in += 1;

            // One AAC-LC frame is 1024 samples per channel; sizing the vector
            // for exactly that keeps the steady state allocation-free.
            let mut out = Vec::with_capacity(AAC_FRAME_SAMPLES * self.format.channels() as usize);

            // SAFETY: MF is initialized on this thread (checked above); every
            // call below uses objects owned by this struct.
            unsafe {
                let sample = self.make_input_sample(access_unit)?;
                let transform = self.transform.clone();
                match transform.ProcessInput(0, &sample, 0) {
                    Ok(()) => {}
                    Err(e) if e.code() == MF_E_NOTACCEPTING_HR => {
                        // Backed up: drain, then the input must be accepted.
                        self.drain_outputs(&mut out)?;
                        transform.ProcessInput(0, &sample, 0).map_err(|e| {
                            Error::Decoder(format!("ProcessInput after drain: {e}"))
                        })?;
                    }
                    Err(e) => return Err(Error::Decoder(format!("ProcessInput: {e}"))),
                }
                self.drain_outputs(&mut out)?;
            }
            Ok(out)
        }

        fn flush(&mut self) {
            // SAFETY: flushing our own MFT; failure is non-fatal.
            unsafe {
                if let Err(e) = self.transform.ProcessMessage(MFT_MESSAGE_COMMAND_FLUSH, 0) {
                    tracing::warn!("AAC MFT flush failed: {e}");
                }
            }
            self.out_sample = None;
            tracing::debug!("audio decoder flushed across a discontinuity");
        }

        fn format(&self) -> AudioFormat {
            self.format
        }

        fn describe(&self) -> String {
            format!(
                "MF AAC-LC (CLSID_MSAACDecMFT), {} Hz {} ch → 16-bit PCM",
                self.format.sample_rate(),
                self.format.channels()
            )
        }
    }

    /// Create a decoder for each wire format and report what Media Foundation
    /// accepted. Proves MFT creation and — the part that actually matters —
    /// that the `MF_MT_USER_DATA` blob is one the AAC decoder will take.
    pub fn self_test() -> String {
        let mut report = String::new();
        for format in AudioFormat::ALL {
            let blob = match aac_user_data(format) {
                Ok(b) => b,
                Err(e) => {
                    report.push_str(&format!("{format:?}: user data FAILED: {e}\n"));
                    continue;
                }
            };
            let hex: String = blob.iter().map(|b| format!("{b:02x} ")).collect();
            report.push_str(&format!(
                "{format:?}: MF_MT_USER_DATA = {}\n",
                hex.trim_end()
            ));
            match MfAacDecoder::new(format) {
                Ok(decoder) => report.push_str(&format!("  OK: {}\n", decoder.describe())),
                Err(e) => report.push_str(&format!("  FAILED: {e}\n")),
            }
        }
        report
    }
}

#[cfg(windows)]
pub use mf::{self_test, MfAacDecoder};

/// Build the platform AAC-LC decoder for one wire format.
///
/// A decoder is bound to its format. When a packet arrives carrying a different
/// `format` code, the caller builds a new one — see [`MfAacDecoder`]'s docs for
/// why that is cheaper than it sounds.
pub fn new_audio_decoder(format: AudioFormat) -> Result<Box<dyn AudioDecode>> {
    #[cfg(windows)]
    {
        Ok(Box::new(MfAacDecoder::new(format)?))
    }
    #[cfg(not(windows))]
    {
        let _ = format;
        Err(Error::Decoder("no AAC-LC decoder on this platform".into()))
    }
}

// ---------------------------------------------------------------------------
// Test double
// ---------------------------------------------------------------------------

/// Canned-PCM [`AudioDecode`], the audio mirror of
/// [`directdesk_shared::traits::NullDecoder`].
///
/// Returns a fixed, deterministic block of PCM for every access unit and counts
/// what it was asked to do, so the playback loop can be driven headless: no
/// Media Foundation, no audio endpoint, no host. The canned block is one AAC
/// frame's worth by default, which makes sample arithmetic in a test read the
/// same way it does in production.
///
/// It is a `pub` type rather than a `#[cfg(test)]` one for the same reason
/// `NullDecoder` is: the integration tests in another crate need it too.
pub struct NullAudioDecoder {
    format: AudioFormat,
    canned: Vec<i16>,
    submits: u64,
    flushes: u64,
}

impl NullAudioDecoder {
    /// One AAC frame of a deterministic ramp — non-silent on purpose, so a test
    /// that asserts audio *flowed* cannot be satisfied by a zeroed buffer that
    /// nothing ever wrote to.
    pub fn new(format: AudioFormat) -> Self {
        let count = AAC_FRAME_SAMPLES * format.channels() as usize;
        let canned = (0..count).map(|i| ((i % 256) as i16) * 64).collect();
        Self {
            format,
            canned,
            submits: 0,
            flushes: 0,
        }
    }

    /// A decoder that returns exactly `pcm` for every access unit, for tests
    /// that need a specific length (a short frame, or none at all).
    pub fn with_pcm(format: AudioFormat, pcm: Vec<i16>) -> Self {
        Self {
            format,
            canned: pcm,
            submits: 0,
            flushes: 0,
        }
    }

    pub fn submits(&self) -> u64 {
        self.submits
    }

    pub fn flushes(&self) -> u64 {
        self.flushes
    }
}

impl AudioDecode for NullAudioDecoder {
    fn submit(&mut self, access_unit: &[u8]) -> Result<Vec<i16>> {
        // Same rejection as the real decoder: a test double that accepts input
        // the real one refuses hides the bug it exists to catch.
        if access_unit.is_empty() {
            return Err(Error::Decoder("empty AAC access unit".into()));
        }
        self.submits += 1;
        Ok(self.canned.clone())
    }

    fn flush(&mut self) {
        self.flushes += 1;
    }

    fn format(&self) -> AudioFormat {
        self.format
    }

    fn describe(&self) -> String {
        format!(
            "null AAC decoder (test passthrough), {} Hz {} ch, {} samples/frame",
            self.format.sample_rate(),
            self.format.channels(),
            self.canned.len()
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The four `AudioSpecificConfig` byte pairs, pinned.
    ///
    /// These are derived independently on the host side. If this test fails,
    /// the derivation is wrong — do NOT edit the expected bytes to match the
    /// code. Two bytes here decide the object type, sample rate and channel
    /// count the decoder configures itself for, and every wrong value has an
    /// audible-but-plausible failure mode (a pitch shift, a mono/stereo
    /// mismatch) rather than an error anyone would trace back to this table.
    #[test]
    fn audio_specific_config_matches_the_pinned_bytes() {
        let cases = [
            (AudioFormat::Stereo48k, [0x11u8, 0x90u8]),
            (AudioFormat::Stereo44k1, [0x12, 0x10]),
            (AudioFormat::Mono48k, [0x11, 0x88]),
            (AudioFormat::Mono44k1, [0x12, 0x08]),
        ];
        for (format, expected) in cases {
            let got = asc_for(format).expect("every wire format has a config");
            assert_eq!(
                got, expected,
                "{format:?} AudioSpecificConfig: got {got:02x?}, expected {expected:02x?}"
            );
        }
        // Every format the wire can carry must have one; no silent gaps.
        for format in AudioFormat::ALL {
            assert!(asc_for(format).is_ok(), "{format:?} has no config");
        }
    }

    /// The bit layout, verified field by field rather than as a whole.
    ///
    /// `audio_specific_config_matches_the_pinned_bytes` proves the four values
    /// we ship are right; this proves they are right for the right *reason*,
    /// by taking the bytes apart again with independent shifts. A packing bug
    /// that happened to compensate across two fields would pass the first test
    /// and fail this one.
    #[test]
    fn audio_specific_config_packs_the_documented_bit_fields() {
        for (rate, channels) in [(48_000u32, 2u8), (44_100, 2), (48_000, 1), (44_100, 1)] {
            let bytes = audio_specific_config(rate, channels).unwrap();
            let bits = u16::from_be_bytes(bytes);
            assert_eq!(bits >> 11, 2, "audioObjectType must be AAC-LC");
            assert_eq!(
                (bits >> 7) & 0xF,
                u16::from(sampling_frequency_index(rate).unwrap()),
                "samplingFrequencyIndex for {rate} Hz"
            );
            assert_eq!(
                (bits >> 3) & 0xF,
                u16::from(channels),
                "channelConfiguration for {channels} ch"
            );
            assert_eq!(
                bits & 0b111,
                0,
                "frameLengthFlag / dependsOnCoreCoder / extensionFlag must all be zero"
            );
        }
    }

    #[test]
    fn sampling_frequency_index_follows_the_iso_table() {
        // The two rates this path can actually carry.
        assert_eq!(sampling_frequency_index(48_000), Some(3));
        assert_eq!(sampling_frequency_index(44_100), Some(4));
        // The rest of the table, so a reordering is caught even though nothing
        // ships these rates today.
        let table = [
            (96_000u32, 0u8),
            (88_200, 1),
            (64_000, 2),
            (48_000, 3),
            (44_100, 4),
            (32_000, 5),
            (24_000, 6),
            (22_050, 7),
            (16_000, 8),
            (12_000, 9),
            (11_025, 10),
            (8_000, 11),
            (7_350, 12),
        ];
        for (rate, index) in table {
            assert_eq!(sampling_frequency_index(rate), Some(index), "{rate} Hz");
        }
        // An unnameable rate is `None`, never the escape index.
        for rate in [0u32, 1, 47_999, 48_001, 96_001, 192_000] {
            assert_eq!(sampling_frequency_index(rate), None, "{rate} Hz");
        }
    }

    #[test]
    fn audio_specific_config_rejects_what_it_cannot_name() {
        assert!(audio_specific_config(192_000, 2).is_err(), "rate off table");
        assert!(
            audio_specific_config(48_000, 0).is_err(),
            "channelConfiguration 0 needs a program config element we do not send"
        );
        assert!(audio_specific_config(48_000, 8).is_err(), "reserved layout");
    }

    /// The `HEAACWAVEINFO` tail, pinned byte by byte.
    ///
    /// Verified against `windows::Win32::Media::DirectShow::HEAACWAVEINFO`
    /// (windows 0.62): `#[repr(C, packed(1))]`, five fields after `wfx` — two
    /// `u16` payload/profile, two `u16` reserved, one `u32` reserved. Twelve
    /// bytes. `SetInputType` will not tell us if this is wrong; the audio will.
    #[test]
    fn heaac_tail_layout_is_pinned() {
        let bytes = HeAacWaveInfoTail::raw_aac_lc().to_bytes();
        assert_eq!(bytes.len(), HEAAC_TAIL_LEN);
        assert_eq!(
            bytes,
            [
                0x00, 0x00, // wPayloadType                 u16 LE = 0 (raw AAC)
                0x29, 0x00, // wAudioProfileLevelIndication u16 LE = 0x29 (L2)
                0x00, 0x00, // wStructType                  u16 LE = 0
                0x00, 0x00, // wReserved1                   u16 LE = 0
                0x00, 0x00, 0x00, 0x00, // dwReserved2      u32 LE = 0
            ],
            "the HEAACWAVEINFO tail moved — MF_MT_USER_DATA now carries a \
             misaligned AudioSpecificConfig and the AAC decoder will either \
             refuse the input type or decode noise"
        );
        // Distinct values in every field, so a widened or reordered field is
        // visible rather than absorbed by neighbouring zeros.
        let probe = HeAacWaveInfoTail {
            w_payload_type: 0x1122,
            w_audio_profile_level_indication: 0x3344,
            w_struct_type: 0x5566,
            w_reserved1: 0x7788,
            dw_reserved2: 0x99AA_BBCC,
        };
        assert_eq!(
            probe.to_bytes(),
            [0x22, 0x11, 0x44, 0x33, 0x66, 0x55, 0x88, 0x77, 0xCC, 0xBB, 0xAA, 0x99]
        );
        assert_eq!(std::mem::size_of::<HeAacWaveInfoTail>(), HEAAC_TAIL_LEN);
    }

    #[test]
    fn user_data_is_the_tail_then_the_config() {
        for format in AudioFormat::ALL {
            let blob = aac_user_data(format).unwrap();
            assert_eq!(
                blob.len(),
                HEAAC_TAIL_LEN + 2,
                "{format:?}: 12-byte tail + 2-byte AudioSpecificConfig"
            );
            assert_eq!(
                &blob[..HEAAC_TAIL_LEN],
                &HeAacWaveInfoTail::raw_aac_lc().to_bytes(),
                "{format:?}: tail"
            );
            assert_eq!(
                &blob[HEAAC_TAIL_LEN..],
                &asc_for(format).unwrap(),
                "{format:?}: config must start at offset {HEAAC_TAIL_LEN}, not before it"
            );
        }
        // The whole blob for the default case, so the two halves are pinned
        // together and not only apart.
        assert_eq!(
            aac_user_data(AudioFormat::Stereo48k).unwrap(),
            vec![0, 0, 0x29, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x11, 0x90]
        );
    }

    #[test]
    fn pcm_bytes_become_little_endian_samples() {
        let mut out = Vec::new();
        append_pcm_le(&[0x00, 0x00, 0xFF, 0x7F, 0x00, 0x80, 0x34, 0x12], &mut out).unwrap();
        assert_eq!(out, vec![0, i16::MAX, i16::MIN, 0x1234]);
        // Appends rather than replaces: the drain loop calls it once per output
        // sample and every one of them must land in the same vector.
        append_pcm_le(&[0x01, 0x00], &mut out).unwrap();
        assert_eq!(out.len(), 5);
        assert_eq!(out[4], 1);
        // Empty is fine and is not an error — an MFT may hand back a
        // zero-length buffer.
        let before = out.len();
        append_pcm_le(&[], &mut out).unwrap();
        assert_eq!(out.len(), before);
    }

    #[test]
    fn pcm_rejects_a_half_sample() {
        let mut out = Vec::new();
        let err = append_pcm_le(&[0x01, 0x02, 0x03], &mut out)
            .expect_err("an odd byte count is not a whole number of samples");
        assert!(err.to_string().contains("16-bit samples"), "got: {err}");
    }

    #[test]
    fn null_audio_decoder_returns_one_frame_of_canned_pcm() {
        for format in AudioFormat::ALL {
            let mut decoder = NullAudioDecoder::new(format);
            assert_eq!(decoder.format(), format);
            let pcm = decoder.submit(&[0xDE, 0xAD]).unwrap();
            assert_eq!(
                pcm.len(),
                AAC_FRAME_SAMPLES * format.channels() as usize,
                "{format:?}: one AAC frame of interleaved samples"
            );
            assert!(pcm.iter().any(|&s| s != 0), "canned PCM must not be silent");
            assert_eq!(decoder.submits(), 1);

            decoder.flush();
            assert_eq!(decoder.flushes(), 1);
            // Flushing does not change what a later submit returns: AAC-LC
            // frames are independently decodable, so there is no post-flush
            // starvation state like the video decoder's keyframe wait.
            assert_eq!(decoder.submit(&[0x01]).unwrap().len(), pcm.len());
            assert_eq!(decoder.submits(), 2);
        }
    }

    #[test]
    fn null_audio_decoder_rejects_an_empty_access_unit() {
        let mut decoder = NullAudioDecoder::new(AudioFormat::Stereo48k);
        assert!(
            decoder.submit(&[]).is_err(),
            "the double must refuse what the real decoder refuses"
        );
        assert_eq!(decoder.submits(), 0, "a rejected unit is not a submit");
    }

    #[test]
    fn null_audio_decoder_can_be_scripted_with_specific_pcm() {
        let mut decoder = NullAudioDecoder::with_pcm(AudioFormat::Mono48k, vec![7, 8, 9]);
        assert_eq!(decoder.submit(&[0x01]).unwrap(), vec![7, 8, 9]);
        // Zero-length output is a legal decoder response (the MFT buffers a
        // frame before it emits anything), so the double must be able to say it.
        let mut silent = NullAudioDecoder::with_pcm(AudioFormat::Mono48k, Vec::new());
        assert!(silent.submit(&[0x01]).unwrap().is_empty());
        assert_eq!(silent.submits(), 1);
    }

    /// A `Box<dyn AudioDecode>` is what the playback loop will hold.
    #[test]
    fn the_double_satisfies_the_object_safe_trait() {
        let mut decoder: Box<dyn AudioDecode> =
            Box::new(NullAudioDecoder::new(AudioFormat::Stereo44k1));
        assert_eq!(decoder.format(), AudioFormat::Stereo44k1);
        assert!(decoder.describe().contains("44100"));
        assert!(!decoder.submit(&[0x01]).unwrap().is_empty());
        decoder.flush();
    }

    /// The factory must not silently succeed where there is no decoder.
    #[cfg(not(windows))]
    #[test]
    fn there_is_no_decoder_off_windows() {
        assert!(new_audio_decoder(AudioFormat::Stereo48k).is_err());
    }
}

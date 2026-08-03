//! Minimal Media Foundation H.264 decoder, harness-local.
//!
//! This exists purely so the harness can prove the encoder's bitstream is a
//! real, decodable, Annex-B H.264 stream. It is deliberately the *software*
//! `CLSID_MSH264DecoderMFT` with CPU NV12 output — no DXVA, no shared device —
//! because an independent decoder is a much stronger check than round-tripping
//! through the same vendor stack that produced the bytes. The client's real
//! decoder is a separate concern and lives in the client crate.

use directdesk_shared::video::EncodedFrame;
use directdesk_shared::{Error, Result};
use windows::core::Interface;
use windows::Win32::Media::MediaFoundation::*;
use windows::Win32::System::Com::{CoCreateInstance, CLSCTX_INPROC_SERVER};

/// One decoded picture in tightly-described NV12.
pub struct Picture {
    pub width: u32,
    pub height: u32,
    /// Row pitch of the luma plane, in bytes.
    pub stride: usize,
    /// Byte offset of the interleaved chroma plane within `data`.
    pub uv_offset: usize,
    pub data: Vec<u8>,
    pub timestamp_ms: u32,
}

pub struct MfH264Decoder {
    transform: IMFTransform,
    width: u32,
    height: u32,
    stride: usize,
    uv_offset: usize,
    out_size: u32,
    provides_samples: bool,
}

impl MfH264Decoder {
    pub fn new(width: u32, height: u32) -> Result<Self> {
        // SAFETY: standard in-proc COM activation of a documented MFT CLSID.
        let transform: IMFTransform =
            unsafe { CoCreateInstance(&CLSID_MSH264DecoderMFT, None, CLSCTX_INPROC_SERVER) }
                .map_err(|e| Error::Decoder(format!("CoCreateInstance(MSH264Decoder): {e}")))?;

        let mut me = Self {
            transform,
            width,
            height,
            stride: width as usize,
            uv_offset: width as usize * height as usize,
            out_size: 0,
            provides_samples: false,
        };

        // SAFETY: fresh media types; all setters take static GUID keys.
        unsafe {
            if let Ok(attrs) = me.transform.GetAttributes() {
                let _ = attrs.SetUINT32(&MF_LOW_LATENCY, 1);
            }
            if let Ok(api) = me.transform.cast::<ICodecAPI>() {
                // Best effort; the software decoder honours MF_LOW_LATENCY anyway.
                let _ = api;
            }

            let inp = MFCreateMediaType().map_err(dec_err("MFCreateMediaType"))?;
            inp.SetGUID(&MF_MT_MAJOR_TYPE, &MFMediaType_Video).ok();
            inp.SetGUID(&MF_MT_SUBTYPE, &MFVideoFormat_H264).ok();
            inp.SetUINT64(&MF_MT_FRAME_SIZE, ((width as u64) << 32) | height as u64)
                .ok();
            inp.SetUINT64(&MF_MT_FRAME_RATE, (60u64 << 32) | 1).ok();
            inp.SetUINT32(&MF_MT_INTERLACE_MODE, MFVideoInterlace_Progressive.0 as u32)
                .ok();
            me.transform
                .SetInputType(0, &inp, 0)
                .map_err(dec_err("SetInputType(H264)"))?;
        }

        me.select_nv12_output()?;

        // SAFETY: documented start sequence for a sync MFT.
        unsafe {
            me.transform
                .ProcessMessage(MFT_MESSAGE_NOTIFY_BEGIN_STREAMING, 0)
                .map_err(dec_err("NOTIFY_BEGIN_STREAMING"))?;
            me.transform
                .ProcessMessage(MFT_MESSAGE_NOTIFY_START_OF_STREAM, 0)
                .map_err(dec_err("NOTIFY_START_OF_STREAM"))?;
        }
        Ok(me)
    }

    pub fn describe(&self) -> String {
        format!(
            "MF CLSID_MSH264DecoderMFT (software, CPU NV12 {}x{}, stride {})",
            self.width, self.height, self.stride
        )
    }

    /// Feed one Annex-B frame; returns zero or more decoded pictures.
    pub fn decode(&mut self, frame: &EncodedFrame) -> Result<Vec<Picture>> {
        if frame.data.is_empty() {
            return Ok(Vec::new());
        }
        let mut out = Vec::new();

        // SAFETY: buffer is sized to the payload and its length set to match.
        let sample = unsafe {
            let sample = MFCreateSample().map_err(dec_err("MFCreateSample"))?;
            let buf = MFCreateMemoryBuffer(frame.data.len() as u32)
                .map_err(dec_err("MFCreateMemoryBuffer"))?;
            let mut ptr: *mut u8 = std::ptr::null_mut();
            buf.Lock(&mut ptr, None, None).map_err(dec_err("Lock(in)"))?;
            std::ptr::copy_nonoverlapping(frame.data.as_ptr(), ptr, frame.data.len());
            let _ = buf.Unlock();
            buf.SetCurrentLength(frame.data.len() as u32)
                .map_err(dec_err("SetCurrentLength(in)"))?;
            sample.AddBuffer(&buf).map_err(dec_err("AddBuffer"))?;
            let _ = sample.SetSampleTime(frame.timestamp_ms as i64 * 10_000);
            if frame.keyframe {
                let _ = sample.SetUINT32(&MFSampleExtension_CleanPoint, 1);
            }
            sample
        };

        // SAFETY: sync MFT contract; NOTACCEPTING means drain then retry once.
        unsafe {
            match self.transform.ProcessInput(0, &sample, 0) {
                Ok(()) => {}
                Err(e) if e.code() == MF_E_NOTACCEPTING => {
                    self.drain(&mut out)?;
                    self.transform
                        .ProcessInput(0, &sample, 0)
                        .map_err(dec_err("ProcessInput(retry)"))?;
                }
                Err(e) => return Err(Error::Decoder(format!("ProcessInput: {e}"))),
            }
        }
        self.drain(&mut out)?;
        Ok(out)
    }

    pub fn flush(&mut self) {
        // SAFETY: plain FFI on a live transform.
        unsafe {
            let _ = self.transform.ProcessMessage(MFT_MESSAGE_COMMAND_FLUSH, 0);
        }
    }

    fn drain(&mut self, out: &mut Vec<Picture>) -> Result<()> {
        loop {
            match self.process_output()? {
                Some(p) => out.push(p),
                None => return Ok(()),
            }
        }
    }

    fn process_output(&mut self) -> Result<Option<Picture>> {
        let mut bufs = [MFT_OUTPUT_DATA_BUFFER { dwStreamID: 0, ..Default::default() }];

        // SAFETY: we allocate the output sample when the MFT does not; the
        // ManuallyDrop fields are taken exactly once so refcounts stay balanced.
        unsafe {
            if !self.provides_samples {
                let sample = MFCreateSample().map_err(dec_err("MFCreateSample(out)"))?;
                let buf = MFCreateMemoryBuffer(self.out_size.max(4096))
                    .map_err(dec_err("MFCreateMemoryBuffer(out)"))?;
                sample.AddBuffer(&buf).map_err(dec_err("AddBuffer(out)"))?;
                bufs[0].pSample = std::mem::ManuallyDrop::new(Some(sample));
            }
            let mut status = 0u32;
            let res = self.transform.ProcessOutput(0, &mut bufs, &mut status);
            let sample = std::mem::ManuallyDrop::take(&mut bufs[0].pSample);
            let events = std::mem::ManuallyDrop::take(&mut bufs[0].pEvents);
            drop(events);

            match res {
                Ok(()) => {}
                Err(e) if e.code() == MF_E_TRANSFORM_NEED_MORE_INPUT => return Ok(None),
                Err(e) if e.code() == MF_E_TRANSFORM_STREAM_CHANGE => {
                    self.select_nv12_output()?;
                    return Ok(None);
                }
                Err(e) => return Err(Error::Decoder(format!("ProcessOutput: {e}"))),
            }

            let Some(sample) = sample else { return Ok(None) };
            let ts_hns = sample.GetSampleTime().unwrap_or(0);
            let buffer = sample
                .ConvertToContiguousBuffer()
                .map_err(dec_err("ConvertToContiguousBuffer"))?;
            let mut ptr: *mut u8 = std::ptr::null_mut();
            let mut len = 0u32;
            buffer
                .Lock(&mut ptr, None, Some(&mut len))
                .map_err(dec_err("Lock(out)"))?;
            let data = std::slice::from_raw_parts(ptr, len as usize).to_vec();
            let _ = buffer.Unlock();

            if data.len() < self.uv_offset {
                return Ok(None);
            }
            Ok(Some(Picture {
                width: self.width,
                height: self.height,
                stride: self.stride,
                uv_offset: self.uv_offset,
                data,
                timestamp_ms: (ts_hns / 10_000) as u32,
            }))
        }
    }

    /// Pick the decoder's NV12 output type and recompute the plane geometry.
    fn select_nv12_output(&mut self) -> Result<()> {
        // SAFETY: enumeration terminates on MF_E_NO_MORE_TYPES; every returned
        // media type is used only within this call.
        unsafe {
            let mut chosen = None;
            for i in 0..32u32 {
                match self.transform.GetOutputAvailableType(0, i) {
                    Ok(t) => {
                        if t.GetGUID(&MF_MT_SUBTYPE).ok() == Some(MFVideoFormat_NV12) {
                            chosen = Some(t);
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
            let t = chosen.ok_or_else(|| {
                Error::Decoder("H.264 decoder offers no NV12 output type".into())
            })?;
            self.transform
                .SetOutputType(0, &t, 0)
                .map_err(dec_err("SetOutputType(NV12)"))?;

            let cur = self
                .transform
                .GetOutputCurrentType(0)
                .map_err(dec_err("GetOutputCurrentType"))?;
            if let Ok(size) = cur.GetUINT64(&MF_MT_FRAME_SIZE) {
                self.width = (size >> 32) as u32;
                self.height = (size & 0xFFFF_FFFF) as u32;
            }
            let stride = cur
                .GetUINT32(&MF_MT_DEFAULT_STRIDE)
                .map(|s| s as i32)
                .unwrap_or(self.width as i32);
            self.stride = stride.unsigned_abs() as usize;
            if self.stride < self.width as usize {
                self.stride = self.width as usize;
            }

            let info = self
                .transform
                .GetOutputStreamInfo(0)
                .map_err(dec_err("GetOutputStreamInfo"))?;
            self.provides_samples = info.dwFlags
                & (MFT_OUTPUT_STREAM_PROVIDES_SAMPLES.0 as u32
                    | MFT_OUTPUT_STREAM_CAN_PROVIDE_SAMPLES.0 as u32)
                != 0;
            self.out_size = info
                .cbSize
                .max((self.stride * self.height as usize * 3 / 2) as u32);

            // The decoder may pad the luma plane to a taller aligned height, so
            // derive the chroma offset from the reported buffer size rather than
            // assuming stride * height.
            let rows = (self.out_size as usize * 2) / (3 * self.stride.max(1));
            self.uv_offset = self.stride * rows.max(self.height as usize);
        }
        tracing::info!(
            "decoder output: {}x{} stride {} uv_offset {} bufsize {}",
            self.width,
            self.height,
            self.stride,
            self.uv_offset,
            self.out_size
        );
        Ok(())
    }
}

impl Drop for MfH264Decoder {
    fn drop(&mut self) {
        // SAFETY: mirror of the start sequence; teardown failures are ignored.
        unsafe {
            let _ = self
                .transform
                .ProcessMessage(MFT_MESSAGE_NOTIFY_END_OF_STREAM, 0);
            let _ = self
                .transform
                .ProcessMessage(MFT_MESSAGE_NOTIFY_END_STREAMING, 0);
        }
    }
}

fn dec_err(what: &'static str) -> impl Fn(windows::core::Error) -> Error {
    move |e| Error::Decoder(format!("{what}: {e}"))
}

/// NV12 -> RGBA8 (limited-range BT.709 inverse), optionally decimating by
/// `step` to keep the per-frame upload cheap on large desktops.
///
/// Returns the `(width, height)` actually written to `out`.
pub fn nv12_to_rgba(pic: &Picture, step: u32, out: &mut Vec<u8>) -> (usize, usize) {
    let step = step.max(1) as usize;
    let w = pic.width as usize;
    let h = pic.height as usize;
    let ow = w.div_ceil(step);
    let oh = h.div_ceil(step);
    out.clear();
    out.resize(ow * oh * 4, 255);

    let uv = &pic.data[pic.uv_offset.min(pic.data.len())..];
    let uv_stride = pic.stride;

    for oy in 0..oh {
        let y = (oy * step).min(h - 1);
        let y_row = y * pic.stride;
        let c_row = (y / 2) * uv_stride;
        for ox in 0..ow {
            let x = (ox * step).min(w - 1);
            let yi = y_row + x;
            if yi >= pic.data.len() {
                continue;
            }
            let luma = pic.data[yi] as i32;
            let ci = c_row + (x & !1);
            let (cb, cr) = if ci + 1 < uv.len() {
                (uv[ci] as i32, uv[ci + 1] as i32)
            } else {
                (128, 128)
            };
            let c = luma - 16;
            let d = cb - 128;
            let e = cr - 128;
            let r = ((298 * c + 459 * e + 128) >> 8).clamp(0, 255) as u8;
            let g = ((298 * c - 55 * d - 136 * e + 128) >> 8).clamp(0, 255) as u8;
            let b = ((298 * c + 541 * d + 128) >> 8).clamp(0, 255) as u8;
            let o = (oy * ow + ox) * 4;
            out[o] = r;
            out[o + 1] = g;
            out[o + 2] = b;
            out[o + 3] = 255;
        }
    }
    (ow, oh)
}

//! Component contracts. Host/client agents implement these; tests use null
//! implementations so the integration matrix runs headless with no GPU.

use crate::error::Result;
use crate::input::InputEvent;
use crate::video::EncodedFrame;

/// A captured frame handed to the encoder. `data` layout depends on `format`.
#[derive(Debug, Clone)]
pub struct RawFrame {
    pub width: u32,
    pub height: u32,
    pub format: PixelFormat,
    pub data: Vec<u8>,
    /// Sender-monotonic capture time in ms (wraps).
    pub timestamp_ms: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PixelFormat {
    Bgra8,
    Nv12,
    Rgba8,
}

/// Produces raw frames (DDA on the host; synthetic source in tests).
pub trait FrameSource: Send {
    /// Blocking-with-timeout acquire. Ok(None) = no new frame this interval.
    fn next_frame(&mut self, timeout_ms: u32) -> Result<Option<RawFrame>>;
    fn dimensions(&self) -> (u32, u32);
}

/// H.264 encoder (MF hardware MFT on host; null passthrough in tests).
pub trait Encoder: Send {
    fn encode(&mut self, frame: &RawFrame) -> Result<Option<EncodedFrame>>;
    /// Request the next output be an IDR keyframe.
    fn request_keyframe(&mut self);
    fn set_bitrate(&mut self, kbps: u32) -> Result<()>;
    /// Human-readable description, e.g. "MF HW H.264 (Intel Arc, QSV)".
    fn describe(&self) -> String;
}

/// H.264 decoder (MF on client; null passthrough in tests).
pub trait Decoder: Send {
    /// Feed one encoded frame; may return zero or more decoded frames.
    fn decode(&mut self, frame: &EncodedFrame) -> Result<Vec<RawFrame>>;
    /// Drop internal state and require a keyframe to resume.
    fn flush(&mut self);
}

/// Injects input into the local session (SendInput on host; mock in tests).
pub trait InputInjector: Send {
    fn inject(&mut self, ev: &InputEvent) -> Result<()>;
}

/// Null encoder for headless tests: wraps raw frame bytes as "encoded" data.
pub struct NullEncoder {
    next_keyframe: bool,
    frame_id: u32,
}

impl NullEncoder {
    pub fn new() -> Self {
        Self { next_keyframe: true, frame_id: 0 }
    }
}

impl Default for NullEncoder {
    fn default() -> Self {
        Self::new()
    }
}

impl Encoder for NullEncoder {
    fn encode(&mut self, frame: &RawFrame) -> Result<Option<EncodedFrame>> {
        let keyframe = std::mem::take(&mut self.next_keyframe);
        self.frame_id = self.frame_id.wrapping_add(1);
        Ok(Some(EncodedFrame {
            frame_id: self.frame_id,
            keyframe,
            timestamp_ms: frame.timestamp_ms,
            data: frame.data.clone(),
        }))
    }

    fn request_keyframe(&mut self) {
        self.next_keyframe = true;
    }

    fn set_bitrate(&mut self, _kbps: u32) -> Result<()> {
        Ok(())
    }

    fn describe(&self) -> String {
        "null encoder (test passthrough)".into()
    }
}

/// Null decoder mirror of [`NullEncoder`].
pub struct NullDecoder;

impl Decoder for NullDecoder {
    fn decode(&mut self, frame: &EncodedFrame) -> Result<Vec<RawFrame>> {
        Ok(vec![RawFrame {
            width: 0,
            height: 0,
            format: PixelFormat::Bgra8,
            data: frame.data.clone(),
            timestamp_ms: frame.timestamp_ms,
        }])
    }

    fn flush(&mut self) {}
}

/// Mock injector recording events for test assertions.
#[derive(Default)]
pub struct MockInjector {
    pub events: Vec<InputEvent>,
}

impl InputInjector for MockInjector {
    fn inject(&mut self, ev: &InputEvent) -> Result<()> {
        self.events.push(*ev);
        Ok(())
    }
}

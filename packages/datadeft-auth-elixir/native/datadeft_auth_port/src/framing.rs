//! Bounds the length prefix before allocating a frame.
use std::io::{self, Read, Write};

// Sized for the configuration frame (service policy, email templates and the
// inline secret documents); every other operation stays far below it. Both
// sides check the prefix before allocating a body.
pub const MAX_FRAME_BYTES: usize = 16384;

#[derive(Debug)]
pub enum FrameError {
    Io,
    Invalid,
}

impl From<io::Error> for FrameError {
    fn from(_: io::Error) -> Self {
        Self::Io
    }
}

pub fn read_frame(reader: &mut impl Read) -> Result<Option<Vec<u8>>, FrameError> {
    let mut prefix = [0_u8; 4];
    // EOF is clean only between frames, not in a prefix/body.
    loop {
        match reader.read(&mut prefix[..1]) {
            Ok(0) => return Ok(None),
            Ok(_) => break,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(_) => return Err(FrameError::Io),
        }
    }
    reader.read_exact(&mut prefix[1..])?;
    let length = u32::from_be_bytes(prefix) as usize;
    if length == 0 || length > MAX_FRAME_BYTES {
        return Err(FrameError::Invalid);
    }
    let mut frame = vec![0; length];
    reader.read_exact(&mut frame)?;
    Ok(Some(frame))
}

/// Writes one length-prefixed frame. Flushing stays with the caller, which
/// knows whether more frames are queued behind this one.
pub fn write_frame(writer: &mut impl Write, frame: &[u8]) -> Result<(), FrameError> {
    if frame.is_empty() || frame.len() > MAX_FRAME_BYTES {
        return Err(FrameError::Invalid);
    }
    let length = u32::try_from(frame.len()).map_err(|_| FrameError::Invalid)?;
    writer.write_all(&length.to_be_bytes())?;
    writer.write_all(frame)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn round_trip_and_clean_eof() {
        let mut bytes = Vec::new();
        write_frame(&mut bytes, b"test").unwrap();
        let mut reader = Cursor::new(bytes);
        assert_eq!(read_frame(&mut reader).unwrap(), Some(b"test".to_vec()));
        assert!(read_frame(&mut reader).unwrap().is_none());
    }

    #[test]
    fn reject_empty_oversized_and_truncated_frames() {
        let mut oversized = Vec::new();
        oversized.extend(u32::try_from(MAX_FRAME_BYTES + 1).unwrap().to_be_bytes());
        for bytes in [
            vec![0, 0, 0, 0],
            oversized,
            vec![255, 255, 255, 255],
            vec![0],
            vec![0, 0, 0, 2, b'a'],
        ] {
            assert!(read_frame(&mut Cursor::new(bytes)).is_err());
        }
        assert!(write_frame(&mut Vec::new(), &[]).is_err());
        assert!(write_frame(&mut Vec::new(), &vec![0; MAX_FRAME_BYTES + 1]).is_err());
    }
}

use std::fmt::{Debug, Display};

use binrw::{BinRead, BinReaderExt, BinWrite, BinWriterExt};

use serde::Serialize;
use uuid::Uuid;

use crate::RawSize;

#[derive(Eq, PartialEq, Copy, Clone)]
pub struct Guid(Uuid);

impl BinRead for Guid {
    type Args<'a> = ();

    fn read_options<R: std::io::Read + std::io::Seek>(
        reader: &mut R,
        endian: binrw::Endian,
        args: Self::Args<'_>,
    ) -> binrw::BinResult<Self> {
        let raw_value: [u8; 16] = reader.read_type_args(endian, args)?;
        let uuid = Uuid::from_bytes_le(raw_value);
        Ok(Self(uuid))
    }
}

impl BinWrite for Guid {
    type Args<'a> = ();

    fn write_options<W: std::io::Write + std::io::Seek>(
        &self,
        writer: &mut W,
        endian: binrw::Endian,
        args: Self::Args<'_>,
    ) -> binrw::BinResult<()> {
        writer.write_type_args(&self.0.to_bytes_le(), endian, args)
    }
}

impl Display for Guid {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(&self.0, f)
    }
}

impl Debug for Guid {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Debug::fmt(&self.0, f)
    }
}

impl<'v> TryFrom<&'v str> for Guid {
    type Error = <uuid::Uuid as std::convert::TryFrom<&'v str>>::Error;

    fn try_from(value: &'v str) -> Result<Self, Self::Error> {
        Ok(Self(Uuid::try_from(value)?))
    }
}

impl RawSize for Guid {
    fn raw_size(&self) -> u16 {
        std::mem::size_of::<u128>() as u16
    }
}

impl Serialize for Guid {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer {
        serializer.serialize_str(&self.to_string())
    }
}
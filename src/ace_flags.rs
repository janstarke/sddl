use binrw::{BinRead, BinReaderExt, BinWrite, BinWriterExt};
use bitflags::bitflags;

bitflags! {
    #[derive(Eq, PartialEq, Clone, Copy, Debug)]
    pub struct AceFlags: u32 {
        const ACE_OBJECT_TYPE_PRESENT = 0x00000001;
        const ACE_INHERITED_OBJECT_TYPE_PRESENT = 0x00000002;
    }
}

impl BinRead for AceFlags {
    type Args<'a> = ();

    fn read_options<R: std::io::Read + std::io::Seek>(
        reader: &mut R,
        endian: binrw::Endian,
        args: Self::Args<'_>,
    ) -> binrw::BinResult<Self> {
        let raw_value: u32 = reader.read_type_args(endian, args)?;
        Ok(AceFlags::from_bits(raw_value).unwrap())
    }
}

impl BinWrite for AceFlags {
    type Args<'a> = ();

    fn write_options<W: std::io::Write + std::io::Seek>(
        &self,
        writer: &mut W,
        endian: binrw::Endian,
        args: Self::Args<'_>,
    ) -> binrw::BinResult<()> {
        let raw_value = self.bits();
        writer.write_type_args(&raw_value, endian, args)
    }
}
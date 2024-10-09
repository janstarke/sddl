use binrw::BinRead;


#[derive(Eq, PartialEq, Copy, Clone, Debug)]
pub(crate) struct Offset(pub u64);

impl BinRead for Offset {
    type Args<'a> = ();

    fn read_options<R: std::io::Read + std::io::Seek>(
        reader: &mut R,
        _endian: binrw::Endian,
        _args: Self::Args<'_>,
    ) -> binrw::BinResult<Self> {
        let offset = reader.stream_position()?;
        Ok(Self(offset))
    }
}
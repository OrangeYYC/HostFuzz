use deku::prelude::*;

#[derive(Debug)]
pub enum AttError {
    InvalidAtt(DekuError),
}

impl From<DekuError> for AttError {
    fn from(value: DekuError) -> Self {
        AttError::InvalidAtt(value)
    }
}

#[derive(Debug, PartialEq, DekuRead, DekuWrite)]
#[deku(id_type = "u8")]
pub enum AttErrorCode {
    #[deku(id = 0x01)]
    InvalidHandle,
    #[deku(id = 0x02)]
    ReadNotPermitted,
    #[deku(id = 0x03)]
    WriteNotPermitted,
    #[deku(id = 0x04)]
    InvalidPdu,
    #[deku(id = 0x05)]
    InsufficientAuthentication,
    #[deku(id = 0x06)]
    RequestNotSupported,
    #[deku(id = 0x07)]
    InvalidOffset,
    #[deku(id = 0x08)]
    InsufficientAuthorization,
    #[deku(id = 0x09)]
    PrepareQueueFull,
    #[deku(id = 0x0A)]
    AttributeNotFound,
    #[deku(id = 0x0B)]
    AttributeNotLong,
    #[deku(id = 0x0C)]
    EncryptionKeySizeTooShort,
    #[deku(id = 0x0D)]
    InvalidAttributeValueLength,
    #[deku(id = 0x0E)]
    UnlikelyError,
    #[deku(id = 0x0F)]
    InsufficientEncryption,
    #[deku(id = 0x10)]
    UpsupportedGroupType,
    #[deku(id = 0x11)]
    InsufficientResources,
    #[deku(id = 0x12)]
    DatabaseOutOfSync,
    #[deku(id = 0x13)]
    ValueNotAllowed,
    #[deku(id_pat = "0x80..=0x9F")]
    ApplicationError { id: u8 },
    #[deku(id_pat = "0xE0..=0xFF")]
    CommonProfileAndServiceError { id: u8 },
}

#[derive(Debug, PartialEq, DekuRead, DekuWrite)]
#[deku(id_type = "u8")]
pub enum AttPacket {
    #[deku(id = 0x01)]
    ErrorRsp {
        request_opcode: u8,
        attribute_handle: u16,
        error_code: AttErrorCode,
    },
    #[deku(id = 0x02)]
    ExchangeMtuReq { client_rx_mtu: u16 },
    #[deku(id = 0x03)]
    ExchangeMtuRsp { server_rx_mtu: u16 },
    #[deku(id = 0x04)]
    FindInformationReq { starting_handle: u16, ending_handle: u16 },
    #[deku(id = 0x05)]
    FindInformationRsp { information: AttInformationData },
    #[deku(id = 0x06)]
    FindByTypeValueReq {
        starting_handle: u16,
        ending_handle: u16,
        attribute_type: u16,
        #[deku(read_all)]
        attribute_value: Vec<u8>,
    },
    #[deku(id = 0x07)]
    FindByTypeValueRsp {
        #[deku(read_all)]
        handles_information_list: Vec<(u16, u16)>,
    },
    #[deku(id = 0x08)]
    ReadByTypeReq {
        starting_handle: u16,
        ending_handle: u16,
        #[deku(read_all)]
        attribute_type: Vec<u8>,
    },
    #[deku(id = 0x09)]
    ReadByTypeRsp {
        length: u8,
        #[deku(read_all, ctx = "*length")]
        attribute_data_list: Vec<AttAttributeData>,
    },
    #[deku(id = 0x0A)]
    ReadReq { attribute_handle: u16 },
    #[deku(id = 0x0B)]
    ReadRsp {
        #[deku(read_all)]
        attribute_value: Vec<u8>,
    },
    #[deku(id = 0x0C)]
    ReadBlobReq { attribute_handle: u16, value_offset: u16 },
    #[deku(id = 0x0D)]
    ReadBlobRsp {
        #[deku(read_all)]
        part_attribute_value: Vec<u8>,
    },
    #[deku(id = 0x0E)]
    ReadMultipleReq {
        #[deku(read_all)]
        set_of_handlers: Vec<u16>,
    },
    #[deku(id = 0x0F)]
    ReadMultipleRsp {
        #[deku(read_all)]
        set_of_values: Vec<u8>,
    },
    #[deku(id = 0x10)]
    ReadByGroupTypeReq {
        starting_handle: u16,
        ending_handle: u16,
        #[deku(read_all)]
        attribute_group_type: Vec<u8>,
    },
    #[deku(id = 0x11)]
    ReadByGroupTypeRsp {
        length: u8,
        #[deku(read_all, ctx = "*length")]
        attribute_data_list: Vec<AttAttributeGroupData>,
    },
    #[deku(id = 0x20)]
    ReadMultipleVariableReq {
        #[deku(read_all)]
        set_of_handlers: Vec<u16>,
    },
    #[deku(id = 0x21)]
    ReadMultipleVariableRsp {
        #[deku(read_all)]
        length_value_tuple_list: Vec<u8>,
    },
    #[deku(id = 0x12)]
    WriteReq {
        attribute_handle: u16,
        #[deku(read_all)]
        attribute_value: Vec<u8>,
    },
    #[deku(id = 0x13)]
    WriteRsp,
    #[deku(id = 0x52)]
    WriteCmd {
        attribute_handle: u16,
        #[deku(read_all)]
        attribute_value: Vec<u8>,
    },
    #[deku(id = 0xD2)]
    SignedWriteCmd {
        attribute_handle: u16,
        #[deku(read_all)]
        attribute_value: Vec<u8>,
    },
    #[deku(id = 0x16)]
    PrepareWriteReq {
        attribute_handle: u16,
        value_offset: u16,
        #[deku(read_all)]
        part_attribute_value: Vec<u8>,
    },
    #[deku(id = 0x17)]
    PrepareWriteRsp {
        attribute_handle: u16,
        value_offset: u16,
        #[deku(read_all)]
        part_attribute_value: Vec<u8>,
    },
    #[deku(id = 0x18)]
    ExecuteWriteReq { flags: u8 },
    #[deku(id = 0x19)]
    ExecuteWriteRsp,
    #[deku(id = 0x1B)]
    HandleValueNtf {
        attribute_handle: u16,
        #[deku(read_all)]
        attribute_value: Vec<u8>,
    },
    #[deku(id = 0x1D)]
    HandleValueInd {
        attribute_handle: u16,
        #[deku(read_all)]
        attribute_value: Vec<u8>,
    },
    #[deku(id = 0x1E)]
    HandleValueCfm,
    #[deku(id = 0x23)]
    MultiHandleValueNtf {
        #[deku(read_all)]
        handle_length_value_tuple: Vec<u8>,
    },
}

#[derive(Debug, PartialEq, DekuRead, DekuWrite)]
#[deku(id_type = "u8")]
pub enum AttInformationData {
    #[deku(id = 0x01)]
    Bit16Uuid(#[deku(read_all)] Vec<(u16, u16)>),
    #[deku(id = 0x02)]
    Bit128Uuid(#[deku(read_all)] Vec<(u16, u128)>),
}

#[derive(Debug, PartialEq, DekuRead, DekuWrite)]
#[deku(ctx = "length: u8")]
pub struct AttAttributeData {
    pub attribute_handle: u16,
    #[deku(count = "length-0x2")]
    pub attribute_value: Vec<u8>,
}

#[derive(Debug, PartialEq, DekuRead, DekuWrite)]
#[deku(ctx = "length: u8")]
pub struct AttAttributeGroupData {
    pub attribute_handle: u16,
    pub end_group_handle: u16,
    #[deku(count = "length-0x4")]
    pub attribute_value: Vec<u8>,
}

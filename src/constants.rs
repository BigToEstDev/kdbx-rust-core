// FileSignature1, FileSignature2 and FileVersion32 in KeePassLib/Serialization/KdbxFile.cs
#[allow(dead_code)]
pub const SIG1: u32 = 0x9AA2_D903;
pub const SIG2: u32 = 0xB54B_FB67;
pub const VERSION_40: u32 = 0x0004_0000;
pub const VERSION_41: u32 = 0x0004_0001;

// Not supported versions
pub const OLD_SIG1: u32 = 0x9AA2_D903;
pub const OLD_SIG2: u32 = 0xB54B_FB65;
pub const VERSION_30: u32 = 0x0003_0000;
pub const VERSION_31: u32 = 0x0003_0001;
pub const VERSION_20: u32 = 0x0002_0000;

#[allow(dead_code)]
pub const VD_VER: u16 = 0x0100;
#[allow(dead_code)]
pub const HEADER_BLK_IDX: u64 = u64::MAX;
#[allow(dead_code)]
pub const SALSA20_IV: &[u8] = &[0xE8, 0x30, 0x09, 0x4B, 0x97, 0x20, 0x5D, 0x2A];
#[allow(dead_code)]
pub const EMPTY: &[u8] = &[];

// Encrypted data is split into blocks of this size before prefixed with its hmac
pub const PAYLOAD_BLOCK_SIZE: u64 = 1048576; // (1MB = 1024 * 1024), 65536  1048576

/*
// Not yet used
Version 2:
    Otp changes
*/
#[allow(dead_code)]
pub const INTERNAL_VERSION: i32 = 2;

pub const GENERATOR_NAME: &str = "OneKeyPass";

pub const EMPTY_STR: &str = "";

pub const OTP_URL_PREFIX: &str = "otpauth://totp";

// All Custom Data keys are of pattern OKP_K*. This is used instead of some descriptive
// string to reduce number of bytes taken by the key name entries in db and thus overall size of db
// Any new key should have the next OKP_Kx.
// Do not change the existing key names and meaning to make sure for backward compatability

#[allow(dead_code)]
pub mod custom_data_key {
    pub const OKP_INTERNAL_VERSION: &str = "OKP_K1";

    pub const OKP_GROUP_AS_CATEGORY: &str = "OKP_K2";

    // OKP_K3 - OKP_K7 held the entry types of OneKeePass (an entry's type, the types of its history,
    // the custom types of a database). The core no longer reads or writes them: they are kept as read,
    // like any foreign CustomData. How they worked - pass-docs plan/todo/core/okp-entry-types-history.md
}

pub mod general_category_names {
    pub const FAVORITES: &str = "Favorites";
}

#[allow(dead_code)]
pub mod entry_keyvalue_key {
    // The kdbx standard fields of an entry
    pub const TITLE: &str = "Title";
    pub const NOTES: &str = "Notes";
    pub const USER_NAME: &str = "UserName";
    pub const PASSWORD: &str = "Password";
    pub const URL: &str = "URL";

    // The field of our standard preset that kdbx does not have - a custom string for other programs
    pub const SERVICE: &str = "Service";

    // TOTP as KeePassXC / KeePassDX and we write it: one field holding an otpauth:// url
    pub const OTP: &str = "otp";

    // TOTP as the original KeePass 2.47+ writes it: separate string fields. The secret may come in
    // any one of the four encodings below; the rest are optional and default to 30 seconds,
    // 6 digits and SHA1. See db_content/time_otp.rs
    pub const TIME_OTP_SECRET: &str = "TimeOtp-Secret";
    pub const TIME_OTP_SECRET_HEX: &str = "TimeOtp-Secret-Hex";
    pub const TIME_OTP_SECRET_BASE32: &str = "TimeOtp-Secret-Base32";
    pub const TIME_OTP_SECRET_BASE64: &str = "TimeOtp-Secret-Base64";
    pub const TIME_OTP_PERIOD: &str = "TimeOtp-Period";
    pub const TIME_OTP_LENGTH: &str = "TimeOtp-Length";
    pub const TIME_OTP_ALGORITHM: &str = "TimeOtp-Algorithm";
}

// Note:
// At this time mainly some essential xml elements are used in OKP app
// For example, tags such as Color, ForegroundColor, BackgroundColor ect are not considered

//#[allow(non_upper_case_globals)]
#[allow(dead_code)]
pub mod xml_element {
    pub const KEEPASS_FILE: &[u8] = b"KeePassFile";
    pub const META: &[u8] = b"Meta";
    pub const ROOT: &[u8] = b"Root";

    //Meta
    pub const GENERATOR: &[u8] = b"Generator";
    pub const DATABASE_NAME: &[u8] = b"DatabaseName";
    pub const DATABASE_NAME_CHANGED: &[u8] = b"DatabaseNameChanged"; //date time
    pub const DATABASE_DESCRIPTION: &[u8] = b"DatabaseDescription";
    pub const DATABASE_DESCRIPTION_CHANGED: &[u8] = b"DatabaseDescriptionChanged";
    pub const SETTINGS_CHANGED: &[u8] = b"SettingsChanged";

    pub const DEFAULT_USER_NAME: &[u8] = b"DefaultUserName";
    pub const DEFAULT_USER_NAME_CHANGED: &[u8] = b"DefaultUserNameChanged";

    pub const MASTER_KEY_CHANGED: &[u8] = b"MasterKeyChanged";
    pub const RECYCLE_BIN_ENABLED: &[u8] = b"RecycleBinEnabled";

    pub const RECYCLE_BIN_UUID: &[u8] = b"RecycleBinUUID";
    pub const RECYCLE_BIN_CHANGED: &[u8] = b"RecycleBinChanged";

    pub const ENTRY_TEMPLATE_GROUP: &[u8] = b"EntryTemplatesGroup";
    pub const ENTRY_TEMPLATE_GROUP_CHANGED: &[u8] = b"EntryTemplatesGroupChanged";

    pub const HISTORY_MAX_ITEMS: &[u8] = b"HistoryMaxItems";
    pub const MAINTENANCE_HISTORY_DAYS: &[u8] = b"MaintenanceHistoryDays";
    pub const HISTORY_MAX_SIZE: &[u8] = b"HistoryMaxSize";
    pub const LAST_SELECTED_GROUP: &[u8] = b"LastSelectedGroup";
    pub const LAST_TOP_VISIBLE_GROUP: &[u8] = b"LastTopVisibleGroup";
    pub const COLOR: &[u8] = b"Color";
    // Master key change policy (KeePass): days, -1 = off
    pub const MASTER_KEY_CHANGE_REC: &[u8] = b"MasterKeyChangeRec";
    pub const MASTER_KEY_CHANGE_FORCE: &[u8] = b"MasterKeyChangeForce";
    // KeePass only; written only when true
    pub const MASTER_KEY_CHANGE_FORCE_ONCE: &[u8] = b"MasterKeyChangeForceOnce";

    pub const MEMORY_PROTECTION: &[u8] = b"MemoryProtection";
    pub const PROTECT_TITLE: &[u8] = b"ProtectTitle";
    pub const PROTECT_USER_NAME: &[u8] = b"ProtectUserName";
    pub const PROTECT_PASSWORD: &[u8] = b"ProtectPassword";
    pub const PROTECT_URL: &[u8] = b"ProtectURL";
    pub const PROTECT_NOTES: &[u8] = b"ProtectNotes";

    pub const CUSTOM_ICONS: &[u8] = b"CustomIcons";
    pub const ICON: &[u8] = b"Icon";
    pub const DATA: &[u8] = b"Data";
    // NAME and LAST_MODIFICATION_TIME are added in VERSION_41 of CUSTOM_ICONS

    // It seems, 'KeePass' removes an entry or group completely and writes its UUID
    // here. This happens when RECYCLE_BIN_ENABLED is false ( By default it is false in KeePass app)
    // OneKeePass and other implementation like KeePassXC uses RECYCLE_BIN_ENABLED = true and
    // Gives the user an option later to empty recycle bin or undo
    // However, when groups or entries are deleted permanently, the uuids of those objectes
    // are added under DeletedObjects after removing the groups/entries content from db
    pub const DELETED_OBJECTS: &[u8] = b"DeletedObjects";
    pub const DELETED_OBJECT: &[u8] = b"DeletedObject";
    pub const DELETION_TIME: &[u8] = b"DeletionTime";

    //Some Common tags

    //Custom Data
    pub const CUSTOM_DATA: &[u8] = b"CustomData";
    pub const ITEM: &[u8] = b"Item";

    //Times
    pub const TIMES: &[u8] = b"Times";
    pub const LAST_MODIFICATION_TIME: &[u8] = b"LastModificationTime";
    pub const CREATION_TIME: &[u8] = b"CreationTime";
    pub const LAST_ACCESS_TIME: &[u8] = b"LastAccessTime";
    pub const EXPIRES: &[u8] = b"Expires";
    pub const EXPIRY_TIME: &[u8] = b"ExpiryTime";
    pub const LOCATION_CHANGED: &[u8] = b"LocationChanged";
    pub const USAGE_COUNT: &[u8] = b"UsageCount";

    //pub const :&[u8]  = b"";
    pub const NOTES: &[u8] = b"Notes";
    pub const TAGS: &[u8] = b"Tags";

    pub const GROUP: &[u8] = b"Group";
    pub const UUID: &[u8] = b"UUID";
    pub const NAME: &[u8] = b"Name";
    pub const ICON_ID: &[u8] = b"IconID";
    pub const LAST_TOP_VISIBLE_ENTRY: &[u8] = b"LastTopVisibleEntry";
    pub const IS_EXPANDED: &[u8] = b"IsExpanded";
    // <EnableSearching>null / True / False</EnableSearching>, null = inherit from parent
    pub const ENABLE_SEARCHING: &[u8] = b"EnableSearching";
    // KDBX 4.1, group and entry: the group the object was in before the last move
    pub const PREVIOUS_PARENT_GROUP: &[u8] = b"PreviousParentGroup";

    // Entry
    pub const FOREGROUND_COLOR: &[u8] = b"ForegroundColor";
    pub const BACKGROUND_COLOR: &[u8] = b"BackgroundColor";
    pub const OVERRIDE_URL: &[u8] = b"OverrideURL";
    // KDBX 4.1: False = exclude the entry from password quality reports; written only when false
    pub const QUALITY_CHECK: &[u8] = b"QualityCheck";

    //

    //Entry
    pub const ENTRY: &[u8] = b"Entry";
    pub const BINARY: &[u8] = b"Binary";
    pub const STRING: &[u8] = b"String";
    pub const KEY: &[u8] = b"Key";
    pub const VALUE: &[u8] = b"Value"; //
    pub const HISTORY: &[u8] = b"History";
    pub const CUSTOM_ICON_UUID: &[u8] = b"CustomIconUUID";

    // AutoKey related
    // Entry level
    pub const AUTO_TYPE: &[u8] = b"AutoType";
    pub const ENABLED: &[u8] = b"Enabled";
    // empty means use the inherited default one (from group)
    pub const DEFAULT_SEQUENCE: &[u8] = b"DefaultSequence";
    // multiple association possible for an entry
    pub const ASSOCIATION: &[u8] = b"Association";
    pub const WINDOW: &[u8] = b"Window";
    // KeystrokeSequence cab be empty empty. If so, use the entry's default sequence
    pub const KEY_STROKE_SEQUENCE: &[u8] = b"KeystrokeSequence";

    // <EnableAutoType>null</EnableAutoType> when 'Inherit from parent is diabled'
    // <EnableAutoType>true</EnableAutoType> when 'enable' is selected

    pub const ENABLE_AUTO_TYPE: &[u8] = b"EnableAutoType"; // Group level ?

    // <DefaultAutoTypeSequence/> when default parent's AutoTypeSequence is enabled
    // <DefaultAutoTypeSequence>{USERNAME}</DefaultAutoTypeSequence> when custom AutoTypeSequence is used
    pub const DEFAULT_AUTO_TYPE_SEQUENCE: &[u8] = b"DefaultAutoTypeSequence"; // Group level

    pub const DATA_TRANSFER_OBFUSCATION: &[u8] = b"DataTransferObfuscation"; // entry AutoType, 0 = none

    //pub const KEEPASS_FILE_TAGS:&[&[u8]] = &[META,ROOT];
}

pub mod key_file_xml_element {
    pub const KEY_FILE: &[u8] = b"KeyFile";
    pub const KEY_FILE_META: &[u8] = b"Meta";
    pub const KEY_FILE_VERSION: &[u8] = b"Version";
    pub const KEY_FILE_KEY: &[u8] = b"Key";
    pub const KEY_FILE_DATA: &[u8] = b"Data";
    pub const KEY_FILE_DATA_HASH: &[u8] = b"Hash";
}

#[allow(dead_code)]
pub mod uuid {
    // KeePassLib/Cryptography/KeyDerivation/Argon2Kdf.cs
    // KeePass2.cpp

    // Type Argon2d
    pub const ARGON2_D_KDF: &[u8] = &[
        0xEF, 0x63, 0x6D, 0xDF, 0x8C, 0x29, 0x44, 0x4B, 0x91, 0xF7, 0xA9, 0xA4, 0x03, 0xE3, 0x0A,
        0x0C,
    ];

    // Type // Argon2id
    pub const ARGON2_ID_KDF: &[u8] = &[
        0x9E, 0x29, 0x8B, 0x19, 0x56, 0xDB, 0x47, 0x73, 0xB2, 0x3D, 0xFC, 0x3E, 0xC6, 0xF0, 0xA1,
        0xE6,
    ];

    // This is supporeted in old KeePass format 3 and we are not supporting
    // pub const AES_KDF: &[u8] = &[
    //     0xC9, 0xD9, 0xF3, 0x9A, 0x62, 0x8A, 0x44, 0x60, 0xBF, 0x74, 0x0D, 0x08, 0xC1, 0x8A, 0x4F,
    //     0xEA,
    // ];

    pub const CHACHA20: &[u8] = &[
        0xD6, 0x03, 0x8A, 0x2B, 0x8B, 0x6F, 0x4C, 0xB5, 0xA5, 0x24, 0x33, 0x9A, 0x31, 0xDB, 0xB5,
        0x9A,
    ];
    pub const AES256: &[u8] = &[
        0x31, 0xC1, 0xF2, 0xE6, 0xBF, 0x71, 0x43, 0x50, 0xBE, 0x58, 0x05, 0x21, 0x6A, 0xFC, 0x5A,
        0xFF,
    ];
}

//Types used in VariantDictionary VdType
#[allow(dead_code)]
pub mod vd_type {
    pub const NONE: u8 = 0x00;
    pub const UINT32: u8 = 0x04;
    pub const UINT64: u8 = 0x05;
    pub const BOOL: u8 = 0x08;
    pub const INT32: u8 = 0x0C;
    pub const INT64: u8 = 0x0D;
    pub const STRING: u8 = 0x18;
    pub const BYTEARRAY: u8 = 0x42;
}

#[allow(dead_code)]
pub mod vd_param {
    pub const UUID: &str = "$UUID";

    pub mod argon2 {
        pub const SALT: &str = "S";
        pub const PARALLELISM: &str = "P";
        pub const MEMORY: &str = "M";
        pub const ITERATIONS: &str = "I";
        pub const VERSION: &str = "V";
        pub const SECRETKEY: &str = "K";
        pub const ASSOCDATA: &str = "A";

        pub const DEFAULT_ITERATIONS: &[u8] = &[0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        pub const DEFAULT_PARALLELISM: &[u8] = &[0x02, 0x00, 0x00, 0x00];
        pub const DEFAULT_MEMORY: &[u8] = &[0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00];
    }

    pub mod aes {
        pub const ROUNDS: &str = "R";
        pub const SEED: &str = "S";

        pub const DEFAULT_ROUNDS: &[u8] = &[0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
    }
}

// All ids from enum KdbxHeaderFieldID of KeePassLib/Serialization/KdbxFile.cs and Only KDBX 4 ids are considered
#[allow(dead_code)]
pub mod header_type {
    pub const END_OF_HEADER: u8 = 0;
    pub const COMMENT: u8 = 1;
    pub const CIPHER_ID: u8 = 2;
    pub const COMPRESSION_FLAGS: u8 = 3;
    pub const MASTER_SEED: u8 = 4;
    pub const ENCRYPTION_IV: u8 = 7;
    pub const KDF_PARAMETERS: u8 = 11;
    pub const PUBLIC_CUSTOM_DATA: u8 = 12;
}

#[allow(dead_code)]
pub mod inner_header_type {
    pub const END_OF_HEADER: u8 = 0x00;
    pub const STREAM_ID: u8 = 0x01;
    pub const STREAM_KEY: u8 = 0x02;
    pub const BINARY: u8 = 0x03;

    pub const BINARY_PROTECTED: u8 = 0x01;
    pub const BINARY_PLAIN: u8 = 0x00;

    pub const SALSA20_STREAM: u32 = 2; //LE Bytes (2 0 0 0)
    pub const CHACHA20_STREAM: u32 = 3; //LE Bytes (3 0 0 0)
}

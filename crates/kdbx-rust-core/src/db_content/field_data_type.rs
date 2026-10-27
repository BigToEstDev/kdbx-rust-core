use serde::{Deserialize, Serialize};

// What a field of an entry holds, for the form to show it. In the kdbx file every field is a plain
// string; the data type is not stored there. Today the core sets only Text and OneTimePassword (a
// field whose value it can generate tokens from); the rest are kept for the presets of Step 44
#[derive(PartialEq, Debug, Copy, Clone, Default, Serialize, Deserialize)]
pub enum FieldDataType {
    #[default]
    Text,
    Bool,
    Number,
    Date, // Day-Month-Year
    Month,
    Year,
    MonthYear,
    OneTimePassword,
}

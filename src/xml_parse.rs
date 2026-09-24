use quick_xml::escape::unescape;
use quick_xml::events::attributes::{Attribute, Attributes};
use quick_xml::events::Event;
use quick_xml::events::{BytesDecl, BytesEnd, BytesStart, BytesText};
use quick_xml::name::QName;
use quick_xml::Reader as QuickXmlReader;
use quick_xml::Writer as QuickXmlWriter;

use std::collections::HashMap;
use std::io::Cursor;
use std::io::{BufRead, Write};

use crate::constants::key_file_xml_element::*;
use crate::constants::xml_element::*;
use crate::constants::GENERATOR_NAME;
use crate::crypto::ProtectedContentStreamCipher;
use crate::db::KeyFileData;
use crate::db_content::*;
use crate::error::{Error, Result};
use crate::util::{self, empty_str};
use log::{debug, error, info};

pub struct XmlReader<'a> {
    reader: QuickXmlReader<&'a [u8]>,
    stream_cipher: Option<ProtectedContentStreamCipher>,
    // Tags of the elements currently open, from the document root down (read_tags! keeps it).
    // An unknown element is stored with its path from the owner, so a place nobody listed -
    // <Times>, a future nested node - is kept as well as one that is listed
    path: Vec<String>,
    // Index in 'path' of the owner collecting unknown elements now: the file, Meta, Root,
    // a group or an entry (see begin_owner / end_owner and db_content/unknown_element.rs)
    owner_depth: usize,
    unknown_elements: UnknownElements,
}

// Macro called for reading specific set of inner tags

macro_rules! read_tags {
    ($self:ident, start_tag_fns {$($start_tag:tt => $start_tag_action:tt),* },
        start_tag_blks {$($parent_tag:tt => $parent_tag_action:tt),*},
        empty_tags {$($empty_tag:pat => $empty_tag_action:tt),*} , $end_tag:expr   )
        => {
        let mut buf:Vec<u8> = vec![];
        $self.enter_tag($end_tag);
        loop {

            match $self.reader.read_event_into(&mut buf) {
                Ok(Event::Start(ref e)) => {
                    match e.name().as_ref() {
                        $($start_tag => {
                            let content = $self.reader.read_text(QName($start_tag))?;
                            // read_text gives the raw text: entities are resolved here, once, for every
                            // field - the writer escapes once. Before Step 17 only some fields were
                            // unescaped, and names, tags etc. gained "&amp;" on every save
                            let content = content.decode().map_err(quick_xml::Error::from)?;
                            let content = content_unescape(&content);
                            $start_tag_action(content,&mut e.attributes(),&mut $self.stream_cipher);
                        }
                        )*

                        $($parent_tag  => {
                            // parent_tag_action is a block intead of a closure so that we can use "self" methods
                            // But if we need to access the attributes of this $parent_tag we need to pass a variable name as
                            // "tt" in "$attributes" and then can be set with value of e.attributes() and
                            // can be used inside parent_tag_action block
                            // start_tag_blks {$($attributes:tt,$parent_tag:tt => $parent_tag_action:tt),*},
                            // let mut $attributes = e.attributes();
                            // let mut $attributes = e.attributes().by_ref().filter_map(|a| a.ok()).collect::<Vec<_>>();
                            $parent_tag_action
                        })*

                        _ => {
                            // A tag not listed above: read it whole - protected values inside are
                            // decrypted, keeping the inner stream in step - and keep it or drop it
                            let unknown = read_unknown_element(&mut $self.reader, &mut $self.stream_cipher, e)?;
                            $self.keep_unknown($end_tag, unknown);
                        }
                    }
                }
                Ok(Event::Empty(ref e)) => {
                    match e.name().as_ref() {
                        $($empty_tag => {
                            $empty_tag_action(&mut e.attributes())
                        }
                        )*
                        x => {
                            // An empty known element (e.g. <Tags/>) means "no value"; any other is unknown
                            let known = match x {
                                $($start_tag => true,)*
                                $($parent_tag => true,)*
                                _ => false,
                            };
                            if !known {
                                let unknown = unknown_element_start(e)?;
                                $self.keep_unknown($end_tag, unknown);
                            }
                        }
                    }
                }

                Ok(Event::End(ref e)) if e.name().as_ref() == $end_tag => {
                    $self.leave_tag();
                    break;
                }
                Ok(Event::End(ref e)) if e.name().as_ref() != $end_tag => {
                    let ep = std::str::from_utf8($end_tag);
                    return Err(Error::XmlReadingFailed(format!("Found unexpected end tag {:?} when only expected end tag is {:?}",e,ep)));
                }
                Ok(Event::Eof) => {
                    let ep = std::str::from_utf8($end_tag);
                    return Err(Error::XmlReadingFailed(format!("Reached end before seeing the end tag {:?}", ep)));
                }
                Ok(ref x) => {
                    //TODO: Log any other events for debugging
                    let ep = std::str::from_utf8($end_tag);
                    println!("Unhandled event {:?} before seeing the end tag {:?}", x,ep);
                }
                Err(e) => {
                    return Err(Error::from(e));
                }
            }
        }
    };
}

// Tag name and attributes of an element the core does not know
fn unknown_element_start(start: &BytesStart) -> Result<UnknownElement> {
    let tag = std::str::from_utf8(start.name().as_ref())?.to_string();
    let mut attrs = vec![];
    for attr in start.attributes() {
        let attr = attr.map_err(quick_xml::Error::from)?;
        let key = std::str::from_utf8(attr.key.as_ref())?.to_string();
        let value = content_unescape(std::str::from_utf8(&attr.value)?);
        attrs.push((key, value));
    }
    Ok(UnknownElement::new(tag, attrs))
}

// Reads an unknown element whose start tag was just read, up to and including its end tag.
// A protected leaf is decrypted here, in document order like every other protected value:
// skipping it without decrypting would shift the inner stream for all later values
fn read_unknown_element<B: BufRead>(
    reader: &mut QuickXmlReader<B>,
    stream_cipher: &mut Option<ProtectedContentStreamCipher>,
    start: &BytesStart,
) -> Result<UnknownElement> {
    let mut element = unknown_element_start(start)?;

    // The reader trims text events, and text around an entity comes as separate events:
    // "a &amp; b" would be read as "a&b". Read unknown content untrimmed, restore after
    let (trim_start, trim_end) = (
        reader.config().trim_text_start,
        reader.config().trim_text_end,
    );
    reader.config_mut().trim_text(false);
    let content = read_unknown_content(reader, stream_cipher, &mut element);
    reader.config_mut().trim_text_start = trim_start;
    reader.config_mut().trim_text_end = trim_end;
    content?;

    if element.children.is_empty() {
        if element.is_protected_leaf() && !element.text.is_empty() {
            if let Some(ref mut cipher) = stream_cipher {
                // base64: surrounding whitespace is layout, not data
                element.text = cipher.process_basic64_str(element.text.trim())?;
            }
        }
    } else if element.text.trim().is_empty() {
        // Indentation between child elements, not content
        element.text.clear();
    }
    Ok(element)
}

fn read_unknown_content<B: BufRead>(
    reader: &mut QuickXmlReader<B>,
    stream_cipher: &mut Option<ProtectedContentStreamCipher>,
    element: &mut UnknownElement,
) -> Result<()> {
    let mut buf = vec![];
    loop {
        match reader.read_event_into(&mut buf)? {
            Event::Start(ref e) => {
                let child = read_unknown_element(reader, stream_cipher, e)?;
                element.children.push(child);
            }
            Event::Empty(ref e) => element.children.push(unknown_element_start(e)?),
            Event::Text(ref t) => {
                let text = t.decode().map_err(quick_xml::Error::from)?;
                element.text.push_str(&text);
            }
            // Entities (&amp; etc.) come as their own event since quick-xml 0.38
            Event::GeneralRef(ref r) => {
                let name = r.decode().map_err(quick_xml::Error::from)?;
                element
                    .text
                    .push_str(&content_unescape(&format!("&{};", name)));
            }
            Event::CData(ref c) => element.text.push_str(std::str::from_utf8(c)?),
            Event::End(_) => break,
            Event::Eof => {
                return Err(Error::XmlReadingFailed(format!(
                    "Reached end inside the element {:?}",
                    element.tag
                )))
            }
            _ => {}
        }
        buf.clear();
    }
    Ok(())
}

// Need to unescape the previously escaped `content` and replaces all xml
// escaped characters (`&...;`) into their corresponding value.
// quick_xml escapes any text content while writing and here we are doing reverse unescape
// "   &quot;
// '   &apos;
// <   &lt;
// >   &gt;
// &   &amp;
// See https://stackoverflow.com/questions/1091945/what-characters-do-i-need-to-escape-in-xml-documents
// https://docs.rs/quick-xml/0.30.0/quick_xml/escape/fn.escape.html
// https://docs.rs/quick-xml/0.30.0/quick_xml/events/struct.BytesText.html#method.new (escapes text content in this call)
fn content_unescape(content: &str) -> String {
    match unescape(content) {
        Ok(unescaped_content) => unescaped_content.to_string(),
        Err(e) => {
            error!("XML read time content unescaping failed with error {} ; Returning the original content", e);
            content.to_string()
        }
    }
}

#[inline]
fn content_to_int(content: String) -> i32 {
    if let Ok(i) = content.parse::<i32>() {
        i
    } else {
        // TODO accept some default value and return in case of parsing failure
        error!(
            "Parsing of content {} as i32 failed and returning -1",
            content
        );
        -1
    }
}

// HistoryMaxSize is a long in KeePass (bytes); content_to_int would turn values above i32::MAX
// (e.g. 4096 MB set in KeePass) into -1, i.e. "no limit", and that -1 would be written back to the file
#[inline]
fn content_to_i64(content: String) -> i64 {
    if let Ok(i) = content.parse::<i64>() {
        i
    } else {
        error!(
            "Parsing of content {} as i64 failed and returning -1",
            content
        );
        -1
    }
}

#[inline]
fn content_to_bool(content: String) -> bool {
    content.to_lowercase() == "true"
}

// Three-state KeePass flag (EnableAutoType, EnableSearching): "null" = inherit from the parent
fn content_to_opt_bool(content: String) -> Option<bool> {
    if content.trim().eq_ignore_ascii_case("null") {
        None
    } else {
        Some(content_to_bool(content))
    }
}

fn opt_bool_to_xml(flag: Option<bool>) -> String {
    flag.map_or_else(|| "null".into(), bool_to_xml_bool)
}

#[inline]
fn content_to_dt(content: String) -> chrono::NaiveDateTime {
    if let Some(d) = util::decode_datetime_b64(&content) {
        d
    } else {
        error!(
            "Parsing of content {} to date failed and returning now",
            content
        );
        util::now_utc()
    }
}

#[inline]
fn content_to_uuid(content: &str) -> uuid::Uuid {
    //TODO: Log the uuid conversion error
    util::decode_uuid(content).unwrap_or_default()
}

#[inline]
fn content_to_string_opt(content: String) -> Option<String> {
    if content.trim().is_empty() {
        None
    } else {
        Some(content)
    }
}

// Unknown elements of one owner while it is being written: each is handed back at the path it
// was read at, and what stays behind is reported. A place the writer forgets would otherwise
// lose data silently - the fixture test `unknown_elements_preservation` is the hard guard,
// this is the runtime warning (an element can also stay behind legitimately: its object, say a
// CustomData item, was deleted by the user since the file was read)
struct PendingUnknowns<'a> {
    items: Vec<(&'a [String], &'a UnknownElement, bool)>,
}

impl<'a> PendingUnknowns<'a> {
    fn new(store: &'a UnknownElements) -> Self {
        Self {
            items: store.iter().map(|(p, e)| (p, e, false)).collect(),
        }
    }

    // Elements read at this exact path, marked as written back
    fn take(&mut self, path: &[&str]) -> Vec<&'a UnknownElement> {
        let mut found = vec![];
        for (item_path, element, written) in self.items.iter_mut() {
            if !*written
                && item_path
                    .iter()
                    .map(|s| s.as_str())
                    .eq(path.iter().copied())
            {
                *written = true;
                found.push(*element);
            }
        }
        found
    }

    // Is there anything to write at or below this path? A container the core would skip as
    // empty (CustomData without items) still has to be written when it holds unknown elements
    fn has_below(&self, prefix: &[&str]) -> bool {
        self.items.iter().any(|(path, _, written)| {
            !*written && path.len() >= prefix.len() && path[..prefix.len()] == *prefix
        })
    }

    fn missed(&self) -> Vec<String> {
        self.items
            .iter()
            .filter(|(_, _, written)| !*written)
            .map(|(path, element, _)| format!("{}/{}", path.join("/"), element.tag))
            .collect()
    }
}

// What the writer did not hand back: either a place the writer forgets, or an object (a custom
// data item, an attachment) the user deleted since the file was read. The fixture test
// unknown_elements_preservation is what turns the first case into a failure
fn report_unwritten(pending: &PendingUnknowns, owner: &str) {
    let missed = pending.missed();
    if !missed.is_empty() {
        log::warn!(
            "{}: unknown elements not written back: {}",
            owner,
            missed.join(", ")
        );
    }
}

#[inline]
fn bool_to_xml_bool(flag: bool) -> String {
    if flag {
        "True".into()
    } else {
        "False".into()
    }
}

impl<'a> XmlReader<'a> {
    pub fn new(data: &'_ [u8], cipher: Option<ProtectedContentStreamCipher>) -> XmlReader<'_> {
        let mut qxmlreader = QuickXmlReader::from_reader(data);
        qxmlreader.config_mut().trim_text(true);
        // qxmlreader.trim_text(true);
        XmlReader {
            reader: qxmlreader,
            stream_cipher: cipher,
            path: vec![],
            // The file itself is the outermost owner: <KeePassFile> lands at index 0
            owner_depth: 0,
            unknown_elements: UnknownElements::default(),
        }
    }

    // Keeping an unknown element is the default, at any depth: it goes to the owner being read
    // with the path where it stood, and the writer puts it back there. Nothing is dropped, so a
    // node no one listed does not silently lose data (Step 18)
    fn keep_unknown(&mut self, _parent_tag: &[u8], element: UnknownElement) {
        let path = self.path_from_owner();
        self.unknown_elements.push(path, element);
    }

    // Path of the element being read, relative to its owner. Empty means "directly in the owner"
    fn path_from_owner(&self) -> Vec<String> {
        self.path
            .get(self.owner_depth + 1..)
            .unwrap_or(&[])
            .to_vec()
    }

    // read_tags! keeps the path: every nested reader goes through the macro, so a new node of
    // the format is covered without touching this file
    fn enter_tag(&mut self, tag: &[u8]) {
        self.path.push(String::from_utf8_lossy(tag).into_owned());
    }

    fn leave_tag(&mut self) {
        self.path.pop();
    }

    // Starts an owner of unknown elements (Meta, Root, a group, an entry): its elements are
    // collected apart and paths are counted from it. Returns the outer owner's state
    fn begin_owner(&mut self) -> (UnknownElements, usize) {
        let outer = std::mem::take(&mut self.unknown_elements);
        let outer_depth = self.owner_depth;
        // The owner's own tag is pushed by read_tags! right after this call
        self.owner_depth = self.path.len();
        (outer, outer_depth)
    }

    // Ends the owner and gives back what it collected, restoring the outer one
    fn end_owner(&mut self, (outer, outer_depth): (UnknownElements, usize)) -> UnknownElements {
        self.owner_depth = outer_depth;
        std::mem::replace(&mut self.unknown_elements, outer)
    }

    // Reads a repeated child (a String, an Item, an Icon...) collecting its unknown elements
    // apart: only after reading do we know its key, which goes into the path. These children
    // have no store of their own - the UI rebuilds them when an entry is edited
    fn read_keyed<T>(
        &mut self,
        read: impl FnOnce(&mut Self) -> Result<T>,
    ) -> Result<(T, UnknownElements)> {
        let outer = self.begin_owner();
        let value = read(self);
        let collected = self.end_owner(outer);
        Ok((value?, collected))
    }

    // Stores what a repeated child collected under "<tag>/<key>"
    fn keep_keyed(&mut self, tag: &[u8], key: &str, collected: UnknownElements) {
        if collected.is_empty() {
            return;
        }
        let mut prefix = self.path_from_owner();
        prefix.push(String::from_utf8_lossy(tag).into_owned());
        prefix.push(key.to_string());
        self.unknown_elements.extend_with_prefix(&prefix, collected);
    }

    pub fn parse(&mut self) -> Result<KeepassFile> {
        log::trace!("Going to parse read the the xml  ...");
        let mut kp = KeepassFile::new();
        let mut buf: Vec<u8> = vec![];
        // XML declarations are optional according to the XML specification.
        // let mut xml_decl_available = false;
        loop {
            match self.reader.read_event_into(&mut buf) {
                Ok(Event::Decl(ref _e)) => {
                    // xml_decl_available = true;
                }
                Ok(Event::DocType(_)) => {}
                Ok(Event::PI(_)) => {}
                Ok(Event::Text(_)) => {}
                // A general entity reference (e.g. `&amp;`) is now reported as its own
                // event (quick-xml 0.38+) instead of being inlined into Event::Text.
                // Only relevant between top-level tags, where text is ignored anyway.
                Ok(Event::GeneralRef(_)) => {}
                Ok(Event::Start(ref e)) => {
                    // if !xml_decl_available {
                    //     return Err(Error::XmlReadingFailed(format!(
                    //         "Xml content does not have XML decl"
                    //     )));
                    // }
                    match e.name().as_ref() {
                        KEEPASS_FILE => {
                            self.read_top_level(&mut kp)?;
                        }
                        x => {
                            //debug!("MAIN: in match {:?}", std::str::from_utf8(e.name()).unwrap());
                            //debug!("MAIN: in match {:?} KEEPASS_FILE", std::str::from_utf8(KEEPASS_FILE).unwrap());
                            return Err(Error::XmlReadingFailed(format!(
                                "Unexpected starting tag {:?}",
                                std::str::from_utf8(x)
                            )));
                        }
                    }
                }
                Ok(Event::Empty(ref _e)) => {}
                Ok(Event::End(ref e)) => {
                    // KeePassFile end tag should have been consumed in read_top_level
                    info!("PARSE:End of tag {:?}", e.name());
                }

                Ok(Event::CData(ref _e)) => {}

                Ok(Event::Comment(ref _e)) => {}

                Ok(Event::Eof) => {
                    //debug!("MAIN: End of File");
                    break;
                }

                Err(e) => {
                    debug!("XML content reading error {:?}", e);
                    return Err(Error::from(e));
                }
            }
        }
        Ok(kp)
    }

    fn read_top_level(&mut self, kp: &mut KeepassFile) -> Result<()> {
        let mut meta = Meta::new();
        let mut root = Root::new();

        read_tags!(self,
            start_tag_fns {},
            start_tag_blks {
                META => {
                    self.read_meta(&mut meta)?;
                },
                ROOT => {
                    self.read_root(&mut root)?;
                }
            },
            empty_tags {},
            KEEPASS_FILE);

        kp.meta = meta;
        kp.root = root;
        // What stood directly under <KeePassFile>: no other owner could hold it
        kp.unknown_elements = std::mem::take(&mut self.unknown_elements);
        Ok(())
    }

    fn read_meta(&mut self, meta: &mut Meta) -> Result<()> {
        let outer_unknown = self.begin_owner();
        read_tags! (
            self,
            start_tag_fns {
                GENERATOR => (
                    |content:String, _,  _| meta.generator = content
                ),
                DATABASE_NAME => (
                    |content:String, _,  _| meta.database_name = content
                ),
                DATABASE_DESCRIPTION => (
                    |content:String, _,  _| meta.database_description = content
                ),
                LAST_SELECTED_GROUP => (
                    |content:String, _,  _| meta.last_selected_group = content_to_uuid(&content)
                ),
                LAST_TOP_VISIBLE_GROUP => (
                    |content:String, _,  _| meta.last_top_visible_group = content_to_uuid(&content)
                ),
                COLOR => (
                    |content:String, _,  _| meta.color = content
                ),
                MASTER_KEY_CHANGE_REC => (
                    |content:String, _,  _| meta.master_key_change_rec = content_to_i64(content)
                ),
                MASTER_KEY_CHANGE_FORCE => (
                    |content:String, _,  _| meta.master_key_change_force = content_to_i64(content)
                ),
                MASTER_KEY_CHANGE_FORCE_ONCE => (
                    |content:String, _,  _| meta.master_key_change_force_once = content_to_bool(content)
                ),
                RECYCLE_BIN_CHANGED => (
                    |content:String, _,  _| meta.recycle_bin_changed = content_to_dt(content)
                ),
                HISTORY_MAX_ITEMS => (
                    |content:String, _,  _| meta.meta_share.set_history_max_items(content_to_int(content))
                ),
                HISTORY_MAX_SIZE => (
                    |content:String, _,  _| meta.meta_share.set_history_max_size(content_to_i64(content))
                ),
                MAINTENANCE_HISTORY_DAYS=> (
                    |content:String, _,  _| meta.maintenance_history_days = content_to_int(content)
                ),
                RECYCLE_BIN_ENABLED => (
                    |content:String, _,  _| meta.recycle_bin_enabled = content_to_bool(content)
                ),
                RECYCLE_BIN_UUID => (
                    |content:String, _,  _| meta.recycle_bin_uuid = content_to_uuid(&content)
                ),
                ENTRY_TEMPLATE_GROUP => (
                    |content:String, _,  _| meta.entry_template_group = content_to_uuid(&content)
                ),
                ENTRY_TEMPLATE_GROUP_CHANGED => (
                    |content:String, _,  _| meta.entry_template_group_changed = content_to_dt(content)
                ),
                DEFAULT_USER_NAME => (
                    |content:String, _,  _| meta.default_user_name = content
                ),
                DATABASE_NAME_CHANGED => (
                    |content:String, _,  _|  meta.database_name_changed = content_to_dt(content)
                ),
                DATABASE_DESCRIPTION_CHANGED => (
                    |content:String, _,  _|  meta.database_description_changed = content_to_dt(content)
                ),
                DEFAULT_USER_NAME_CHANGED => (
                    |content:String, _,  _|  meta.default_user_name_changed = content_to_dt(content)
                ),
                SETTINGS_CHANGED => (
                    |content:String, _,  _| meta.settings_changed = content_to_dt(content)
                ),
                MASTER_KEY_CHANGED => (
                    |content:String, _,  _| meta.master_key_changed = content_to_dt(content)
                )

            },
            start_tag_blks {
                //attributes1,
                MEMORY_PROTECTION => {
                    self.read_memory_protection(&mut meta.memory_protection)?;
                    //debug!("Attributes of  MEMORY_PROTECTION will be {:?}",attributes1);
                },
                //attributes2,
                CUSTOM_ICONS => {
                    //debug!("Called CUSTOM_ICONS");
                    self.read_custom_icons(&mut meta.custom_icons)?;
                    //debug!("CUSTOM_ICONS Content will be {:?}",attributes2);
                },
                CUSTOM_DATA => {
                    self.read_custom_data(&mut meta.custom_data)?;
                }
            },
            empty_tags {},
            META
        );
        meta.unknown_elements = self.end_owner(outer_unknown);
        Ok(())
    }

    fn read_memory_protection(&mut self, mp: &mut MemoryProtection) -> Result<()> {
        read_tags!(self,
            start_tag_fns {
                PROTECT_PASSWORD =>
                (|content:String, _,  _|
                    mp.protect_password = content_to_bool(content)
                ),
                PROTECT_NOTES =>
                (|content:String, _,  _|
                    mp.protect_notes = content_to_bool(content)
                ),
                PROTECT_TITLE =>
                (|content:String, _,  _|
                    mp.protect_title = content_to_bool(content)
                ),
                PROTECT_USER_NAME =>
                (|content:String, _,  _|
                    mp.protect_username = content_to_bool(content)
                ),
                PROTECT_URL =>
                (|content:String, _,  _|
                    mp.protect_url = content_to_bool(content)
                )
            },
            start_tag_blks {},
            empty_tags {},
            MEMORY_PROTECTION
        );
        Ok(())
    }

    fn read_custom_icons(&mut self, custom_icons: &mut CustomIcons) -> Result<()> {
        read_tags!(self,
            start_tag_fns {},
            start_tag_blks {
                ICON => {
                    let (icon, unknown) = self.read_keyed(|s| s.read_custom_icon())?;
                    self.keep_keyed(ICON, &icon.uuid.to_string(), unknown);
                    custom_icons.icons.push(icon);
                }
            },
            empty_tags{},
            CUSTOM_ICONS
        );
        Ok(())
    }

    fn read_custom_icon(&mut self) -> Result<Icon> {
        let mut icon = Icon::default();
        read_tags!(self,
            start_tag_fns {
                UUID => (|content:String, _,  _| icon.uuid = content_to_uuid(&content)),
                DATA => (|content:String, _,  _| {
                    if let Ok(d) = util::base64_decode(&content) {
                        icon.data = d;
                    }
                }),
                NAME => (|content:String, _,  _|  icon.name = Some(content)),
                LAST_MODIFICATION_TIME => (
                    |content:String, _,  _| icon.last_modification_time = content_to_dt(content)
                )
            },
            start_tag_blks {},
            empty_tags{},
            ICON
        );

        Ok(icon)
    }

    fn read_custom_data(&mut self, custom_data: &mut CustomData) -> Result<()> {
        read_tags!(self,
            start_tag_fns {},
            start_tag_blks {
                ITEM => {
                    let (item, unknown) = self.read_keyed(|s| s.read_custom_data_item())?;
                    self.keep_keyed(ITEM, &item.key, unknown);
                    custom_data.insert_item(item);
                }
            },
            empty_tags{},
            CUSTOM_DATA);
        Ok(())
    }

    fn read_custom_data_item(&mut self) -> Result<Item> {
        let mut item = Item::default();
        read_tags!(self,
            start_tag_fns {
                KEY =>
                (|content:String, _,  _|
                    item.key = content
                ),
                VALUE =>
                (|content:String, _,  _|
                    item.value = content
                ),
                LAST_MODIFICATION_TIME =>
                (|content:String, _,  _|
                    item.last_modification_time = if !content.trim().is_empty() {
                            Some(content_to_dt(content))
                        }
                        else {
                            None
                        }
                )
            },
            start_tag_blks {},
            empty_tags{},
            ITEM
        );
        Ok(item)
    }

    fn read_root(&mut self, root: &mut Root) -> Result<()> {
        let outer_unknown = self.begin_owner();
        read_tags!(self,
            start_tag_fns {},
            start_tag_blks {
                GROUP => {
                    // root.root_uuid = self.read_group(None,&mut root.all_groups,&mut root.all_entries)?;
                    // root.root_uuid = self.read_group(None,root)?;
                    let uuid = self.read_group(None,root)?;
                    root.set_root_uuid(uuid);
                },
                DELETED_OBJECTS => {
                    self.read_deleted_objects(root)?;
                }
            },
            empty_tags {},
            ROOT
        );
        root.unknown_elements = self.end_owner(outer_unknown);
        Ok(())
    }

    fn read_deleted_objects(&mut self, root: &mut Root) -> Result<()> {
        // Reads all DeletedObject tags under the parent tag 'DeletedObjects'
        read_tags!(self,start_tag_fns {},
            start_tag_blks {
                DELETED_OBJECT => {
                    let (deleted_object, unknown) =
                        self.read_keyed(|s| s.read_deleted_object())?;
                    self.keep_keyed(DELETED_OBJECT, &deleted_object.uuid.to_string(), unknown);
                    root.add_deleted_object(deleted_object);
                }
            },
            empty_tags {},
            DELETED_OBJECTS
        );
        Ok(())
    }

    // Reads one or more element <DeletedObject> ..</DeletedObject> and its child tgas
    fn read_deleted_object(&mut self) -> Result<DeletedObject> {
        let mut deleted_object = DeletedObject::default();
        read_tags!(self,
            start_tag_fns {
                UUID => (|content:String, _,  _| deleted_object.uuid = content_to_uuid(&content)),
                DELETION_TIME => (|content:String, _,  _| deleted_object.deletion_time = content_to_dt(content))
            },
            start_tag_blks {},
            empty_tags {},
            DELETED_OBJECT
        );
        Ok(deleted_object)
    }

    fn read_group(
        &mut self,
        parent_group_uuid: Option<uuid::Uuid>,
        root: &mut Root,
    ) -> Result<uuid::Uuid> {
        let mut group = Group::new();
        // All non root groups will have some parent group as parent
        if let Some(gid) = parent_group_uuid {
            group.parent_group_uuid = gid;
        }
        let outer_unknown = self.begin_owner();
        read_tags!(self,
            start_tag_fns {
                NAME => (|content:String, _,  _| group.name = content),
                UUID => (|content:String, _,  _| group.uuid = content_to_uuid(&content)),
                ICON_ID => (|content:String, _,  _| group.icon_id = content_to_int(content)),
                LAST_TOP_VISIBLE_ENTRY => (|content:String, _,  _| group.last_top_visible_entry = content_to_uuid(&content)),
                PREVIOUS_PARENT_GROUP => (|content:String, _,  _| group.previous_parent_group = content_to_uuid(&content)),
                IS_EXPANDED => (|content:String, _,  _| group.is_expanded = content_to_bool(content)),
                NOTES => (|content:String, _,  _| group.notes = content),
                TAGS => (|content:String, _,  _| group.tags = content),
                DEFAULT_AUTO_TYPE_SEQUENCE => (|content:String, _,  _| group.default_auto_type_sequence = Some(content)),
                ENABLE_AUTO_TYPE => (|content:String, _,  _| group.enable_auto_type = content_to_opt_bool(content)),
                ENABLE_SEARCHING => (|content:String, _,  _| group.enable_searching = content_to_opt_bool(content)),
                CUSTOM_ICON_UUID => (|content:String, _,  _|
                    group.custom_icon_uuid = if content.is_empty() {
                                                    None
                                                } else {
                                                    Some(content_to_uuid(&content))
                                                } )
            },
            start_tag_blks {
                TIMES => {
                    self.read_times(&mut group.times)?;
                },
                GROUP => {
                    // Recursive child group call
                    // IMPORTANT: It is assumed group.uuid is already read and set. See comments below for ENTRY
                    group.group_uuids.push(self.read_group(Some(group.uuid),root)?);
                },
                ENTRY => {
                    // group.entries.push(self.read_entry()?);
                    // It is assumed that Entry tag of a group is seen after UUID tag of Group so group.uuid should have valid uuid. See next comment
                    // TODO:
                    // If entry tag of a group comes before UUID tag of Group, then group.uuid will be a Uuid:Default vlaue.
                    // May need to fix when that happens with other KeePass app generated xml content.
                    // So far a group's entry always come after the group's uuid read
                    group.entry_uuids.push(self.read_entry(group.uuid, root)?);
                },
                CUSTOM_DATA => {
                    self.read_custom_data(&mut group.custom_data)?;
                }
            },
            empty_tags {},
            GROUP
        );
        group.unknown_elements = self.end_owner(outer_unknown);
        // TODO: We may need to ensure all Entries of this group has its group_uuid is set to this group's UUID. See above comments in 'ENTRY'
        let gid = group.uuid; // copy to return

        root.insert_to_all_groups(group);
        Ok(gid)
    }

    fn read_entry_data(&mut self) -> Result<Entry> {
        let mut entry = Entry::new();
        let outer_unknown = self.begin_owner();
        read_tags!(self,
            start_tag_fns {
                UUID => (|content:String, _,  _| entry.uuid = content_to_uuid(&content)),
                ICON_ID => (|content:String, _,  _| entry.icon_id = content_to_int(content)),
                CUSTOM_ICON_UUID => (|content:String, _,  _|
                        entry.custom_icon_uuid = if content.is_empty() {
                                                        None
                                                    } else {
                                                        Some(content_to_uuid(&content))
                                                    } ),
                TAGS => (|content:String, _,  _| entry.tags = content),
                FOREGROUND_COLOR => (|content:String, _,  _| entry.foreground_color = content),
                BACKGROUND_COLOR => (|content:String, _,  _| entry.background_color = content),
                OVERRIDE_URL => (|content:String, _,  _| entry.override_url = content),
                QUALITY_CHECK => (|content:String, _,  _| entry.quality_check = content_to_bool(content)),
                PREVIOUS_PARENT_GROUP => (|content:String, _,  _| entry.previous_parent_group = content_to_uuid(&content))
            },
            start_tag_blks {
                TIMES => {
                    self.read_times(&mut entry.times)?;
                },
                STRING => {
                    let (kv, unknown) = self.read_keyed(|s| s.read_key_value())?;
                    self.keep_keyed(STRING, &kv.key, unknown);
                    entry.entry_field.insert_key_value(kv);
                },
                BINARY => {
                    let (kv, unknown) = self.read_keyed(|s| s.read_binary_key_value())?;
                    self.keep_keyed(BINARY, &kv.key, unknown);
                    entry.binary_key_values.push(kv);
                },
                HISTORY => {
                    entry.history = self.read_histrory()?;
                },
                CUSTOM_DATA => {
                    self.read_custom_data(&mut entry.custom_data)?;
                },
                AUTO_TYPE => {
                    entry.auto_type = self.read_auto_type()?;
                }
            },
            empty_tags {},
            ENTRY
        );
        entry.unknown_elements = self.end_owner(outer_unknown);

        Ok(entry)
    }

    fn read_entry(&mut self, group_uuid: uuid::Uuid, root: &mut Root) -> Result<uuid::Uuid> {
        let mut entry = self.read_entry_data()?; //Entry::new();
        entry.parent_group_uuid = group_uuid;
        let eid = entry.uuid;
        root.insert_to_all_entries(entry);
        Ok(eid)
    }

    /// Reads the "History" tag content. Each "History" tag has 0 or more Entries
    /// The Entry tag under History should not contain any History tag
    fn read_histrory(&mut self) -> Result<History> {
        let mut history = History::default();
        read_tags!(self,
            start_tag_fns {},
            start_tag_blks {
                ENTRY => {
                    history.entries.push(self.read_entry_data()?);
                }
            },
            empty_tags {},
            HISTORY
        );
        Ok(history)
    }

    fn read_binary_key_value(&mut self) -> Result<BinaryKeyValue> {
        let mut kv = BinaryKeyValue::default();
        read_tags!(self,
            start_tag_fns {
                KEY =>(|content:String, _,  _| kv.key = content),
                // This handles the tag where we have both start and end tag like <Value Ref="0"></Value>
                VALUE => (|_, attributes:&mut Attributes,  _| kv.index_ref = attachment_ref_index(attributes))
            },
            start_tag_blks {},
            empty_tags {
                // This handles the tag where we have only an empty tag with attributes like <Value Ref="0" />
                VALUE =>
                (|attributes:&mut Attributes| {
                    kv.index_ref = attachment_ref_index(attributes);
                    }
                )
            },
            BINARY
        );
        Ok(kv)
    }

    fn read_key_value(&mut self) -> Result<KeyValue> {
        let mut kv = KeyValue::new();
        read_tags!(self,
            start_tag_fns {
                KEY =>
                (|content:String, _attributes, _cipher| {
                    kv.key = content;
                }),
                VALUE =>
                (|content:String, attributes:&mut Attributes, cipher:&mut Option<ProtectedContentStreamCipher>| {
                        // content is already unescaped by read_tags! (a protected value is base64)
                        //println!("KV:Value content is {}",&content);

                        kv.protected = is_value_protected(attributes);
                        //debug!("Key Value content is key:{}, value:{},protected:{}",&kv.key,&content,&kv.protected);
                        if kv.protected {
                            // Will there be a situation where field is protected and no cipher is used?
                            if let Some(ref mut cip) = cipher {
                                if let Ok(v) = cip.process_basic64_str(&content) {
                                    kv.value = v;
                                }
                            } else {
                                kv.value = content;
                            }
                        }
                        else {
                                kv.value = content;
                        }
                    }
                )
            },
            start_tag_blks {},
            // empty_tags {},
            empty_tags {
                // This handles the tag where we have only an empty tag with attributes like <Value Protected="True"/>
                VALUE =>
                (|attributes:&mut Attributes| {
                    kv.protected = is_value_protected(attributes);
                    }
                )
            },
            STRING
        );
        //debug!("Key value after reading is {:?}",&kv);
        Ok(kv)
    }

    // Reads the "AutoType" tag content. Each "AutoType" tag has 0 or more Association
    fn read_auto_type(&mut self) -> Result<AutoType> {
        let mut auto_type = AutoType::default();
        read_tags!(self,
            start_tag_fns {
                ENABLED =>
                (|content:String, _attributes, _cipher| {
                    auto_type.enabled = content_to_bool(content);
                }),
                DEFAULT_SEQUENCE => (|content:String, _attributes, _cipher| {
                    auto_type.default_sequence = content_to_string_opt(content);
                }),
                DATA_TRANSFER_OBFUSCATION => (|content:String, _attributes, _cipher| {
                    auto_type.data_transfer_obfuscation = content_to_int(content);
                })
            },
            start_tag_blks {
                ASSOCIATION => {
                    // Associations have no key of their own - addressed by position
                    let (association, unknown) =
                        self.read_keyed(|s| s.read_auto_type_association())?;
                    let index = auto_type.associations.len().to_string();
                    self.keep_keyed(ASSOCIATION, &index, unknown);
                    auto_type.associations.push(association);
                }
            },
            empty_tags {},
            AUTO_TYPE
        );
        Ok(auto_type)
    }

    fn read_auto_type_association(&mut self) -> Result<Association> {
        let mut association = Association::default();
        read_tags!(self,
            start_tag_fns {
                WINDOW =>
                (|content:String, _attributes, _cipher|
                    association.window = content),

                KEY_STROKE_SEQUENCE =>
                (|content:String, _, _|
                    association.key_stroke_sequence = content_to_string_opt(content))
            },
            start_tag_blks {},
            empty_tags {},
            ASSOCIATION
        );
        Ok(association)
    }

    fn read_times(&mut self, times: &mut Times) -> Result<()> {
        read_tags!(self,
            start_tag_fns {
                EXPIRES => (
                    |content:String, _,  _|  times.expires= content_to_bool(content)
                ),
                EXPIRY_TIME => (
                    |content:String, _,  _|  times.expiry_time = content_to_dt(content)
                ),
                LAST_MODIFICATION_TIME => (
                    |content:String, _,  _|  times.last_modification_time = content_to_dt(content)
                ),
                CREATION_TIME => (
                    |content:String, _,  _|  times.creation_time = content_to_dt(content)
                ),
                LAST_ACCESS_TIME => (
                    |content:String, _,  _|  times.last_access_time = content_to_dt(content)
                ),
                LOCATION_CHANGED => (|content:String, _,  _|  times.location_changed = content_to_dt(content)),
                USAGE_COUNT => (|content:String, _,  _|  times.usage_count = content_to_int(content))

            },
            start_tag_blks {},
            empty_tags {},
            TIMES

        );

        Ok(())
    }
}

fn is_value_protected(attributes: &mut Attributes) -> bool {
    let mut protected = false;
    let mut v = attributes
        .by_ref()
        .filter_map(|a| a.ok())
        .collect::<Vec<_>>();
    // Expected at leaset one attribute or no attributes for the the tag <Value>
    // e.g <Value Protected="True">RcHUs0nSHfunhQA=</Value>
    if !v.is_empty() {
        match v.pop() {
            Some(Attribute {
                key: QName(b"Protected"),
                value: x,
            }) => {
                //debug!("!!!!!! in fn attributes of Value are {:?}",v);
                if let std::borrow::Cow::Borrowed(a) = x {
                    //debug!("@@@@ a is {:?}",std::str::from_utf8(a).ok());
                    if b"True" == a {
                        protected = true;
                    }
                }
            }
            // Log as error if these happen when reading other KeePass app generated
            // xml. This may happen if such apps introduce app specific changes. So far we never saw these
            Some(x) => error!(
                "Some unexpected attribute {:?} for the protected value for String -> Value tag",
                x
            ),
            None => error!("No protected attribute for this Value tag - String -> Value tag"),
        }
    }
    protected
}

fn attachment_ref_index(attributes: &mut Attributes) -> i32 {
    let mut ref_index = -1;
    let mut v = attributes
        .by_ref()
        .filter_map(|a| a.ok())
        .collect::<Vec<_>>();
    // Expected at leaset one attribute for the the tag <Value>
    // e.g <Value Ref="0"/>
    if !v.is_empty() {
        match v.pop() {
            Some(Attribute {
                key: QName(b"Ref"),
                value: x,
            }) => {
                //debug!("!!!!!! in fn attributes of Value are {:?}",v);
                if let std::borrow::Cow::Borrowed(a) = x {
                    //debug!("@@@@ a is {:?}",std::str::from_utf8(a).ok());
                    if let Ok(i) = std::str::from_utf8(a) {
                        if let Ok(i) = i.parse::<i32>() {
                            ref_index = i;
                        }
                    }
                }
            }
            Some(x) => error!(
                "Some unexpected attribute {:?} for the attachment Binary -> Value tag",
                x
            ),
            None => {
                error!("No attribute is for this Value tag of attachment - Binary -> Value tag")
            }
        }
    }
    ref_index
}

/// Start parsing incoming xml bytes content
pub fn parse(data: &[u8], cipher: Option<ProtectedContentStreamCipher>) -> Result<KeepassFile> {
    let mut reader = XmlReader::new(data, cipher);

    reader.parse()
}

///////   All XML writing related //////////

// NOTE:
// The tags are written in the order  write_* macros are called for a Group or an entry.
// If we want change the order of tags, then call the write_* macros in that required sequences accordingly

macro_rules! write_tags {
    ($self:ident, $($tag_name:expr, $txt:expr),*) => {
        // Write empty tag if the content passed in $txt is a empty string
        // $txt should be evaluated once and reuse. Otherwise it will be evaluated
        // each time it is used
        $( let val = &$txt; // $txt evaluates to a String
            let name_of_tag  = std::str::from_utf8($tag_name)?;
            if val.is_empty() {
                $self.writer.write_event(Event::Empty(BytesStart::new(name_of_tag)))?;
            } else {
                $self.writer.write_event(Event::Start(BytesStart::new(name_of_tag)))?;
                // Creates a new BytesText from a string. The string is expected not to be escaped
                // quick_xml escapes the text content internally
                $self.writer.write_event(Event::Text(BytesText::new(val)))?;
                $self.writer.write_event(Event::End(BytesEnd::new(name_of_tag)))?;
            }
        )*
    };
}

// Skips the tag wriiting if the content is empty
macro_rules! write_tags_or_skip_empty {
    ($self:ident, $($tag_name:expr, $txt:expr),*) => {
        // Skips the tag if the content passed in $txt is a empty string
        // $txt should be evaluated once and reuse. Otherwise it will be evaluated
        // each time it is used
        $( let val = &$txt; // $txt evaluates to a String
            if !val.is_empty() {
                let name_of_tag  = std::str::from_utf8($tag_name)?;
                $self.writer.write_event(Event::Start(BytesStart::new(name_of_tag)))?;
                // Creates a new BytesText from a string. The string is expected not to be escaped
                // quick_xml escapes the text content internally
                $self.writer.write_event(Event::Text(BytesText::new(val)))?;
                $self.writer.write_event(Event::End(BytesEnd::new(name_of_tag)))?;

            }
        )*
    };
}

// Skips the tag wriiting if the content is None
macro_rules! write_opt_val_tags_or_skip {
    ($self:ident, $($tag_name:expr, $txt:expr),*) => {
        // Skips the tag if the content passed in $txt is None
        // $txt should be evaluated once and reuse. Otherwise it will be evaluated
        // each time it is used
        $( if let Some(ref val ) = $txt {
                // $txt evaluates to an Option
                let name_of_tag  = std::str::from_utf8($tag_name)?;
                $self.writer.write_event(Event::Start(BytesStart::new(name_of_tag)))?;
                // Creates a new BytesText from a string. The string is expected not to be escaped
                // quick_xml escapes the text content internally
                $self.writer.write_event(Event::Text(BytesText::new(val)))?;
                $self.writer.write_event(Event::End(BytesEnd::new(name_of_tag)))?;
            }
        )*
    };
}

// The same, plus the unknown elements kept for this node's path - they go back inside it,
// after the known children (see PendingUnknowns)
macro_rules! write_parent_child_tags_keeping_unknown {
    ($self:ident, $parent_tag:expr, $pending:expr, $path:expr, $($tag_name:expr, $txt:expr),*) => {
        let name_of_paren_tag  = std::str::from_utf8($parent_tag)?;
        $self.writer.write_event(Event::Start(BytesStart::new(name_of_paren_tag)))?;
        write_tags!($self, $($tag_name, $txt),*);
        let kept = $pending.take($path);
        $self.write_unknown_elements(kept)?;
        $self.writer.write_event(Event::End(BytesEnd::new(name_of_paren_tag)))?;
    }
}

macro_rules! write_tags_with_attributes {
    ($self:ident, $($tag_name:expr, $attrs:expr,$txt:expr),*) => {
        $(
            let name_of_tag  = std::str::from_utf8($tag_name)?;
            let mut my_element = BytesStart::new(name_of_tag);
            for a in $attrs.iter() {
                my_element.push_attribute(*a);
            }
            let s:&str = $txt.as_ref();
            $self.writer.write_event(Event::Start(my_element))?;
            $self.writer.write_event(Event::Text(BytesText::new(s)))?; //&$txt
            $self.writer.write_event(Event::End(BytesEnd::new(name_of_tag)))?;
        )*
    };
}

macro_rules! write_parent_child_with_attributes {
    ($self:ident, $parent_tag:expr, $($tag_name:expr, $attrs:expr,$txt:expr),*) => {
        let name_of_paren_tag  = std::str::from_utf8($parent_tag)?;
        $self.writer.write_event(Event::Start(BytesStart::new(name_of_paren_tag)))?;
        write_tags_with_attributes!($self, $($tag_name, $attrs,$txt),*);
        $self.writer.write_event(Event::End(BytesEnd::new(name_of_paren_tag)))?;
    }
}

// The same, plus the unknown elements kept for the path of this node (String, Binary)
macro_rules! write_parent_child_with_attributes_keeping_unknown {
    ($self:ident, $parent_tag:expr, $pending:expr, $path:expr, $($tag_name:expr, $attrs:expr,$txt:expr),*) => {
        let name_of_paren_tag  = std::str::from_utf8($parent_tag)?;
        $self.writer.write_event(Event::Start(BytesStart::new(name_of_paren_tag)))?;
        write_tags_with_attributes!($self, $($tag_name, $attrs,$txt),*);
        let kept = $pending.take($path);
        $self.write_unknown_elements(kept)?;
        $self.writer.write_event(Event::End(BytesEnd::new(name_of_paren_tag)))?;
    }
}

pub struct XmlWriter<W: Write> {
    writer: QuickXmlWriter<W>,
    //stream_cipher: ProtectedContentStreamCipher,
    stream_cipher: Option<ProtectedContentStreamCipher>,
}

impl<W: Write> XmlWriter<W> {
    pub fn new(writer: W, cipher: Option<ProtectedContentStreamCipher>) -> Self {
        Self {
            writer: QuickXmlWriter::new(writer),
            stream_cipher: cipher,
        }
    }

    pub fn new_with_indent(writer: W, cipher: Option<ProtectedContentStreamCipher>) -> Self {
        Self {
            writer: QuickXmlWriter::new_with_indent(writer, b" "[0], 2),
            stream_cipher: cipher,
        }
    }

    fn write_deleted_objects(&mut self, root: &Root, pending: &mut PendingUnknowns) -> Result<()> {
        if root.deleted_objects().is_empty() && !pending.has_below(&["DeletedObjects"]) {
            return Ok(());
        }

        let deleted_objects_tags = std::str::from_utf8(DELETED_OBJECTS)?;
        self.writer
            .write_event(Event::Start(BytesStart::new(deleted_objects_tags)))?;

        for deleted_object in root.deleted_objects().iter() {
            let object_path = [
                "DeletedObjects",
                "DeletedObject",
                &deleted_object.uuid.to_string(),
            ];
            write_parent_child_tags_keeping_unknown! { self,
               DELETED_OBJECT,
               pending,
               &object_path,
               UUID, util::encode_uuid(&deleted_object.uuid),
               DELETION_TIME, util::encode_datetime(&deleted_object.deletion_time)
            };
        }

        let kept = pending.take(&["DeletedObjects"]);
        self.write_unknown_elements(kept)?;

        self.writer
            .write_event(Event::End(BytesEnd::new(deleted_objects_tags)))?;

        Ok(())
    }

    fn write_meta(&mut self, keepass_file: &KeepassFile) -> Result<()> {
        let meta_tag = std::str::from_utf8(META)?;
        self.writer
            .write_event(Event::Start(BytesStart::new(meta_tag)))?;

        let meta = &keepass_file.meta;

        // Element order as in KeePass (KdbxFile.Write) and KeePassXC (KdbxXmlWriter)
        write_tags! { self,
            GENERATOR,GENERATOR_NAME,
            DATABASE_NAME,meta.database_name,
            DATABASE_NAME_CHANGED,util::encode_datetime(&meta.database_name_changed),
            DATABASE_DESCRIPTION, meta.database_description,
            DATABASE_DESCRIPTION_CHANGED,util::encode_datetime(&meta.database_description_changed),
            DEFAULT_USER_NAME, meta.default_user_name,
            DEFAULT_USER_NAME_CHANGED,util::encode_datetime(&meta.default_user_name_changed),
            MAINTENANCE_HISTORY_DAYS, meta.maintenance_history_days.to_string(),
            COLOR, meta.color,
            MASTER_KEY_CHANGED, util::encode_datetime(&meta.master_key_changed),
            MASTER_KEY_CHANGE_REC, meta.master_key_change_rec.to_string(),
            MASTER_KEY_CHANGE_FORCE, meta.master_key_change_force.to_string()
        };
        // KeePass writes it only when set
        if meta.master_key_change_force_once {
            write_tags! { self, MASTER_KEY_CHANGE_FORCE_ONCE, "True" };
        }

        let mut pending = PendingUnknowns::new(&meta.unknown_elements);

        self.write_memory_protection(&meta.memory_protection, &mut pending)?;

        self.write_custom_icons(&meta.custom_icons, &mut pending)?;

        write_tags! { self,
            RECYCLE_BIN_ENABLED, if meta.recycle_bin_enabled {"True"} else {"False"},
            RECYCLE_BIN_UUID, util::encode_uuid(&meta.recycle_bin_uuid),
            RECYCLE_BIN_CHANGED, util::encode_datetime(&meta.recycle_bin_changed),
            ENTRY_TEMPLATE_GROUP, util::encode_uuid(&meta.entry_template_group),
            ENTRY_TEMPLATE_GROUP_CHANGED,util::encode_datetime(&meta.entry_template_group_changed),
            HISTORY_MAX_ITEMS,meta.meta_share.history_max_items().to_string(),
            HISTORY_MAX_SIZE,meta.meta_share.history_max_size().to_string(),
            LAST_SELECTED_GROUP, util::encode_uuid(&meta.last_selected_group),
            LAST_TOP_VISIBLE_GROUP, util::encode_uuid(&meta.last_top_visible_group),
            SETTINGS_CHANGED, util::encode_datetime(&meta.settings_changed)
        };

        self.write_custom_data(&meta.custom_data, &mut pending)?;

        let kept = pending.take(&[]);
        self.write_unknown_elements(kept)?;
        report_unwritten(&pending, "Meta");

        self.writer
            .write_event(Event::End(BytesEnd::new(meta_tag)))?;

        Ok(())
    }

    // Writes back elements the core does not know (read by read_unknown_element).
    // Protected leaves are encrypted here, in document order like every other protected value
    fn write_unknown_elements<'e>(
        &mut self,
        elements: impl IntoIterator<Item = &'e UnknownElement>,
    ) -> Result<()> {
        for element in elements {
            let mut start = BytesStart::new(element.tag.as_str());
            for (key, value) in element.attrs.iter() {
                start.push_attribute((key.as_str(), value.as_str()));
            }
            if element.text.is_empty() && element.children.is_empty() {
                self.writer.write_event(Event::Empty(start))?;
                continue;
            }

            self.writer.write_event(Event::Start(start))?;
            if !element.text.is_empty() {
                let mut text = element.text.clone();
                if element.is_protected_leaf() {
                    if let Some(ref mut cipher) = &mut self.stream_cipher {
                        text = cipher.process_content_b64_str(&element.text)?;
                    }
                }
                self.writer
                    .write_event(Event::Text(BytesText::new(&text)))?;
            }
            self.write_unknown_elements(&element.children)?;
            self.writer
                .write_event(Event::End(BytesEnd::new(element.tag.as_str())))?;
        }
        Ok(())
    }

    fn write_memory_protection(
        &mut self,
        mp: &MemoryProtection,
        pending: &mut PendingUnknowns,
    ) -> Result<()> {
        write_parent_child_tags_keeping_unknown! {
            self,
            MEMORY_PROTECTION,
            pending,
            &["MemoryProtection"],
            PROTECT_TITLE, bool_to_xml_bool(mp.protect_title),
            PROTECT_USER_NAME, bool_to_xml_bool(mp.protect_username),
            PROTECT_PASSWORD, bool_to_xml_bool(mp.protect_password),
            PROTECT_URL, bool_to_xml_bool(mp.protect_url),
            PROTECT_NOTES, bool_to_xml_bool(mp.protect_notes)
        };
        Ok(())
    }

    fn write_times(&mut self, times: &Times, pending: &mut PendingUnknowns) -> Result<()> {
        write_parent_child_tags_keeping_unknown! {
            self,
            TIMES,
            pending,
            &["Times"],
            LAST_MODIFICATION_TIME, util::encode_datetime(&times.last_modification_time),
            CREATION_TIME, util::encode_datetime(&times.creation_time),
            LAST_ACCESS_TIME,util::encode_datetime(&times.last_access_time),
            LOCATION_CHANGED,util::encode_datetime(&times.location_changed),
            EXPIRY_TIME, util::encode_datetime(&times.expiry_time),
            EXPIRES, if times.expires {"True"} else {"False"},
            USAGE_COUNT,times.usage_count.to_string()
        };

        Ok(())
    }

    fn write_custom_icons(
        &mut self,
        custom_icons: &CustomIcons,
        pending: &mut PendingUnknowns,
    ) -> Result<()> {
        // An empty container is skipped - unless it is the place of an unknown element
        if custom_icons.icons.is_empty() && !pending.has_below(&["CustomIcons"]) {
            return Ok(());
        }

        let custom_icons_tag = std::str::from_utf8(CUSTOM_ICONS)?;
        self.writer
            .write_event(Event::Start(BytesStart::new(custom_icons_tag)))?;
        for icon in custom_icons.icons.iter() {
            let icon_path = ["CustomIcons", "Icon", &icon.uuid.to_string()];
            write_parent_child_tags_keeping_unknown! {
                self,
                ICON,
                pending,
                &icon_path,
                UUID, util::encode_uuid(&icon.uuid),
                NAME, &icon.name.as_ref().map_or_else(util::empty_str, |s| s.to_string()),
                DATA,  util::base64_encode(&icon.data),
                LAST_MODIFICATION_TIME, util::encode_datetime(&icon.last_modification_time)
            };
        }

        let kept = pending.take(&["CustomIcons"]);
        self.write_unknown_elements(kept)?;

        self.writer
            .write_event(Event::End(BytesEnd::new(custom_icons_tag)))?;

        Ok(())
    }

    fn write_custom_data(
        &mut self,
        custom_data: &CustomData,
        pending: &mut PendingUnknowns,
    ) -> Result<()> {
        if custom_data.get_items().is_empty() && !pending.has_below(&["CustomData"]) {
            return Ok(());
        }

        let custom_data_tag = std::str::from_utf8(CUSTOM_DATA)?;
        self.writer
            .write_event(Event::Start(BytesStart::new(custom_data_tag)))?;

        for item in custom_data.get_items().iter() {
            // Need to evaluate 'last_modification_time' before passing it to the macro.
            // Otherwise this match will be evaluated twice - first time here
            // and again while executing the expanded code
            let item_path = ["CustomData", "Item", &item.key];
            write_parent_child_tags_keeping_unknown! {
                self,
                ITEM,
                pending,
                &item_path,
                KEY, &item.key,
                VALUE, &item.value,
                LAST_MODIFICATION_TIME, match item.last_modification_time {
                    Some(ref d) => {
                        util::encode_datetime(d)
                    } ,
                    None => {
                        util::empty_str()}
                }
            };
        }

        let kept = pending.take(&["CustomData"]);
        self.write_unknown_elements(kept)?;

        self.writer
            .write_event(Event::End(BytesEnd::new(custom_data_tag)))?;

        Ok(())
    }

    fn write_group(&mut self, group_uuid: &uuid::Uuid, root: &Root) -> Result<()> {
        let group_tag = std::str::from_utf8(GROUP)?;
        if let Some(group) = root.group_by_id(group_uuid) {
            self.writer
                .write_event(Event::Start(BytesStart::new(group_tag)))?;

            // The tags are written in this order (as KeePassXC KdbxXmlWriter). If we want change the
            // order of tags, then call the write_* macros in that required sequences accordingly

            write_tags! { self,
                UUID,util::encode_uuid(&group.uuid),
                NAME, group.name,
                NOTES, group.notes
            };

            write_tags_or_skip_empty! { self,TAGS,group.tags};

            write_tags! { self, ICON_ID,group.icon_id.to_string() };

            write_opt_val_tags_or_skip! { self,
                CUSTOM_ICON_UUID, group.custom_icon_uuid.map(|uuid|util::encode_uuid(&uuid))
            }

            let mut pending = PendingUnknowns::new(&group.unknown_elements);

            self.write_times(&group.times, &mut pending)?;

            write_tags! { self,
                IS_EXPANDED, bool_to_xml_bool(group.is_expanded),
                DEFAULT_AUTO_TYPE_SEQUENCE, group.default_auto_type_sequence.as_deref().unwrap_or_default(),
                ENABLE_AUTO_TYPE, opt_bool_to_xml(group.enable_auto_type),
                ENABLE_SEARCHING, opt_bool_to_xml(group.enable_searching),
                LAST_TOP_VISIBLE_ENTRY, util::encode_uuid(&group.last_top_visible_entry)
            };

            //Custom Data
            self.write_custom_data(&group.custom_data, &mut pending)?;

            if group.previous_parent_group != uuid::Uuid::default() {
                write_tags! { self, PREVIOUS_PARENT_GROUP, util::encode_uuid(&group.previous_parent_group) };
            }

            let kept = pending.take(&[]);
            self.write_unknown_elements(kept)?;
            report_unwritten(&pending, "Group");

            for e_uuid in group.entry_uuids.iter() {
                self.write_entry(e_uuid, root.all_entries(), false)?;
            }

            for g_uuid in group.group_uuids.iter() {
                self.write_group(g_uuid, root)?;
            }

            self.writer
                .write_event(Event::End(BytesEnd::new(group_tag)))?;
        } else {
            return Err(Error::DataError(
                "Writing group failed as no value found in the lookup map",
            ));
        }

        Ok(())
    }

    // Writes the AutoType tag and its children
    fn write_entry_auto_type(
        &mut self,
        auto_type: &AutoType,
        pending: &mut PendingUnknowns,
    ) -> Result<()> {
        let tag_element = std::str::from_utf8(AUTO_TYPE)?;
        self.writer
            .write_event(Event::Start(BytesStart::new(tag_element)))?;
        write_tags! { self,
            ENABLED, bool_to_xml_bool(auto_type.enabled),
            DATA_TRANSFER_OBFUSCATION, auto_type.data_transfer_obfuscation.to_string(),
            DEFAULT_SEQUENCE,  auto_type.default_sequence.as_ref().map_or("", |s| s)
        };

        // Writes Association tag and its children. Associations have no key of their own,
        // so an unknown element inside one is addressed by position (as read)
        for (index, association) in auto_type.associations.iter().enumerate() {
            let association_path = ["AutoType", "Association", &index.to_string()];
            write_parent_child_tags_keeping_unknown! {
                self,
                ASSOCIATION,
                pending,
                &association_path,
                WINDOW, association.window,
                KEY_STROKE_SEQUENCE, association.key_stroke_sequence.as_ref().map_or("", |s| s)
            };
        }

        let kept = pending.take(&["AutoType"]);
        self.write_unknown_elements(kept)?;

        self.writer
            .write_event(Event::End(BytesEnd::new(tag_element)))?;
        Ok(())
    }

    fn write_entry_data(&mut self, entry: &Entry, in_history: bool) -> Result<()> {
        //let temp_title = entry.entry_field.find_key_value("Title");
        //debug!("Start of writing the entry with Title {:?}", temp_title);

        let tag_element = std::str::from_utf8(ENTRY)?;
        self.writer
            .write_event(Event::Start(BytesStart::new(tag_element)))?;

        // Element order as in KeePassXC (KdbxXmlWriter::writeEntry)
        write_tags! { self,
            UUID, util::encode_uuid(&entry.uuid), //entry.uuid.to_string(),
            ICON_ID,entry.icon_id.to_string()
        };

        write_tags_or_skip_empty! {
            self,
            CUSTOM_ICON_UUID, entry.custom_icon_uuid.map_or_else(empty_str,|uuid|util::encode_uuid(&uuid))
        }

        write_tags! { self,
            FOREGROUND_COLOR, entry.foreground_color,
            BACKGROUND_COLOR, entry.background_color,
            OVERRIDE_URL, entry.override_url,
            TAGS,entry.tags
        };

        let mut pending = PendingUnknowns::new(&entry.unknown_elements);

        // Times tag and the children
        self.write_times(&entry.times, &mut pending)?;

        // KDBX 4.1 elements, written only when not default (as KeePass / KeePassXC)
        if !entry.quality_check {
            write_tags! { self, QUALITY_CHECK, "False" };
        }
        if entry.previous_parent_group != uuid::Uuid::default() {
            write_tags! { self, PREVIOUS_PARENT_GROUP, util::encode_uuid(&entry.previous_parent_group) };
        }

        // The String tag has childeren with attributes
        let empty_attr: Vec<(&str, &str)> = vec![];
        for s in entry.entry_field.get_key_values().iter() {
            //debug!("Writing kvs {:?}",s);

            let mut vp = vec![];
            // TODO: Need to find a better way to get the encrypted data
            // We need to create a temp var _e outside the 'if protected' block so that encrypted data can be used later.
            // Setting content = &self.stream_cipher.process_content_b64_str fails with error
            // "temporary value dropped while borrowed",
            // "creates a temporary which is freed while still in use"
            let mut _e = String::new();
            let mut content = &s.value;
            if s.protected {
                vp.push(("Protected", "True"));
                //IMPORTANT:
                // We should use stream cipher to encrypt only if content is not empty
                // Otherwise cipher call will return an error
                if !s.value.is_empty() {
                    if let Some(ref mut cipher) = &mut self.stream_cipher {
                        _e = cipher.process_content_b64_str(&s.value)?;
                        content = &_e;
                    }
                }
            }

            let string_path = ["String", &s.key];
            write_parent_child_with_attributes_keeping_unknown! {
                self,
                STRING,
                pending,
                &string_path,
                KEY, empty_attr, s.key,
                VALUE, vp, content
            };
        }
        // Binary tag for attachment where Value tag has an attribute
        for b in entry.binary_key_values.iter() {
            let binary_path = ["Binary", &b.key];
            write_parent_child_with_attributes_keeping_unknown! {
                self,
                BINARY,
                pending,
                &binary_path,
                KEY, empty_attr, b.key,
                VALUE, [("Ref", b.index_ref.to_string().as_str())],b.value
            };
        }
        self.write_entry_auto_type(&entry.auto_type, &mut pending)?;

        // Custom Data of the entry
        self.write_custom_data(&entry.custom_data, &mut pending)?;

        let kept = pending.take(&[]);
        self.write_unknown_elements(kept)?;

        // We need to exclude the History tag while writing the child Entry tag that comes under the History tag
        if !in_history {
            let history_tag_element = std::str::from_utf8(HISTORY)?;
            self.writer
                .write_event(Event::Start(BytesStart::new(history_tag_element)))?;
            for e in entry.history.entries.iter() {
                self.write_entry_data(e, true)?;
            }
            let kept = pending.take(&["History"]);
            self.write_unknown_elements(kept)?;
            self.writer
                .write_event(Event::End(BytesEnd::new(history_tag_element)))?;
        }
        report_unwritten(&pending, "Entry");

        self.writer
            .write_event(Event::End(BytesEnd::new(tag_element)))?;

        //debug!("End of writing the entry with Title {:?}", temp_title);
        Ok(())
    }

    fn write_entry(
        &mut self,
        entry_uuid: &uuid::Uuid,
        all_entries: &HashMap<uuid::Uuid, Entry>,
        in_history: bool,
    ) -> Result<()> {
        if let Some(entry) = all_entries.get(entry_uuid) {
            self.write_entry_data(entry, in_history)
        } else {
            Err(Error::DataError(
                "Writing entry failed as no value found in the lookup map",
            ))
        }
    }

    fn write_root(&mut self, kp: &KeepassFile) -> Result<()> {
        let tag_element = std::str::from_utf8(ROOT)?;
        self.writer
            .write_event(Event::Start(BytesStart::new(tag_element)))?;
        self.write_group(&kp.root.root_uuid(), &kp.root)?;

        let mut pending = PendingUnknowns::new(&kp.root.unknown_elements);
        self.write_deleted_objects(&kp.root, &mut pending)?;

        let kept = pending.take(&[]);
        self.write_unknown_elements(kept)?;
        report_unwritten(&pending, "Root");

        self.writer
            .write_event(Event::End(BytesEnd::new(tag_element)))?;
        Ok(())
    }

    pub fn write(&mut self, kp: &KeepassFile) -> Result<()> {
        //<?xml version="1.0" encoding="utf-8" standalone="yes"?>
        self.writer.write_event(Event::Decl(BytesDecl::new(
            "1.0",
            Some("utf-8"),
            Some("yes"),
        )))?;

        let tag_element = std::str::from_utf8(KEEPASS_FILE)?;

        self.writer
            .write_event(Event::Start(BytesStart::new(tag_element)))?;
        self.write_meta(kp)?;
        self.write_root(kp)?;

        let mut pending = PendingUnknowns::new(&kp.unknown_elements);
        let kept = pending.take(&[]);
        self.write_unknown_elements(kept)?;
        report_unwritten(&pending, "KeePassFile");

        self.writer
            .write_event(Event::End(BytesEnd::new(tag_element)))?;
        Ok(())
    }
}

pub fn write_xml(
    kp: &KeepassFile,
    cipher: Option<ProtectedContentStreamCipher>,
) -> Result<Vec<u8>> {
    log::debug!("Going to write the xml string ...");
    let mut xml_writer = XmlWriter::new(Cursor::new(Vec::new()), cipher);
    xml_writer.write(kp)?;
    // First into_inner() returns the inner writer Cursor and second into_inner() gives the underlying 'Vec'
    let v = xml_writer.writer.into_inner().into_inner();
    //debug!("In write_xml method: XML content is \n {}", std::str::from_utf8(&v).unwrap()); //Need to use {} and not the debug one {:?} to avoid \" in the print
    Ok(v)
}

pub fn write_xml_with_indent(
    kp: &KeepassFile,
    cipher: Option<ProtectedContentStreamCipher>,
) -> Result<Vec<u8>> {
    log::info!("Going to write the xml string ...");
    let mut xml_writer = XmlWriter::new_with_indent(Cursor::new(Vec::new()), cipher);
    xml_writer.write(kp)?;
    // First into_inner() returns the inner writer Cursor and second into_inner() gives the underlying 'Vec'
    let v = xml_writer.writer.into_inner().into_inner();
    //println!("In write_xml method: XML content is \n {}", std::str::from_utf8(&v).unwrap()); //Need to use {} and not the debug one {:?} to avoid \" in the print
    Ok(v)
}

////////////////////////  Xml based Key file ////////////////

// For now FileKeyXmlReader and FileKeyXmlWriter are using similar struct XmlReader and XmlWriter
// but with FileKey xml specific methods supported
pub struct FileKeyXmlReader<'a> {
    reader: QuickXmlReader<&'a [u8]>,
    // We need this dummy member just to reuse the macros that are used for reading and writing databse xml content
    stream_cipher: Option<ProtectedContentStreamCipher>,
}

impl<'a> FileKeyXmlReader<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        let mut qxmlreader = QuickXmlReader::from_reader(data);
        qxmlreader.config_mut().trim_text(true);
        // qxmlreader.trim_text(true);
        FileKeyXmlReader {
            reader: qxmlreader,
            stream_cipher: None,
        }
    }

    // Key files are only read, never written back - unknown elements are not kept
    // and the element path (see XmlReader) is not needed either
    fn keep_unknown(&mut self, _parent_tag: &[u8], _element: UnknownElement) {}

    fn enter_tag(&mut self, _tag: &[u8]) {}

    fn leave_tag(&mut self) {}

    pub fn parse(&mut self) -> Result<KeyFileData> {
        let mut buf: Vec<u8> = vec![];
        let mut xml_decl_available = false;
        let mut key_file_data = KeyFileData::default();
        loop {
            match self.reader.read_event_into(&mut buf) {
                Ok(Event::Decl(ref _e)) => {
                    xml_decl_available = true;
                    // return Err(Error::NotXmlKeyFile);
                }
                Ok(Event::DocType(_)) => {}
                Ok(Event::PI(_)) => {}
                Ok(Event::Text(_)) => {}
                // A general entity reference (e.g. `&amp;`) is now reported as its own
                // event (quick-xml 0.38+) instead of being inlined into Event::Text.
                Ok(Event::GeneralRef(_)) => {}

                Ok(Event::Start(ref e)) => {
                    if !xml_decl_available {
                        return Err(Error::NotXmlKeyFile);
                        // return Err(Error::XmlReadingFailed(format!(
                        //     "Xml content does not have XML decl"
                        // )));
                    }
                    match e.name().as_ref() {
                        KEY_FILE => {
                            self.read_top_level(&mut key_file_data)?;
                        }
                        x => {
                            //debug!("MAIN: in match {:?}", std::str::from_utf8(e.name()).unwrap());
                            //debug!("MAIN: in match {:?} KEEPASS_FILE", std::str::from_utf8(KEEPASS_FILE).unwrap());
                            return Err(Error::XmlReadingFailed(format!(
                                "Unexpected starting tag {:?}",
                                std::str::from_utf8(x)
                            )));
                        }
                    }
                }

                Ok(Event::Empty(ref _e)) => {}
                Ok(Event::End(ref _e)) => {
                    // KeyFile end tag should have been consumed in read_top_level
                    //info!("PARSE:End of tag {:?}", self.reader.decode(e));
                }

                Ok(Event::CData(ref _e)) => {}

                Ok(Event::Comment(ref _e)) => {}

                Ok(Event::Eof) => {
                    if !xml_decl_available {
                        return Err(Error::NotXmlKeyFile);
                    }
                    break;
                }

                Err(e) => {
                    if !xml_decl_available {
                        return Err(Error::NotXmlKeyFile);
                    } else {
                        return Err(Error::from(e));
                    }
                }
            }
        }
        Ok(key_file_data)
    }

    fn read_top_level(&mut self, key_file_data: &mut KeyFileData) -> Result<()> {
        read_tags!(self,
            start_tag_fns {},
            start_tag_blks {
                KEY_FILE_META => {
                    self.read_meta(key_file_data)?;
                },
                KEY_FILE_KEY => {
                    self.read_key(key_file_data)?;
                }
            },
            empty_tags {},
            KEY_FILE);

        Ok(())
    }

    fn read_meta(&mut self, key_file_data: &mut KeyFileData) -> Result<()> {
        read_tags!(self,
            start_tag_fns {
                KEY_FILE_VERSION =>
                (|content:String, _,  _|
                    key_file_data.version  = Some(content)
                )
            },
            start_tag_blks {},
            empty_tags {},
            KEY_FILE_META
        );

        if key_file_data.version.is_none() || key_file_data.version != Some("2.0".into()) {
            return Err(Error::UnsupportedXmlKeyFileVersion);
        }

        Ok(())
    }

    fn read_key(&mut self, key_file_data: &mut KeyFileData) -> Result<()> {
        read_tags!(self,
            start_tag_fns {
                KEY_FILE_DATA =>
                (|content:String, attributes:&mut Attributes,  _| {
                    let format_removed_content = Self::remove_formatting(&content);
                    key_file_data.data  = Some(format_removed_content);
                    key_file_data.hash = Self::read_data_hash(attributes);
                })
            },
            start_tag_blks {},
            empty_tags {},
            KEY_FILE_KEY
        );

        Ok(())
    }

    #[inline]
    fn remove_formatting(data: &str) -> String {
        data.split_whitespace().collect::<Vec<_>>().join("")
    }

    fn read_data_hash(attributes: &mut Attributes) -> Option<String> {
        let mut data_hash: Option<String> = None;
        let mut v = attributes
            .by_ref()
            .filter_map(|a| a.ok())
            .collect::<Vec<_>>();
        // Expected at leaset one attribute or no attributes for the the tag <Data>
        // e.g <Data Hash="F205E6EB">
        if !v.is_empty() {
            match v.pop() {
                Some(Attribute {
                    key: QName(KEY_FILE_DATA_HASH),
                    value: x,
                }) => {
                    //debug!("!!!!!! in fn attributes of Value are {:?}",v);
                    if let std::borrow::Cow::Borrowed(a) = x {
                        // println!("@@@@ a is {:?}", std::str::from_utf8(a).ok());
                        data_hash = std::str::from_utf8(a).map(|s| s.to_string()).ok();
                    }
                }
                // Log as error if these happen when reading other KeePass app generated
                // xml. This may happen if such apps introduce app specific changes. So far we never saw these
                Some(x) => error!(
                "Some unexpected attribute {:?} for the protected value for String -> Value tag",
                x
            ),
                None => error!("No protected attribute for this Value tag - String -> Value tag"),
            }
        }

        data_hash
    }
}

pub struct FileKeyXmlWriter<W: Write> {
    writer: QuickXmlWriter<W>,
}

impl<W: Write> FileKeyXmlWriter<W> {
    pub fn new_with_indent(writer: W) -> Self {
        Self {
            writer: QuickXmlWriter::new_with_indent(writer, b" "[0], 2),
        }
    }

    fn write_meta(&mut self, _key_file_data: &KeyFileData) -> Result<()> {
        let tag_element = std::str::from_utf8(KEY_FILE_META)?;
        self.writer
            .write_event(Event::Start(BytesStart::new(tag_element)))?;

        write_tags! { self,
            KEY_FILE_VERSION, "2.0"
        };
        self.writer
            .write_event(Event::End(BytesEnd::new(tag_element)))?;

        Ok(())
    }

    fn write_key_data(&mut self, key_file_data: &KeyFileData) -> Result<()> {
        let h = key_file_data
            .hash
            .as_ref()
            .map_or_else(|| "".into(), |s| s.clone());
        let d = key_file_data
            .data
            .as_ref()
            .map_or_else(|| "".into(), |s| s.clone());

        let fs = Self::format_hash_data(&d);
        write_parent_child_with_attributes! {
            self,
            KEY_FILE_KEY,
            KEY_FILE_DATA, [("Hash", h.as_str())], fs.as_str()

        };
        Ok(())
    }

    // These formatting are not required. As other implementations are formatting the
    // key xml file, a simple formatting attempt is done here
    fn format_hash_data(data: &str) -> String {
        // Splits the full hex string into 8 sub strings of each size 8
        let r = util::sub_strings(data, 8);
        // Split the vec r into two groups of 4 members each
        let ss = r.split_at(4);
        // Form str from each group
        let s1 = ss.0.to_vec().join(" ");
        let s2 = ss.1.to_vec().join(" ");
        // Final formatted text to use as Text of <Data> tag
        ["\n          ", &s1, "\n          ", &s2, "\n    "].join("")
    }

    pub fn write(&mut self, key_file_data: &KeyFileData) -> Result<()> {
        self.writer
            .write_event(Event::Decl(BytesDecl::new("1.0", Some("UTF-8"), None)))?;

        let tag_element = std::str::from_utf8(KEY_FILE)?;

        self.writer
            .write_event(Event::Start(BytesStart::new(tag_element)))?;

        self.write_meta(key_file_data)?;
        self.write_key_data(key_file_data)?;

        self.writer
            .write_event(Event::End(BytesEnd::new(tag_element)))?;

        Ok(())
    }
}

// cargo test test_mod_name::test_fn_name -- --exact
// Need to use " cargo test -- --nocapture " to see println! output in the console
// cargo test -- --show-output
// To use "env_logger" in tests use 'RUST_LOG=xml_parse=info cargo test read_sample_xml'
// However, Log events will be captured by `cargo` and only printed if the test fails. So see all log messages
// the test needs to fail !

#[cfg(test)]
#[allow(unused)]
mod tests {

    use super::*;
    use std::env;
    use std::fs;
    use std::path::PathBuf;

    // --- Non-ignored unit tests ---

    // Step 17 / 18: elements the core does not know are kept wherever they stood
    const UNKNOWN_XML: &str = r#"<?xml version="1.0" encoding="utf-8" standalone="yes"?>
<KeePassFile>
  <Meta>
    <Generator>test</Generator>
    <XMeta a="1"/>
  </Meta>
  <Root>
    <Group>
      <UUID>Wg46TgAAQACAAAAAAAAAAQ==</UUID>
      <Name>Root</Name>
      <Tags/>
      <XGroup>text &amp; more<Inner k="v">x</Inner></XGroup>
      <Entry>
        <UUID>Wg46TgAAQACAAAAAAAAAEA==</UUID>
        <Times>
          <XInTimes>dropped</XInTimes>
        </Times>
        <OverrideURL/>
        <XEntry/>
      </Entry>
    </Group>
  </Root>
</KeePassFile>"#;

    // Tag of every unknown element of this owner, with the path it was read at
    fn kept(store: &UnknownElements) -> Vec<(Vec<&str>, &str)> {
        store
            .iter()
            .map(|(path, element)| {
                (
                    path.iter().map(|p| p.as_str()).collect(),
                    element.tag.as_str(),
                )
            })
            .collect()
    }

    #[test]
    fn unknown_elements_are_kept_with_their_path() {
        let kp = parse(UNKNOWN_XML.as_bytes(), None).unwrap();

        let meta_unknown: Vec<_> = kp.meta.unknown_elements.iter().collect();
        assert_eq!(meta_unknown.len(), 1);
        assert!(meta_unknown[0].0.is_empty(), "directly in Meta");
        assert_eq!(meta_unknown[0].1.tag, "XMeta");
        assert_eq!(
            meta_unknown[0].1.attrs,
            vec![("a".to_string(), "1".to_string())]
        );

        let group = kp.root.group_by_id(&kp.root.root_uuid()).unwrap();
        // <Tags/> is a known empty element, not an unknown one
        assert_eq!(kept(&group.unknown_elements), vec![(vec![], "XGroup")]);
        let x_group = group.unknown_elements.iter().next().unwrap().1;
        assert_eq!(x_group.text, "text & more");
        assert_eq!(x_group.children[0].tag, "Inner");
        assert_eq!(x_group.children[0].text, "x");

        let entry = kp.root.all_entries().values().next().unwrap();
        // <OverrideURL/> is known; <XInTimes> is kept with the path it stood at (Step 18:
        // before that it was dropped, as nothing held elements below an entry)
        assert_eq!(
            kept(&entry.unknown_elements),
            vec![(vec!["Times"], "XInTimes"), (vec![], "XEntry")]
        );
    }

    // Text fields are unescaped once on read and escaped once on write: "A & B" stays "A & B"
    // after any number of saves (before Step 17 names and tags gained "&amp;" on every save)
    #[test]
    fn escaped_text_survives_read_write_read() {
        let xml = r#"<?xml version="1.0" encoding="utf-8" standalone="yes"?>
<KeePassFile>
  <Meta>
    <DatabaseName>Db &amp; Co &lt;x&gt;</DatabaseName>
    <DefaultUserName>me &amp; you</DefaultUserName>
  </Meta>
  <Root>
    <Group>
      <UUID>Wg46TgAAQACAAAAAAAAAAQ==</UUID>
      <Name>A &amp; B</Name>
      <Tags>g&amp;h</Tags>
      <Entry>
        <UUID>Wg46TgAAQACAAAAAAAAAEA==</UUID>
        <Tags>x&amp;y;z</Tags>
        <String><Key>K &amp; k</Key><Value>v &amp; v</Value></String>
      </Entry>
    </Group>
  </Root>
</KeePassFile>"#;
        let first = parse(xml.as_bytes(), None).unwrap();
        let written = write_xml(&first, None).unwrap();
        let second = parse(&written, None).unwrap();

        for kp in [&first, &second] {
            assert_eq!(kp.meta.database_name, "Db & Co <x>");
            assert_eq!(kp.meta.default_user_name, "me & you");
            let group = kp.root.group_by_id(&kp.root.root_uuid()).unwrap();
            assert_eq!(group.name, "A & B");
            assert_eq!(group.tags, "g&h");
            let entry = kp.root.all_entries().values().next().unwrap();
            assert_eq!(entry.tags, "x&y;z");
            let kv = entry.entry_field.find_key_value("K & k").unwrap();
            assert_eq!(kv.value, "v & v");
        }
    }

    #[test]
    fn unknown_elements_are_written_back() {
        let kp = parse(UNKNOWN_XML.as_bytes(), None).unwrap();
        let xml = String::from_utf8(write_xml(&kp, None).unwrap()).unwrap();

        assert!(xml.contains(r#"<XMeta a="1"/>"#), "{}", xml);
        assert!(
            xml.contains(r#"<XGroup>text &amp; more<Inner k="v">x</Inner></XGroup>"#),
            "{}",
            xml
        );
        assert!(xml.contains("<XEntry/>"), "{}", xml);
        // Back inside <Times>, where it was read - not at the end of the entry
        assert!(
            xml.contains("<UsageCount>0</UsageCount><XInTimes>dropped</XInTimes></Times>"),
            "{}",
            xml
        );
        assert_eq!(xml.matches("<Tags").count(), 1, "{}", xml);
    }

    #[test]
    fn content_unescape_plain_string_unchanged() {
        assert_eq!(content_unescape("hello world"), "hello world");
    }

    #[test]
    fn content_unescape_ampersand_entity() {
        assert_eq!(content_unescape("Tom &amp; Jerry"), "Tom & Jerry");
    }

    #[test]
    fn content_unescape_lt_gt_entities() {
        assert_eq!(content_unescape("a &lt; b &gt; c"), "a < b > c");
    }

    #[test]
    fn content_unescape_apostrophe_entity() {
        assert_eq!(content_unescape("Kim&apos;s idea"), "Kim's idea");
    }

    #[test]
    fn content_unescape_quot_entity() {
        assert_eq!(content_unescape("say &quot;hi&quot;"), "say \"hi\"");
    }

    #[test]
    fn content_to_int_valid_number() {
        assert_eq!(content_to_int("42".into()), 42);
    }

    #[test]
    fn content_to_int_negative_number() {
        assert_eq!(content_to_int("-7".into()), -7);
    }

    #[test]
    fn content_to_int_zero() {
        assert_eq!(content_to_int("0".into()), 0);
    }

    #[test]
    fn content_to_int_invalid_returns_minus_one() {
        assert_eq!(content_to_int("notanumber".into()), -1);
    }

    #[test]
    fn content_to_int_empty_returns_minus_one() {
        assert_eq!(content_to_int("".into()), -1);
    }

    #[test]
    fn content_to_bool_true_lowercase() {
        assert!(content_to_bool("true".into()));
    }

    #[test]
    fn content_to_bool_true_uppercase() {
        assert!(content_to_bool("True".into()));
    }

    #[test]
    fn content_to_bool_true_mixed_case() {
        assert!(content_to_bool("TRUE".into()));
    }

    #[test]
    fn content_to_bool_false_string() {
        assert!(!content_to_bool("false".into()));
    }

    #[test]
    fn content_to_bool_empty_is_false() {
        assert!(!content_to_bool("".into()));
    }

    #[test]
    fn bool_to_xml_bool_true_produces_true_string() {
        assert_eq!(bool_to_xml_bool(true), "True");
    }

    #[test]
    fn bool_to_xml_bool_false_produces_false_string() {
        assert_eq!(bool_to_xml_bool(false), "False");
    }

    #[test]
    fn file_key_xml_roundtrip_produces_valid_checksum() {
        use crate::db::KeyFileData;
        let key_file_data = KeyFileData::generate_key_data().unwrap();

        let mut xml_writer = FileKeyXmlWriter::new_with_indent(std::io::Cursor::new(Vec::new()));
        xml_writer.write(&key_file_data).unwrap();

        let v = xml_writer.writer.into_inner().into_inner();
        let xs = std::str::from_utf8(&v).unwrap();

        let mut reader = FileKeyXmlReader::new(xs.as_bytes());
        let parsed: crate::error::Result<KeyFileData> = reader.parse();
        assert!(parsed.is_ok());
        assert!(parsed.unwrap().verify_checksum().is_ok());
    }

    #[test]
    fn file_key_xml_contains_required_elements() {
        use crate::db::KeyFileData;
        let key_file_data = KeyFileData::generate_key_data().unwrap();

        let mut xml_writer = FileKeyXmlWriter::new_with_indent(std::io::Cursor::new(Vec::new()));
        xml_writer.write(&key_file_data).unwrap();

        let v = xml_writer.writer.into_inner().into_inner();
        let xml_str = std::str::from_utf8(&v).unwrap();

        assert!(xml_str.contains("KeyFile"));
        assert!(xml_str.contains("Version"));
        assert!(xml_str.contains("2.0"));
        assert!(xml_str.contains("Data"));
    }

    // To see logging output during testing in VS Code
    fn init() {
        let _ = env_logger::builder()
            // Include all events in tests
            .filter_level(log::LevelFilter::max())
            // Ensure events are captured by `cargo test`
            .is_test(true)
            // Ignore errors initializing the logger if tests race to configure it
            .try_init();
    }
    #[test]
    fn verify_escape_unescape() {
        let s = "asddaads\nKim's idea";
        let es = quick_xml::escape::escape(s);
        //println!("escaped {:?}", es);
        assert_eq!(es, "asddaads\nKim&apos;s idea");

        let ues = quick_xml::escape::unescape(&es);
        //println!("unescaped {:?}", ues);
        assert!(ues.is_ok());
        assert_eq!(ues.unwrap(), "asddaads\nKim's idea");

        // Here unicode U+2019 ’ is used and that is not escaped
        let es2 = "My name&amp;apos;s none ddd\n\nThe name’s of nature….  Boy’s name\n\n";
        let ues2 = quick_xml::escape::unescape(es2);
        //println!("unescaped {:?}", ues2);
        assert!(ues2.is_ok());
        // &amp;apos;s on unescape &apos;s
        // Only &amp;  -> &
        assert_eq!(
            ues2.unwrap(),
            "My name&apos;s none ddd\n\nThe name’s of nature….  Boy’s name\n\n"
        );
    }

    #[test]
    fn read_database_xml_without_declaration() {
        let xml = r#"<KeePassFile>
            <Meta>
                <Generator>OneKeePass</Generator>
            </Meta>
            <Root>
                <Group>
                    <UUID>3aBY+AcLQmiPas0vjK2zng==</UUID>
                    <Name>Root</Name>
                </Group>
            </Root>
        </KeePassFile>"#;

        let mut reader = XmlReader::new(xml.as_bytes(), None);
        assert!(reader.parse().is_ok());
    }
    #[test]
    fn read_sample_text_xml() {
        init();
        log::info!("This record will be captured by `cargo test`");
        let xml = r#"
        <?xml version="1.0" encoding="utf-8" standalone="yes"?>
        <KeePassFile>
            <Meta> 
                <Generator>OneKeePass</Generator> 
            </Meta>
            <UnhandledTag> </UnhandledTag> 
            <Root> 
                <Group>
                    <UUID>3aBY+AcLQmiPas0vjK2zng==</UUID>
                    <Name>Root</Name>
                    <Notes>Some text comes here</Notes>
                    <IconID>48</IconID>
                    <Times>
                        <CreationTime>J9pg1g4AAAA=</CreationTime>
                        <LastModificationTime>J9pg1g4AAAA=</LastModificationTime>
                        <LastAccessTime>/OZp2A4AAAA=</LastAccessTime>
                        <ExpiryTime>J9pg1g4AAAA=</ExpiryTime>
                        <Expires>False</Expires>
                        <UsageCount>4</UsageCount>
                        <LocationChanged>J9pg1g4AAAA=</LocationChanged>        
                    </Times>
                    <Group>
                        <Name>MyGroup1</Name>
                        <UUID>RRITlCo4TMKXYUPQ09yAvw==</UUID>
                        <IconID>59</IconID>
                        <Tags/>
                        <Notes>This is my first group.
                            Hello first</Notes>
                        <IsExpanded>True</IsExpanded>
                        <Entry>
                            <UUID>+Hf3wkQhQ46qUntgLmDGYw==</UUID>
                            <IconID>59</IconID>
                            <Tags/>
                            <Times>
                                <LastModificationTime>MNxg1g4AAAA=</LastModificationTime>
                                <CreationTime>b9tg1g4AAAA=</CreationTime>
                                <LastAccessTime>MNxg1g4AAAA=</LastAccessTime>
                                <ExpiryTime>b9tg1g4AAAA=</ExpiryTime>
                                <Expires>False</Expires>
                                <UsageCount>0</UsageCount>
                            </Times>
                                <String>
                                    <Key>UserName</Key>
                                    <Value>user1</Value>
                                </String>
                                <String>
                                    <Key>Column1</Key>
                                    <Value>This is first column</Value>
                                </String>
                                <String>
                                    <Key>Column2</Key>
                                    <Value Protected="True">dO2DjqfKUa3T7JNh3O0=</Value>
                                </String>
                                <String>
                                    <Key>Password</Key>
                                    <Value Protected="True">g2nZrW/E2dZyTpU=</Value>
                                </String>
                                <String>
                                    <Key>Notes</Key>
                                    <Value>For oracle</Value>
                                </String>
                                <String>
                                    <Key>Title</Key>
                                    <Value>My Title 1</Value>
                                </String>
                                <String>
                                    <Key>URL</Key>
                                    <Value>https://www.oracle.com</Value>
                                </String>
                                <CustomData>
                                </CustomData>
                                <AutoType>
                                    <Enabled>True</Enabled>
                                    <DefaultSequence/>
                                </AutoType>
                                <History>
                                </History>
                            </Entry>
                    </Group>
                </Group>
            </Root>
        </KeePassFile>
        "#;

        let mut reader = XmlReader::new(xml.as_bytes(), None);
        let r = reader.parse();
        if let Err(e) = &r {
            println!("Error is {:?}", e);
        }
        assert!(r.is_ok());
        println!(" Kp is {:?}", r.unwrap());
    }
    #[test]
    fn read_sample_xml_fail1() {
        init();
        log::info!("End tag is missing");
        // <!-- No end tag -->
        let xml = r#"
        <?xml version="1.0" encoding="utf-8" standalone="yes"?>
        <KeePassFile>
            <Meta> 
        </KeePassFile>
        "#;

        let mut reader = XmlReader::new(xml.as_bytes(), None);
        let r = reader.parse();
        if let Err(e) = &r {
            println!("Error is {:?}", e);
        }
        assert!(r.is_err());
    }

    // KeePass-XML sample used by `read_sample_xml` / `read_write_sample_xml`, embedded
    // directly (no external/personal fixture file). The two Protected values
    // (Column2, Password) are encrypted here with the given key, in document order,
    // so a cipher built from the same key can decrypt them back during parsing.
    // (A mismatched key would still "succeed" but leave the parser holding invalid
    // UTF-8 - the crate's process_basic64_str falls back to from_utf8_unchecked in
    // that case, which is later a panic waiting to happen, not something a test
    // should trigger on purpose.)
    fn sample_kdbx_xml(key: &Vec<u8>) -> String {
        let mut enc_cipher = ProtectedContentStreamCipher::try_from(3, key).unwrap();
        // Encrypted in the same order the fields appear below: Column2 then Password
        let column2_protected = enc_cipher
            .process_content_b64_str("protected column2 value")
            .unwrap();
        let password_protected = enc_cipher
            .process_content_b64_str("s3cret-password")
            .unwrap();

        format!(
            r#"
        <?xml version="1.0" encoding="utf-8" standalone="yes"?>
        <KeePassFile>
            <Meta>
                <Generator>OneKeePass</Generator>
            </Meta>
            <UnhandledTag> </UnhandledTag>
            <Root>
                <Group>
                    <UUID>3aBY+AcLQmiPas0vjK2zng==</UUID>
                    <Name>Root</Name>
                    <Notes>Some text comes here</Notes>
                    <IconID>48</IconID>
                    <Times>
                        <CreationTime>J9pg1g4AAAA=</CreationTime>
                        <LastModificationTime>J9pg1g4AAAA=</LastModificationTime>
                        <LastAccessTime>/OZp2A4AAAA=</LastAccessTime>
                        <ExpiryTime>J9pg1g4AAAA=</ExpiryTime>
                        <Expires>False</Expires>
                        <UsageCount>4</UsageCount>
                        <LocationChanged>J9pg1g4AAAA=</LocationChanged>
                    </Times>
                    <Group>
                        <Name>MyGroup1</Name>
                        <UUID>RRITlCo4TMKXYUPQ09yAvw==</UUID>
                        <IconID>59</IconID>
                        <Tags/>
                        <Notes>This is my first group.
                            Hello first</Notes>
                        <IsExpanded>True</IsExpanded>
                        <Entry>
                            <UUID>+Hf3wkQhQ46qUntgLmDGYw==</UUID>
                            <IconID>59</IconID>
                            <Tags/>
                            <Times>
                                <LastModificationTime>MNxg1g4AAAA=</LastModificationTime>
                                <CreationTime>b9tg1g4AAAA=</CreationTime>
                                <LastAccessTime>MNxg1g4AAAA=</LastAccessTime>
                                <ExpiryTime>b9tg1g4AAAA=</ExpiryTime>
                                <Expires>False</Expires>
                                <UsageCount>0</UsageCount>
                            </Times>
                                <String>
                                    <Key>UserName</Key>
                                    <Value>user1</Value>
                                </String>
                                <String>
                                    <Key>Column1</Key>
                                    <Value>This is first column</Value>
                                </String>
                                <String>
                                    <Key>Column2</Key>
                                    <Value Protected="True">{column2_protected}</Value>
                                </String>
                                <String>
                                    <Key>Password</Key>
                                    <Value Protected="True">{password_protected}</Value>
                                </String>
                                <String>
                                    <Key>Notes</Key>
                                    <Value>For oracle</Value>
                                </String>
                                <String>
                                    <Key>Title</Key>
                                    <Value>My Title 1</Value>
                                </String>
                                <String>
                                    <Key>URL</Key>
                                    <Value>https://www.oracle.com</Value>
                                </String>
                                <CustomData>
                                </CustomData>
                                <AutoType>
                                    <Enabled>True</Enabled>
                                    <DefaultSequence/>
                                </AutoType>
                                <History>
                                </History>
                            </Entry>
                    </Group>
                </Group>
            </Root>
        </KeePassFile>
        "#
        )
    }

    // Looks up a field value by key on the single entry `sample_kdbx_xml` creates.
    // Guards against a change (e.g. a `quick-xml` upgrade) that parses without error
    // but silently corrupts the decoded text content.
    fn sample_entry_field_value(kp: &KeepassFile, key: &str) -> Option<String> {
        kp.root
            .all_entries()
            .values()
            .next()
            .and_then(|e| {
                e.entry_field
                    .get_key_values()
                    .into_iter()
                    .find(|kv| kv.key == key)
            })
            .map(|kv| kv.value.clone())
    }

    #[test]
    fn read_sample_xml() {
        init();
        log::info!("This record will be captured by `cargo test`");

        let key = crate::crypto::get_random_bytes::<32>().unwrap();
        let xml = sample_kdbx_xml(&key);
        let cipher = ProtectedContentStreamCipher::try_from(3, &key).unwrap();

        let mut reader = XmlReader::new(xml.as_bytes(), Some(cipher));
        let r = reader.parse();
        if let Err(e) = &r {
            println!("Error is {:?}", e);
        }
        assert!(r.is_ok());
        let kp = r.unwrap();
        println!(" Kp is {:?}", kp);

        // Plain (non-Protected) field values must survive decoding unchanged.
        assert_eq!(
            sample_entry_field_value(&kp, "UserName").as_deref(),
            Some("user1")
        );
        assert_eq!(
            sample_entry_field_value(&kp, "Title").as_deref(),
            Some("My Title 1")
        );
        assert_eq!(
            sample_entry_field_value(&kp, "URL").as_deref(),
            Some("https://www.oracle.com")
        );
        assert_eq!(
            sample_entry_field_value(&kp, "Notes").as_deref(),
            Some("For oracle")
        );
        // Protected fields decrypt with the same key used to encrypt them in
        // `sample_kdbx_xml`, so their plaintext must also come through unchanged.
        assert_eq!(
            sample_entry_field_value(&kp, "Password").as_deref(),
            Some("s3cret-password")
        );
        assert_eq!(
            sample_entry_field_value(&kp, "Column2").as_deref(),
            Some("protected column2 value")
        );
    }

    #[test]
    fn read_write_sample_xml() {
        let key = crate::crypto::get_random_bytes::<32>().unwrap();
        let xml = sample_kdbx_xml(&key);
        let cipher = ProtectedContentStreamCipher::try_from(3, &key).unwrap();

        let mut reader = super::XmlReader::new(xml.as_bytes(), Some(cipher));
        let r = reader.parse();
        if let Err(e) = &r {
            println!("Error is {:?}", e);
        }
        assert!(r.is_ok());

        let cipher = ProtectedContentStreamCipher::try_from(3, &key).unwrap();
        let kp = r.unwrap();

        let write_result = write_xml_with_indent(&kp, Some(cipher));
        if let Err(e) = &write_result {
            println!("Error is {:?}", e);
        }
        assert!(write_result.is_ok());

        // Re-parse what was just written and compare against the original values -
        // guards the write path the same way `read_sample_xml` guards the read path
        // (a fresh cipher instance is needed on each side: the stream cipher is
        // stateful, and both the write above and this re-parse consume its
        // keystream from the start, independently of each other).
        let xml_content = write_result.unwrap();
        let reparse_cipher = ProtectedContentStreamCipher::try_from(3, &key).unwrap();
        let mut reparse_reader = XmlReader::new(&xml_content[..], Some(reparse_cipher));
        let reparsed = reparse_reader.parse();
        assert!(
            reparsed.is_ok(),
            "re-parsing written xml failed: {:?}",
            reparsed
        );
        let reparsed_kp = reparsed.unwrap();

        for field in ["UserName", "Title", "URL", "Notes", "Password", "Column2"] {
            assert_eq!(
                sample_entry_field_value(&kp, field),
                sample_entry_field_value(&reparsed_kp, field),
                "field {field} changed across write+re-parse round trip"
            );
        }

        // Use the following to print the xml content output to the console for visual inspection

        // // Need to use {} and not the debug one {:?} to avoid \" in the printed output
        // println!(
        //     "XML content is \n {}",
        //     std::str::from_utf8(&xml_content).unwrap()
        // );
    }

    // Key xml file related reading and writing tests
    #[test]
    fn verify_reading_file_key_xml() {
        // Data text is formatted
        let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
        <KeyFile>
            <Meta>
                <Version>2.0</Version>
            </Meta>
            <Key>
                <Data Hash="F205E6EB">
                    ABA681B2 C6E19C74 E671EDEC 41D5AC09
                    9089F4B4 605937B5 B3E211AD 0056B325
                </Data>
            </Key>
        </KeyFile>
        "#;

        // Data text is one line
        // let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
        // <KeyFile>
        //     <Meta>
        //         <Version>2.0</Version>
        //     </Meta>
        //     <Key>
        //         <Data Hash="F205E6EB">ABA681B2C6E19C74E671EDEC41D5AC099089F4B4605937B5B3E211AD0056B325</Data>
        //     </Key>
        // </KeyFile>
        // "#;

        let mut reader = FileKeyXmlReader::new(xml.as_bytes());

        let r: Result<KeyFileData> = reader.parse();

        assert!(r.is_ok());
        let r1 = r.unwrap();
        println!(" r1 is {:?}", r1);
        assert!(r1.verify_checksum().is_ok());
    }
    #[test]
    fn verify_write_file_key_xml() {
        let data = "ABA681B2C6E19C74E671EDEC41D5AC099089F4B4605937B5B3E211AD0056B325";

        let key_file_data = KeyFileData {
            version: Some("2.0".into()),
            hash: Some("F205E6EB".into()),
            data: Some(data.into()),
        };

        let mut xml_writer = FileKeyXmlWriter::new_with_indent(Cursor::new(Vec::new()));
        let w = xml_writer.write(&key_file_data);
        assert!(w.is_ok());

        // First into_inner() returns the inner writer Cursor and second into_inner() gives the underlying 'Vec'
        let v = xml_writer.writer.into_inner().into_inner();
        let xs = std::str::from_utf8(&v).unwrap();

        // println!("In write_xml method: XML content is \n{}", &xs);

        // Read back and verify
        let mut reader = FileKeyXmlReader::new(xs.as_bytes());
        let r: Result<KeyFileData> = reader.parse();
        assert!(r.is_ok());
        let r1 = r.unwrap();

        assert!(r1.verify_checksum().is_ok());
    }
    #[test]
    fn verify_generate_xml_key() {
        let r = KeyFileData::generate_key_data();
        let key_file_data = r.unwrap();

        //println!("kd is {:?}",key_file_data);

        let mut xml_writer = FileKeyXmlWriter::new_with_indent(Cursor::new(Vec::new()));
        let w = xml_writer.write(&key_file_data);
        assert!(w.is_ok());

        let v = xml_writer.writer.into_inner().into_inner();
        let xs = std::str::from_utf8(&v).unwrap();

        //println!("In write_xml method: XML content is \n{}", &xs);

        // Read back and verify
        let mut reader = FileKeyXmlReader::new(xs.as_bytes());
        let r: Result<KeyFileData> = reader.parse();
        assert!(r.is_ok());
        let r1 = r.unwrap();

        assert!(r1.verify_checksum().is_ok());
    }
}

// If the content ($txt) is a string with value "NO_TAG", not even an empty tag is written
// Instead of using NO_Tag, we may pass vec of tags for which no empty tag is written if $txt.isEmpty()

// const NO_TAG: &str = "NO_TAG";

// macro_rules! write_tags_or_skip_tag {
//     ($self:ident, $($tag_name:expr, $txt:expr),*) => {
//         // Write empty tag if the content passed in $txt is a empty string
//         // $txt should be evaluated once and reuse. Otherwise it will be evaluated
//         // each time it is used
//         $( let val = &$txt; // $txt evaluates to a String
//             if val != NO_TAG {
//                 let name_of_tag  = std::str::from_utf8($tag_name)?;
//                 if val.is_empty() {
//                     $self.writer.write_event(Event::Empty(BytesStart::new(name_of_tag)))?;
//                 } else {
//                     $self.writer.write_event(Event::Start(BytesStart::new(name_of_tag)))?;
//                     // Creates a new BytesText from a string. The string is expected not to be escaped
//                     // quick_xml escapes the text content internally
//                     $self.writer.write_event(Event::Text(BytesText::new(val)))?;
//                     $self.writer.write_event(Event::End(BytesEnd::new(name_of_tag)))?;
//                 }
//             }
//         )*
//     };
// }

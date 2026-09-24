// An XML element the core does not know, kept as is and written back on save.
//
// KeePass and KeePassXC files may carry elements that are not in our model: newer KDBX
// versions, client-specific extensions. Without this they were dropped on the first save.
//
// Where they are kept (Step 18): the file, Meta, Root, every group and every entry own an
// `UnknownElements` store. Anything unknown found below one of them is stored there WITH THE
// PATH it stood at - `["Times"]`, `["CustomData", "Item", "<key>"]` - and the writer puts it
// back at that path. Keeping the path, instead of a field per struct, is what makes this work
// for nodes nobody listed: reading is a default ("keep"), not a list of places.
//
// Repeated children (String, Binary, Item, Icon, DeletedObject, Association) carry their key
// in the path rather than a store of their own: the UI rebuilds those structs when an entry is
// edited, and a store inside them would be dropped on the first edit.
//
// A leaf with Protected="True" holds a value encrypted with the inner stream cipher.
// The stream is shared by all protected values in document order, so such a value is
// decrypted when read (otherwise every later password decrypts to garbage) and
// encrypted again when written. `text` of such a leaf is plaintext in memory.
//
// Limitation: mixed content (text and child elements in one element) is written as the
// text followed by the children.

#[derive(Debug, Clone, Default, PartialEq)]
pub(crate) struct UnknownElement {
    pub(crate) tag: String,
    // Unescaped attribute values, in document order
    pub(crate) attrs: Vec<(String, String)>,
    // Unescaped text content
    pub(crate) text: String,
    pub(crate) children: Vec<UnknownElement>,
}

impl UnknownElement {
    pub(crate) fn new(tag: String, attrs: Vec<(String, String)>) -> Self {
        Self {
            tag,
            attrs,
            ..Default::default()
        }
    }

    // True for a leaf whose text is an inner-stream protected value
    pub(crate) fn is_protected_leaf(&self) -> bool {
        self.children.is_empty()
            && self
                .attrs
                .iter()
                .any(|(k, v)| k == "Protected" && v.eq_ignore_ascii_case("true"))
    }

    // Memory-security lock: volatile-zero all text (protected values are plaintext here)
    pub(crate) fn zeroize_text(&mut self) {
        use zeroize::Zeroize;
        self.text.zeroize();
        for child in &mut self.children {
            child.zeroize_text();
        }
    }
}

// Unknown elements of one owner (the file, Meta, Root, a group, an entry), each with the
// path where it stood, relative to that owner. An empty path means "directly in the owner".
#[derive(Debug, Clone, Default, PartialEq)]
pub(crate) struct UnknownElements {
    items: Vec<(Vec<String>, UnknownElement)>,
}

impl UnknownElements {
    pub(crate) fn push(&mut self, path: Vec<String>, element: UnknownElement) {
        self.items.push((path, element));
    }

    // Takes over elements read below `prefix` (e.g. one <String>), keeping their own
    // relative paths: ["Value"] read inside <String> of key "Title" becomes
    // ["String", "Title", "Value"]
    pub(crate) fn extend_with_prefix(&mut self, prefix: &[String], other: UnknownElements) {
        for (path, element) in other.items {
            let mut full = prefix.to_vec();
            full.extend(path);
            self.items.push((full, element));
        }
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    pub(crate) fn iter(&self) -> impl Iterator<Item = (&[String], &UnknownElement)> {
        self.items.iter().map(|(p, e)| (p.as_slice(), e))
    }

    // Memory-security lock: volatile-zero all text (protected values are plaintext here)
    pub(crate) fn zeroize_text(&mut self) {
        for (_, element) in &mut self.items {
            element.zeroize_text();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{UnknownElement, UnknownElements};

    fn leaf(attrs: &[(&str, &str)]) -> UnknownElement {
        UnknownElement::new(
            "Value".into(),
            attrs
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
        )
    }

    #[test]
    fn protected_leaf_needs_the_attribute() {
        assert!(leaf(&[("Protected", "True")]).is_protected_leaf());
        assert!(!leaf(&[("Protected", "False")]).is_protected_leaf());
        assert!(!leaf(&[]).is_protected_leaf());
    }

    // An element with children is never decrypted as a whole
    #[test]
    fn element_with_children_is_not_a_protected_leaf() {
        let mut parent = leaf(&[("Protected", "True")]);
        parent.children.push(leaf(&[]));
        assert!(!parent.is_protected_leaf());
    }

    #[test]
    fn zeroize_clears_nested_text() {
        let mut parent = leaf(&[]);
        parent.text = "a".into();
        let mut child = leaf(&[("Protected", "True")]);
        child.text = "secret".into();
        parent.children.push(child);

        parent.zeroize_text();

        assert!(parent.text.is_empty());
        assert!(parent.children[0].text.is_empty());
    }

    fn tagged(tag: &str) -> UnknownElement {
        UnknownElement::new(tag.into(), vec![])
    }

    fn path(parts: &[&str]) -> Vec<String> {
        parts.iter().map(|p| p.to_string()).collect()
    }

    #[test]
    fn elements_keep_the_path_they_were_read_at() {
        let mut store = UnknownElements::default();
        store.push(vec![], tagged("InOwner"));
        store.push(path(&["Times"]), tagged("InTimes"));

        let found: Vec<_> = store.iter().collect();
        assert_eq!(found[0].0, Vec::<String>::new().as_slice());
        assert_eq!(found[1].0, path(&["Times"]).as_slice());
        assert_eq!(found[1].1.tag, "InTimes");
    }

    // A subtree is read on its own and handed over with the key of the repeated child
    #[test]
    fn prefix_is_prepended_to_paths_of_a_subtree() {
        let mut subtree = UnknownElements::default();
        subtree.push(vec![], tagged("InString"));
        subtree.push(path(&["Value"]), tagged("InValue"));

        let mut store = UnknownElements::default();
        store.extend_with_prefix(&path(&["String", "Title"]), subtree);

        let found: Vec<_> = store.iter().collect();
        assert_eq!(found[0].0, path(&["String", "Title"]).as_slice());
        assert_eq!(found[1].0, path(&["String", "Title", "Value"]).as_slice());
    }

    #[test]
    fn zeroize_clears_text_of_stored_elements() {
        let mut element = tagged("Secret");
        element.text = "secret".into();
        let mut store = UnknownElements::default();
        store.push(vec![], element);

        store.zeroize_text();

        assert!(store.iter().next().unwrap().1.text.is_empty());
    }
}

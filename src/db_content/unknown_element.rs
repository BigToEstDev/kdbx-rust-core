// An XML element the core does not know, kept as is and written back on save.
//
// KeePass and KeePassXC files may carry elements that are not in our model: newer KDBX
// versions, client-specific extensions. Without this they were dropped on the first save.
// Kept for Meta, groups and entries (including history) - see xml_parse.rs, read_tags!.
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

#[cfg(test)]
mod tests {
    use super::UnknownElement;

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
}

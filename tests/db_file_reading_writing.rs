mod common;

use kdbx_rust_core::db_service::{self, *};
use uuid::Uuid;

// All the databases used by these tests are created on the fly under the OS temp dir
// (create_kdbx / write to a temp path), instead of reading personal .kdbx fixtures.
// See Step 7 in the docs repo plan for the background.

fn temp_path(name: &str) -> String {
    let mut p = std::env::temp_dir();
    p.push(format!("{}_{}", name, std::process::id()));
    p.to_str().unwrap().to_string()
}

// Builds a NewDatabase via serde (fields are pub(crate)) starting from Default so
// kdf/cipher_id get valid defaults, then injects the file path + password.
fn make_new_db(db_key: &str, password: &str) -> NewDatabase {
    let mut v = serde_json::to_value(NewDatabase::default()).unwrap();
    v["database_name"] = serde_json::json!("TestDb");
    v["database_file_name"] = serde_json::json!(db_key);
    v["password"] = serde_json::json!(password);
    serde_json::from_value(v).unwrap()
}

// Creates a Login entry with known field values via the public form-data round trip
// (EntryFormData's fields are private but Serialize/Deserialize, so we go through
// serde_json::Value the same way `make_new_db` does for NewDatabase). Returns the
// new entry's uuid.
fn insert_login_entry(
    db_key: &str,
    parent_group_uuid: &Uuid,
    title: &str,
    username: &str,
    password: &str,
) -> Uuid {
    let form = db_service::new_entry_form_data(Some(parent_group_uuid));

    let mut v = serde_json::to_value(&form).unwrap();
    let entry_uuid_str = v["uuid"].as_str().unwrap().to_string();

    common::form::set_field(&mut v, "Title", title);
    common::form::set_field(&mut v, "UserName", username);
    common::form::set_field(&mut v, "Password", password);

    let form: EntryFormData = serde_json::from_value(v).unwrap();
    db_service::insert_entry_from_form_data(db_key, form).unwrap();

    Uuid::parse_str(&entry_uuid_str).unwrap()
}

#[test]
fn verify_read_db_file() {
    common::init();

    let db_key = temp_path("okp_verify_read_db_file.kdbx");
    let _ = std::fs::remove_file(&db_key);
    let password = "test-pass-1234";

    let created = create_kdbx(make_new_db(&db_key, password));
    assert!(created.is_ok(), "create_kdbx failed: {:?}", created);
    let _ = db_service::close_kdbx(&db_key);

    // Read (load) the db file back from disk
    let r = load_kdbx(&db_key, Some(password), None);
    assert!(r.is_ok(), "load_kdbx failed: {:?}", r);

    let settings = db_service::get_db_settings(&db_key);
    assert!(settings.is_ok());

    let _ = db_service::close_kdbx(&db_key);
    let _ = std::fs::remove_file(&db_key);
}

#[test]
fn verify_read_write_db_file() {
    common::init();

    let db_key = temp_path("okp_verify_read_write_db_file.kdbx");
    let _ = std::fs::remove_file(&db_key);
    let password = "test-pass-1234";

    let created = create_kdbx(make_new_db(&db_key, password));
    assert!(created.is_ok(), "create_kdbx failed: {:?}", created);

    // Change something and save
    let mut settings = db_service::get_db_settings(&db_key).unwrap();
    settings.set_database_name("Changed");
    db_service::set_db_settings(&db_key, settings, None).unwrap();

    let saved = db_service::save_kdbx_with_backup(&db_key, None, true);
    assert!(saved.is_ok(), "save_kdbx_with_backup failed: {:?}", saved);

    let _ = db_service::close_kdbx(&db_key);

    // Read back and verify the change survived the round trip
    let r = load_kdbx(&db_key, Some(password), None);
    assert!(r.is_ok(), "reload after save failed: {:?}", r);

    let settings = db_service::get_db_settings(&db_key).unwrap();
    assert_eq!(settings.get_database_name(), "Changed");

    let _ = db_service::close_kdbx(&db_key);
    let _ = std::fs::remove_file(&db_key);
}

#[test]
fn verify_read_db_and_export_xml() {
    common::init();

    let db_key = temp_path("okp_verify_export_xml.kdbx");
    let _ = std::fs::remove_file(&db_key);
    let password = "test-pass-1234";

    let created = create_kdbx(make_new_db(&db_key, password));
    assert!(created.is_ok(), "create_kdbx failed: {:?}", created);

    let root_uuid = db_service::groups_summary_data(&db_key).unwrap().root_uuid;
    insert_login_entry(&db_key, &root_uuid, "Site One", "user1", "pass1");

    let xml_path = temp_path("okp_verify_export_xml_out.xml");
    let _ = std::fs::remove_file(&xml_path);

    let r = db_service::export_as_xml(&db_key, &xml_path);
    assert!(r.is_ok(), "export_as_xml failed: {:?}", r);

    let xml_content = std::fs::read_to_string(&xml_path).unwrap();
    assert!(!xml_content.is_empty());
    assert!(xml_content.contains("Site One"));

    let _ = std::fs::remove_file(&xml_path);
    let _ = db_service::close_kdbx(&db_key);
    let _ = std::fs::remove_file(&db_key);
}

#[test]
fn verify_db_merge() {
    common::init();

    let target_db_key = temp_path("okp_verify_merge_target.kdbx");
    let source_db_key = temp_path("okp_verify_merge_source.kdbx");
    let _ = std::fs::remove_file(&target_db_key);
    let _ = std::fs::remove_file(&source_db_key);
    let password = "test-pass-1234";

    let created = create_kdbx(make_new_db(&target_db_key, password));
    assert!(
        created.is_ok(),
        "create_kdbx (target) failed: {:?}",
        created
    );
    let created = create_kdbx(make_new_db(&source_db_key, password));
    assert!(
        created.is_ok(),
        "create_kdbx (source) failed: {:?}",
        created
    );

    // Add an entry only to the source db - this is what the merge should bring over
    let source_root_uuid = db_service::groups_summary_data(&source_db_key)
        .unwrap()
        .root_uuid;
    let entry_uuid = insert_login_entry(
        &source_db_key,
        &source_root_uuid,
        "Merged Site",
        "merged-user",
        "merged-pass",
    );

    let merge_result =
        db_service::merge_databases(&target_db_key, &source_db_key, Some(password), None);
    assert!(
        merge_result.is_ok(),
        "merge_databases failed: {:?}",
        merge_result
    );

    let merge_result_json = serde_json::to_value(merge_result.unwrap()).unwrap();
    assert_eq!(merge_result_json["merge_done"], serde_json::json!(true));
    assert_eq!(
        merge_result_json["added_entries"].as_array().unwrap().len(),
        1
    );

    // The merged entry must now be readable from the target db with its original uuid
    let merged_entry = db_service::get_entry_form_data_by_id(&target_db_key, &entry_uuid);
    assert!(
        merged_entry.is_ok(),
        "merged entry not found in target: {:?}",
        merged_entry
    );

    let _ = db_service::close_kdbx(&target_db_key);
    let _ = db_service::close_kdbx(&source_db_key);
    let _ = std::fs::remove_file(&target_db_key);
    let _ = std::fs::remove_file(&source_db_key);
}

#[test]
fn verify_read_save_as_db_file() {
    common::init();

    let db_key = temp_path("okp_verify_save_as.kdbx");
    let database_file_name = temp_path("okp_verify_save_as_copy.kdbx");
    let _ = std::fs::remove_file(&db_key);
    let _ = std::fs::remove_file(&database_file_name);
    let password = "test-pass-1234";

    let created = create_kdbx(make_new_db(&db_key, password));
    assert!(created.is_ok(), "create_kdbx failed: {:?}", created);

    let root_uuid = db_service::groups_summary_data(&db_key).unwrap().root_uuid;
    insert_login_entry(&db_key, &root_uuid, "Site One", "user1", "pass1");

    let wr = save_as_kdbx(&db_key, &database_file_name);
    assert!(wr.is_ok(), "save_as_kdbx failed: {:?}", wr);

    // Read back the copy and verify it opens and matches the original content
    let r = load_kdbx(&database_file_name, Some(password), None);
    assert!(r.is_ok(), "load_kdbx of the saved-as copy failed: {:?}", r);

    let settings = db_service::get_db_settings(&database_file_name).unwrap();
    assert_eq!(settings.get_database_name(), "TestDb");

    let _ = db_service::close_kdbx(&db_key);
    let _ = db_service::close_kdbx(&database_file_name);
    let _ = std::fs::remove_file(&db_key);
    let _ = std::fs::remove_file(&database_file_name);
}

#[test]
fn verify_entry_1() {
    common::init();

    let db_key = temp_path("okp_verify_entry_1.kdbx");
    let _ = std::fs::remove_file(&db_key);
    let password = "test-pass-1234";

    let created = create_kdbx(make_new_db(&db_key, password));
    assert!(created.is_ok(), "create_kdbx failed: {:?}", created);

    let root_uuid = db_service::groups_summary_data(&db_key).unwrap().root_uuid;
    let entry_uuid = insert_login_entry(&db_key, &root_uuid, "My Test Entry", "testuser", "s3cret");

    let entry_form = get_entry_form_data_by_id(&db_key, &entry_uuid);
    assert!(
        entry_form.is_ok(),
        "get_entry_form_data_by_id failed: {:?}",
        entry_form
    );

    let v = serde_json::to_value(entry_form.unwrap()).unwrap();
    assert_eq!(common::form::field(&v, "Title"), Some("My Test Entry"));
    assert_eq!(common::form::field(&v, "UserName"), Some("testuser"));
    assert_eq!(common::form::field(&v, "Password"), Some("s3cret"));

    let _ = db_service::close_kdbx(&db_key);
    let _ = std::fs::remove_file(&db_key);
}

// Field names in any script survive saving and reopening, protected ones too (the inner stream walks
// them in order). Keys are compared exactly: names in another case are two fields - folding case is the
// app's rule for the names it writes, not the core's
#[test]
fn field_names_in_any_script_survive_the_file() {
    common::init();

    let db_key = temp_path("okp_field_names_scripts.kdbx");
    let _ = std::fs::remove_file(&db_key);
    let password = "test-pass-1234";
    create_kdbx(make_new_db(&db_key, password)).unwrap();

    let root = db_service::groups_summary_data(&db_key).unwrap().root_uuid;
    let entry_uuid = insert_login_entry(&db_key, &root, "Scripts", "user", "pw");

    let fields = [
        ("Пароль банка", "секрет 1", false),
        ("كلمة السر", "سر ٢", true),
        ("密码", "秘密 3", true),
        ("ПИН", "1111", false),
        ("пин", "2222", false),
    ];
    let form = get_entry_form_data_by_id(&db_key, &entry_uuid).unwrap();
    let mut v = serde_json::to_value(&form).unwrap();
    for (key, value, protected) in fields {
        common::form::set_field(&mut v, key, value);
        if protected {
            common::form::protect(&mut v, key);
        }
    }
    update_entry_from_form_data(&db_key, serde_json::from_value(v).unwrap()).unwrap();

    db_service::save_kdbx_with_backup(&db_key, None, true).unwrap();
    let _ = db_service::close_kdbx(&db_key);
    load_kdbx(&db_key, Some(password), None).unwrap();

    let v = serde_json::to_value(get_entry_form_data_by_id(&db_key, &entry_uuid).unwrap()).unwrap();
    let read: Vec<(String, String, bool)> = v["fields"]
        .as_array()
        .unwrap()
        .iter()
        .skip(5)
        .map(|f| {
            (
                f["key"].as_str().unwrap().to_string(),
                f["value"].as_str().unwrap().to_string(),
                f["protected"].as_bool().unwrap(),
            )
        })
        .collect();
    let expected: Vec<(String, String, bool)> = fields
        .iter()
        .map(|(k, v, p)| (k.to_string(), v.to_string(), *p))
        .collect();
    assert_eq!(read, expected);

    let _ = db_service::close_kdbx(&db_key);
    let _ = std::fs::remove_file(&db_key);
}

// The fields keep the order of the form through saving and reopening (Step 43: the core keeps the
// fields of an entry in the order of the file; Step 45: the order is the app's - any order it sends)
#[test]
fn fields_keep_the_order_of_the_form_through_the_file() {
    common::init();

    let db_key = temp_path("okp_fields_order.kdbx");
    let _ = std::fs::remove_file(&db_key);
    let password = "test-pass-1234";
    create_kdbx(make_new_db(&db_key, password)).unwrap();

    let root = db_service::groups_summary_data(&db_key).unwrap().root_uuid;
    let entry_uuid = insert_login_entry(&db_key, &root, "Ordered", "user", "pw");

    let form = get_entry_form_data_by_id(&db_key, &entry_uuid).unwrap();
    let mut v = serde_json::to_value(&form).unwrap();
    for key in ["Zeta", "Alpha", "Mid"] {
        common::form::set_field(&mut v, key, &format!("{} value", key));
    }
    v["fields"].as_array_mut().unwrap().reverse();
    update_entry_from_form_data(&db_key, serde_json::from_value(v).unwrap()).unwrap();

    db_service::save_kdbx_with_backup(&db_key, None, true).unwrap();
    let _ = db_service::close_kdbx(&db_key);
    load_kdbx(&db_key, Some(password), None).unwrap();

    let v = serde_json::to_value(get_entry_form_data_by_id(&db_key, &entry_uuid).unwrap()).unwrap();
    assert_eq!(
        common::form::keys(&v),
        vec!["Mid", "Alpha", "Zeta", "Notes", "URL", "Password", "UserName", "Title"]
    );

    let _ = db_service::close_kdbx(&db_key);
    let _ = std::fs::remove_file(&db_key);
}

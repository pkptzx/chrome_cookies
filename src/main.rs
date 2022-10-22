use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use tabled::{Tabled, Table};
use std::collections::HashMap;
use windows::Win32::Security::Cryptography::CRYPTOAPI_BLOB;
fn main() {
    //开发时cargo运行:
    //cargo run pwd
    //cargo run .bilibili.com
    let args: Vec<_> = std::env::args().collect();
    if args.len() < 2 {
        //编译后在target中运行chrome_cookies
        println!("Usage: chrome_cookies [pwd] <host_url>");
        println!("获取cookies示例: chrome_cookies .bilibili.com");
        println!("获取Chrome密码示例: chrome_cookies pwd");
        std::process::exit(1);
    }
    let host_url = &args[1];
    if host_url =="pwd" {
        let login_data = get_raw_pwd();
        println!("{}",Table::new(login_data).to_string());
        return;
    }
    let key = get_key();
    let mut result = HashMap::new();
    let data = get_raw_cookies(host_url);
    for (name, encrypted_value) in data.iter() {
        result.insert(name, decrypt_string(&key, encrypted_value));
    }
    let json_result = serde_json::json!(result);
    println!("{json_result}");
}

fn get_key() -> Vec<u8> {
    let app_data_path = std::env::var("LOCALAPPDATA").unwrap();
    let local_statue_path = format!(r"{app_data_path}\Google\Chrome\User Data\Local State");

    let f = std::fs::File::open(local_statue_path).unwrap();
    let json: serde_json::Value = serde_json::from_reader(f).unwrap();
    let encrypted_key = json
        .get("os_crypt")
        .unwrap()
        .get("encrypted_key")
        .unwrap()
        .as_str()
        .unwrap();
    let encrypted_key_bytes = base64::decode(encrypted_key).unwrap();
    let encrypted_key_bytes = &encrypted_key_bytes[5..];

    let decode_key = crypt_unprotect_data(encrypted_key_bytes);
    decode_key.to_vec()
}

fn get_raw_cookies(host_url: &str) -> HashMap<String, Vec<u8>> {
    let app_data_path = std::env::var("LOCALAPPDATA").unwrap();
    let cookies_db_path =
        format!(r"{app_data_path}\Google\Chrome\User Data\Default\Network\Cookies");
    let conn = rusqlite::Connection::open(cookies_db_path).unwrap();
    let mut stmt = conn
        .prepare("select name,encrypted_value from cookies where host_key=?")
        .unwrap();
    let mut rows = stmt.query(rusqlite::params![host_url]).unwrap();
    let mut data: HashMap<String, Vec<u8>> = HashMap::new();

    while let Some(row) = rows.next().unwrap() {
        let encrypted_value_ref = row.get_ref_unwrap(1);
        let encrypted_value = encrypted_value_ref.as_bytes().unwrap();
        data.insert(row.get(0).unwrap(), encrypted_value.to_vec());
    }
    data
}

#[derive(Debug,Tabled)]
struct Login {
    origin_url: String,
    username_value: String,
    password_value: String,
}

fn get_raw_pwd() -> Vec<Login> {
    let app_data_path = std::env::var("LOCALAPPDATA").unwrap();
    let logindata_db_path = format!(r"{app_data_path}\Google\Chrome\User Data\Default\Login Data");

    std::fs::copy(logindata_db_path, "Login Data").unwrap();

    let conn = rusqlite::Connection::open("Login Data").unwrap();
    let mut stmt = conn.prepare("select origin_url,username_value,password_value from logins where blacklisted_by_user=0").unwrap();
    let key = get_key();
    let mut data:Vec<Login> = Vec::new();
    let mut rows = stmt.query([]).unwrap();
    while let Some(row) =  rows.next().unwrap() {
        let origin_url:String = row.get(0).unwrap();
        let username_value:String = row.get(1).unwrap();
        let password_value_ref = row.get_ref_unwrap(2);
        let password_value = password_value_ref.as_bytes().unwrap();
        let header = &password_value[0..3];
        let mut _pwd_plain = String::new();
        if header == b"v10" || header == b"v11" {
            _pwd_plain = decrypt_string(&key, password_value);
        }else{
            let decode = crypt_unprotect_data(password_value);
            _pwd_plain = String::from_utf8(decode.to_vec()).unwrap();
        }
        let login_info = Login{
            origin_url,username_value,password_value:_pwd_plain
        };
        data.push(login_info);
    }
    data

}

fn decrypt_string(key: &[u8], data: &[u8]) -> String {
    let iv = &data[3..15];
    let cipherbytes = &data[15..];

    let cipher = Aes256Gcm::new_from_slice(key).unwrap();
    let nonce = Nonce::from_slice(iv);
    let plaintext = cipher.decrypt(nonce, cipherbytes).unwrap();
    String::from_utf8(plaintext).unwrap()
}
fn crypt_unprotect_data(data: &[u8]) -> &[u8] {
    let mut out = CRYPTOAPI_BLOB::default();
    let mut data_vec = data.to_vec();
    let _rst = unsafe {
        let size = u32::try_from(data_vec.len()).unwrap();
        let p_data_in = CRYPTOAPI_BLOB {
            cbData: size,
            pbData: data_vec.as_mut_ptr(),
        };
        windows::Win32::Security::Cryptography::CryptUnprotectData(
            &p_data_in,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            0,
            &mut out,
        )
    };

    let decode_key = unsafe {
        let output = core::slice::from_raw_parts(out.pbData, out.cbData as _);
        windows::Win32::System::Memory::LocalFree(out.pbData as _);
        output
    };
    decode_key
}

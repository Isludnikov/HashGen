extern crate native_windows_gui as nwg;
use main_library::{
    ARGON2_M_MAX, ARGON2_M_MIN, ARGON2_P_MAX, ARGON2_P_MIN, ARGON2_T_MAX, ARGON2_T_MIN,
    KEY_LEN_MAX, KEY_LEN_MIN, form_log_string,
};
use std::{ffi::c_void, thread, time};

type Hwnd = *mut c_void;

#[link(name = "user32")]
unsafe extern "system" {
    fn GetWindow(hWnd: Hwnd, uCmd: u32) -> Hwnd;
    fn SendMessageW(hWnd: Hwnd, Msg: u32, wParam: usize, lParam: isize) -> isize;
}

const GW_CHILD: u32 = 5;
const EM_SETREADONLY: u32 = 0x00CF;

pub fn make_number_select_readonly(input: &nwg::NumberSelect) {
    unsafe {
        if let Some(frame) = input.handle.hwnd() {
            let edit = GetWindow(frame as Hwnd, GW_CHILD);
            if !edit.is_null() {
                SendMessageW(edit, EM_SETREADONLY, 1, 0);
            }
        }
    }
}

const VERSION: &str = env!("CARGO_PKG_VERSION");

pub fn exit(status: &nwg::StatusBar) {
    status.set_text(0, &form_log_string("Γεια σας!"));
    thread::sleep(time::Duration::from_millis(250));
    nwg::stop_thread_dispatch();
}

pub fn build_window(window: &mut nwg::Window) {
    nwg::Window::builder()
        .size((950, 550))
        .flags(nwg::WindowFlags::WINDOW | nwg::WindowFlags::VISIBLE)
        .ex_flags(0x00000200)
        .center(true)
        .maximized(false)
        .title(format!("Password hasher / random keys generator GUI v {}", VERSION).as_str())
        .build(window)
        .unwrap();
}

pub fn build_controls(
    window: &nwg::Window,
    password_description: &mut nwg::Label,
    password_edit: &mut nwg::TextInput,
    len_description: &mut nwg::Label,
    len_input: &mut nwg::NumberSelect,
    argon2id_hash_button: &mut nwg::Button,
    argon2i_hash_button: &mut nwg::Button,
    argon2_m_description: &mut nwg::Label,
    argon2_m_input: &mut nwg::NumberSelect,
    argon2_t_description: &mut nwg::Label,
    argon2_t_input: &mut nwg::NumberSelect,
    argon2_p_description: &mut nwg::Label,
    argon2_p_input: &mut nwg::NumberSelect,
    random_keys_button: &mut nwg::Button,
    result_description: &mut nwg::Label,
    output_list: &mut nwg::ListBox<String>,
    status: &mut nwg::StatusBar,
) {
    nwg::Label::builder()
        .parent(window)
        .text("Password:")
        .build(password_description)
        .unwrap();
    nwg::TextInput::builder()
        .placeholder_text(Some("Enter password to hash"))
        .focus(true)
        .parent(window)
        .build(password_edit)
        .unwrap();
    nwg::Label::builder()
        .parent(window)
        .text("Key length:")
        .build(len_description)
        .unwrap();
    nwg::NumberSelect::builder()
        .parent(window)
        .decimals(0)
        .min_int(KEY_LEN_MIN.into())
        .max_int(KEY_LEN_MAX.into())
        .step_int(8)
        .value_int(32)
        .size((180, 32))
        .build(len_input)
        .unwrap();
    nwg::Button::builder()
        .text("Get Argon2id hash")
        .parent(window)
        .build(argon2id_hash_button)
        .unwrap();
    nwg::Button::builder()
        .text("Get Argon2i hash")
        .parent(window)
        .build(argon2i_hash_button)
        .unwrap();
    nwg::Label::builder()
        .parent(window)
        .text("m (KiB):")
        .build(argon2_m_description)
        .unwrap();
    nwg::NumberSelect::builder()
        .parent(window)
        .decimals(0)
        .min_int(ARGON2_M_MIN.into())
        .max_int(ARGON2_M_MAX.into())
        .step_int(8192)
        .value_int(131072)
        .build(argon2_m_input)
        .unwrap();
    nwg::Label::builder()
        .parent(window)
        .text("t:")
        .build(argon2_t_description)
        .unwrap();
    nwg::NumberSelect::builder()
        .parent(window)
        .decimals(0)
        .min_int(ARGON2_T_MIN.into())
        .max_int(ARGON2_T_MAX.into())
        .step_int(1)
        .value_int(3)
        .build(argon2_t_input)
        .unwrap();
    nwg::Label::builder()
        .parent(window)
        .text("p:")
        .build(argon2_p_description)
        .unwrap();
    nwg::NumberSelect::builder()
        .parent(window)
        .decimals(0)
        .min_int(ARGON2_P_MIN.into())
        .max_int(ARGON2_P_MAX.into())
        .step_int(1)
        .value_int(4)
        .build(argon2_p_input)
        .unwrap();
    nwg::Button::builder()
        .text("Generate random keys")
        .parent(window)
        .build(random_keys_button)
        .unwrap();
    nwg::Label::builder()
        .text("Results:")
        .parent(window)
        .build(result_description)
        .unwrap();
    nwg::ListBox::builder()
        .parent(window)
        .build(output_list)
        .unwrap();
    nwg::StatusBar::builder()
        .parent(window)
        .text(&form_log_string(&format!("ver. {VERSION}")))
        .build(status)
        .unwrap();
}

pub fn setup_layout(
    window: &nwg::Window,
    layout: &nwg::GridLayout,
    password_description: &nwg::Label,
    password_edit: &nwg::TextInput,
    len_description: &nwg::Label,
    len_input: &nwg::NumberSelect,
    argon2id_hash_button: &nwg::Button,
    argon2i_hash_button: &nwg::Button,
    argon2_m_description: &nwg::Label,
    argon2_m_input: &nwg::NumberSelect,
    argon2_t_description: &nwg::Label,
    argon2_t_input: &nwg::NumberSelect,
    argon2_p_description: &nwg::Label,
    argon2_p_input: &nwg::NumberSelect,
    random_keys_button: &nwg::Button,
    result_description: &nwg::Label,
    output_list: &nwg::ListBox<String>,
    status: &nwg::StatusBar,
) {
    nwg::GridLayout::builder()
        .parent(window)
        .spacing(1)
        .child(0, 0, password_description)
        .child_item(nwg::GridLayoutItem::new(password_edit, 1, 0, 8, 1))
        .child_item(nwg::GridLayoutItem::new(argon2id_hash_button, 0, 1, 5, 1))
        .child_item(nwg::GridLayoutItem::new(argon2i_hash_button, 5, 1, 4, 1))
        .child(0, 2, argon2_m_description)
        .child_item(nwg::GridLayoutItem::new(argon2_m_input, 1, 2, 2, 1))
        .child(3, 2, argon2_t_description)
        .child(4, 2, argon2_t_input)
        .child(5, 2, argon2_p_description)
        .child(6, 2, argon2_p_input)
        .child(0, 3, len_description)
        .child_item(nwg::GridLayoutItem::new(len_input, 1, 3, 2, 1))
        .child_item(nwg::GridLayoutItem::new(random_keys_button, 3, 3, 6, 1))
        .child(0, 4, result_description)
        .child_item(nwg::GridLayoutItem::new(output_list, 0, 5, 9, 10))
        .child_item(nwg::GridLayoutItem::new(status, 0, 15, 9, 1))
        .build(layout)
        .unwrap();
}

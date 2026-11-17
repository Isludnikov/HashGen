#![windows_subsystem = "windows"]

mod ui;

extern crate native_windows_gui as nwg;
use clipboard_win::{formats, set_clipboard};
use main_library::{
    ARGON2_M_MAX, ARGON2_M_MIN, ARGON2_P_MAX, ARGON2_P_MIN, ARGON2_T_MAX, ARGON2_T_MIN,
    Argon2Variant, KEY_LEN_MAX, KEY_LEN_MIN, form_log_string, hash_gen, parse_bounded, spawn_hash,
};
use std::{cell::RefCell, rc::Rc, thread::JoinHandle};

type HashJob = JoinHandle<Result<String, String>>;

const KEY_BATCH_COUNT: usize = 16;

fn read_param(input: &nwg::NumberSelect, min: u32, max: u32) -> Result<u32, String> {
    parse_bounded(&input.data().formatted_value(), min, max)
}

fn read_argon2_params(
    m: &nwg::NumberSelect,
    t: &nwg::NumberSelect,
    p: &nwg::NumberSelect,
) -> Result<(u32, u32, u32), String> {
    Ok((
        read_param(m, ARGON2_M_MIN, ARGON2_M_MAX).map_err(|e| format!("m: {e}"))?,
        read_param(t, ARGON2_T_MIN, ARGON2_T_MAX).map_err(|e| format!("t: {e}"))?,
        read_param(p, ARGON2_P_MIN, ARGON2_P_MAX).map_err(|e| format!("p: {e}"))?,
    ))
}

fn main() {
    nwg::init().expect("Failed to init Native Windows GUI");
    nwg::Font::set_global_family("Segoe UI").expect("Failed to set default font");

    let mut window = Default::default();
    let mut password_edit = Default::default();
    let mut argon2id_hash_button = Default::default();
    let mut argon2i_hash_button = Default::default();
    let mut argon2_m_description = Default::default();
    let mut argon2_m_input: nwg::NumberSelect = Default::default();
    let mut argon2_t_description = Default::default();
    let mut argon2_t_input: nwg::NumberSelect = Default::default();
    let mut argon2_p_description = Default::default();
    let mut argon2_p_input: nwg::NumberSelect = Default::default();
    let mut random_keys_button = Default::default();
    let mut len_input = Default::default();
    let layout = Default::default();
    let mut output_list: nwg::ListBox<String> = Default::default();
    let mut status = Default::default();
    let mut password_description = Default::default();
    let mut len_description = Default::default();
    let mut result_description = Default::default();

    ui::build_window(&mut window);
    ui::build_controls(
        &window,
        &mut password_description,
        &mut password_edit,
        &mut len_description,
        &mut len_input,
        &mut argon2id_hash_button,
        &mut argon2i_hash_button,
        &mut argon2_m_description,
        &mut argon2_m_input,
        &mut argon2_t_description,
        &mut argon2_t_input,
        &mut argon2_p_description,
        &mut argon2_p_input,
        &mut random_keys_button,
        &mut result_description,
        &mut output_list,
        &mut status,
    );
    // NumberSelect only tracks values changed via its +/- buttons; text typed into
    // the edit box is silently ignored. Make every box read-only so the displayed
    // value always matches the value actually used.
    for input in [
        &argon2_m_input,
        &argon2_t_input,
        &argon2_p_input,
        &len_input,
    ] {
        ui::make_number_select_readonly(input);
    }
    ui::setup_layout(
        &window,
        &layout,
        &password_description,
        &password_edit,
        &len_description,
        &len_input,
        &argon2id_hash_button,
        &argon2i_hash_button,
        &argon2_m_description,
        &argon2_m_input,
        &argon2_t_description,
        &argon2_t_input,
        &argon2_p_description,
        &argon2_p_input,
        &random_keys_button,
        &result_description,
        &output_list,
        &status,
    );

    let mut hash_notice = nwg::Notice::default();
    nwg::Notice::builder()
        .parent(&window)
        .build(&mut hash_notice)
        .expect("Failed to create notice");
    let hash_job: RefCell<Option<(Argon2Variant, HashJob)>> = RefCell::new(None);

    let window = Rc::new(window);
    let events_window = window.clone();
    let handler = nwg::full_bind_event_handler(&window.handle, move |evt, _evt_data, handle| {
        use nwg::Event as E;

        // Lock the inputs that affect the running hash so the user can't start a
        // second job or change parameters mid-computation.
        let set_hash_controls_enabled = |enabled: bool| {
            argon2id_hash_button.set_enabled(enabled);
            argon2i_hash_button.set_enabled(enabled);
            password_edit.set_enabled(enabled);
            argon2_m_input.set_enabled(enabled);
            argon2_t_input.set_enabled(enabled);
            argon2_p_input.set_enabled(enabled);
        };

        match evt {
            E::OnWindowClose => {
                if handle == *events_window {
                    ui::exit(&status);
                }
            }
            E::OnButtonClick => {
                if handle == argon2id_hash_button || handle == argon2i_hash_button {
                    if hash_job.borrow().is_some() {
                        return; // a hash is already being computed
                    }
                    let variant = if handle == argon2id_hash_button {
                        Argon2Variant::Id
                    } else {
                        Argon2Variant::I
                    };
                    let (m, t, p) =
                        match read_argon2_params(&argon2_m_input, &argon2_t_input, &argon2_p_input)
                        {
                            Ok(params) => params,
                            Err(e) => {
                                status.set_text(0, &form_log_string(&e));
                                return;
                            }
                        };
                    let sender = hash_notice.sender();
                    match spawn_hash(variant, password_edit.text(), m, t, p, move || {
                        sender.notice()
                    }) {
                        Ok(job) => {
                            *hash_job.borrow_mut() = Some((variant, job));
                            set_hash_controls_enabled(false);
                            status.set_text(
                                0,
                                &form_log_string(&format!("Computing {} hash…", variant.name())),
                            );
                        }
                        Err(e) => status
                            .set_text(0, &form_log_string(&format!("Failed to start worker: {e}"))),
                    }
                } else if handle == random_keys_button {
                    match read_param(&len_input, KEY_LEN_MIN, KEY_LEN_MAX) {
                        Ok(len) => {
                            output_list.clear();
                            for _ in 0..KEY_BATCH_COUNT {
                                output_list.insert(output_list.len(), hash_gen(len as usize));
                            }
                            status.set_text(0, &form_log_string("Keys generated"));
                        }
                        Err(e) => status.set_text(0, &form_log_string(&e)),
                    }
                }
            }
            E::OnNotice => {
                if handle == hash_notice
                    && let Some((variant, job)) = hash_job.borrow_mut().take()
                {
                    let result = job
                        .join()
                        .unwrap_or_else(|_| Err("Worker thread panicked".into()));
                    match result {
                        Ok(hash) => {
                            output_list.clear();
                            output_list.insert(0, hash);
                            status.set_text(
                                0,
                                &form_log_string(&format!("{} hash generated", variant.name())),
                            );
                        }
                        Err(e) => status.set_text(0, &form_log_string(&e)),
                    }
                    set_hash_controls_enabled(true);
                }
            }
            E::OnListBoxSelect => {
                if handle == output_list
                    && let Some(s) = output_list.selection_string()
                {
                    let msg = match set_clipboard(formats::Unicode, s) {
                        Ok(()) => "Copied to clipboard".to_string(),
                        Err(e) => format!("Clipboard error: {e}"),
                    };
                    status.set_text(0, &form_log_string(&msg));
                }
            }
            E::OnKeyEsc => {
                ui::exit(&status);
            }
            _ => {}
        }
    });

    nwg::dispatch_thread_events();
    nwg::unbind_event_handler(&handler);
}

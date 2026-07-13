mod commands;

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .manage(commands::ScannerState::default())
        .invoke_handler(tauri::generate_handler![
            commands::list_scan_targets,
            commands::start_scan,
            commands::cancel_scan,
            commands::get_scan_summary,
            commands::query_items,
            commands::get_item_details,
            commands::get_storage_aggregate,
            commands::get_treemap_slice,
            commands::build_cleanup_plan,
            commands::edit_cleanup_plan,
            commands::set_path_protection,
            commands::dismiss_suggestion,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}

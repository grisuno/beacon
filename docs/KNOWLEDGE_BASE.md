# Polyglot Codebase Knowledge Graph

> Generated offline by **readmenator**. Supports C, C++, Python, Go, Rust, JS/TS, Java, C#, Shell, PHP, Dart, GDScript, Nim, ASM.
> No LLMs. No tokens. Pure static analysis.

**Total Files Parsed:** 46 | **Total Symbols Extracted:** 514 | **Total Imports:** 107

## Structural Knowledge Map
```mermaid
graph TD
    classDef mod fill:#1e1e1e,stroke:#ff6666,stroke-width:2px,color:#fff;
    classDef cls fill:#2d2d2d,stroke:#4ec9b0,stroke-width:2px,color:#fff;
    classDef fn fill:#333,stroke:#dcdcaa,stroke-width:1px,color:#dcdcaa;
    classDef ext fill:#111,stroke:#666,stroke-dasharray: 5 5,color:#aaa;
    beacon_c["beacon.c (c)"]
    class beacon_c mod;
    beacon_c__PROCESS_BASIC_INFORMATION["_PROCESS_BASIC_INFORMATION"]
    class beacon_c__PROCESS_BASIC_INFORMATION cls;
    beacon_c --> beacon_c__PROCESS_BASIC_INFORMATION
    beacon_c__UNICODE_STRING["_UNICODE_STRING"]
    class beacon_c__UNICODE_STRING cls;
    beacon_c --> beacon_c__UNICODE_STRING
    beacon_c__LDR_DATA_TABLE_ENTRY["_LDR_DATA_TABLE_ENTRY"]
    class beacon_c__LDR_DATA_TABLE_ENTRY cls;
    beacon_c --> beacon_c__LDR_DATA_TABLE_ENTRY
    beacon_c__PEB_LDR_DATA["_PEB_LDR_DATA"]
    class beacon_c__PEB_LDR_DATA cls;
    beacon_c --> beacon_c__PEB_LDR_DATA
    beacon_c__PEB["_PEB"]
    class beacon_c__PEB cls;
    beacon_c --> beacon_c__PEB
    cJSON_c["cJSON.c (c)"]
    class cJSON_c mod;
    cJSON_c_internal_hooks["internal_hooks"]
    class cJSON_c_internal_hooks cls;
    cJSON_c --> cJSON_c_internal_hooks
    cJSON_c_CJSON_PUBLIC["CJSON_PUBLIC"]
    class cJSON_c_CJSON_PUBLIC fn;
    cJSON_c --> cJSON_c_CJSON_PUBLIC
    cJSON_c_CJSON_PUBLIC["CJSON_PUBLIC"]
    class cJSON_c_CJSON_PUBLIC fn;
    cJSON_c --> cJSON_c_CJSON_PUBLIC
    cJSON_c_CJSON_PUBLIC["CJSON_PUBLIC"]
    class cJSON_c_CJSON_PUBLIC fn;
    cJSON_c --> cJSON_c_CJSON_PUBLIC
    cJSON_c_CJSON_PUBLIC["CJSON_PUBLIC"]
    class cJSON_c_CJSON_PUBLIC fn;
    cJSON_c --> cJSON_c_CJSON_PUBLIC
    COFFLoader3_c["COFFLoader3.c (c)"]
    class COFFLoader3_c mod;
    COFFLoader3_c_djb2_hash["djb2_hash"]
    class COFFLoader3_c_djb2_hash fn;
    COFFLoader3_c --> COFFLoader3_c_djb2_hash
    COFFLoader3_c_create_trampoline["create_trampoline"]
    class COFFLoader3_c_create_trampoline fn;
    COFFLoader3_c --> COFFLoader3_c_create_trampoline
    COFFLoader3_c_handle_relocation["handle_relocation"]
    class COFFLoader3_c_handle_relocation fn;
    COFFLoader3_c --> COFFLoader3_c_handle_relocation
    COFFLoader3_c_get_symbol_name["get_symbol_name"]
    class COFFLoader3_c_get_symbol_name fn;
    COFFLoader3_c --> COFFLoader3_c_get_symbol_name
    COFFLoader3_c___attribute__["__attribute__"]
    class COFFLoader3_c___attribute__ fn;
    COFFLoader3_c --> COFFLoader3_c___attribute__
    bof_test_tel_py["tel.py (py)"]
    class bof_test_tel_py mod;
    bof_test_tel_py_get_machine_id["get_machine_id"]
    class bof_test_tel_py_get_machine_id fn;
    bof_test_tel_py --> bof_test_tel_py_get_machine_id
    bof_test_tel_py_get_version["get_version"]
    class bof_test_tel_py_get_version fn;
    bof_test_tel_py --> bof_test_tel_py_get_version
    bof_test_tel_py_to_numbers["to_numbers"]
    class bof_test_tel_py_to_numbers fn;
    bof_test_tel_py --> bof_test_tel_py_to_numbers
    bof_test_tel_py_to_hex["to_hex"]
    class bof_test_tel_py_to_hex fn;
    bof_test_tel_py --> bof_test_tel_py_to_hex
    bof_test_tel_py_decrypt_cookie["decrypt_cookie"]
    class bof_test_tel_py_decrypt_cookie fn;
    bof_test_tel_py --> bof_test_tel_py_decrypt_cookie
    generate_hashs_py["generate_hashs.py (py)"]
    class generate_hashs_py mod;
    generate_hashs_py_djb2["djb2"]
    class generate_hashs_py_djb2 fn;
    generate_hashs_py --> generate_hashs_py_djb2
    generate_hashs_py_generate_coff_loader["generate_coff_loader"]
    class generate_hashs_py_generate_coff_loader fn;
    generate_hashs_py --> generate_hashs_py_generate_coff_loader
    generate_hashs_py_generate_bof_test["generate_bof_test"]
    class generate_hashs_py_generate_bof_test fn;
    generate_hashs_py --> generate_hashs_py_generate_bof_test
    generate_hashs_py_main["main"]
    class generate_hashs_py_main fn;
    generate_hashs_py --> generate_hashs_py_main
    bof_test_disablelog_c["disablelog.c (c)"]
    class bof_test_disablelog_c mod;
    bof_test_disablelog_c_my_wcscmp["my_wcscmp"]
    class bof_test_disablelog_c_my_wcscmp fn;
    bof_test_disablelog_c --> bof_test_disablelog_c_my_wcscmp
    bof_test_disablelog_c_go["go"]
    class bof_test_disablelog_c_go fn;
    bof_test_disablelog_c --> bof_test_disablelog_c_go
    bof_test_disablelog_c_WIN32_LEAN_AND_MEAN["WIN32_LEAN_AND_MEAN"]
    class bof_test_disablelog_c_WIN32_LEAN_AND_MEAN fn;
    bof_test_disablelog_c --> bof_test_disablelog_c_WIN32_LEAN_AND_MEAN
    bof_test_disablelog_c_NT_SUCCESS["NT_SUCCESS"]
    class bof_test_disablelog_c_NT_SUCCESS fn;
    bof_test_disablelog_c --> bof_test_disablelog_c_NT_SUCCESS
    bof_test_vncrelay_c["vncrelay.c (c)"]
    class bof_test_vncrelay_c mod;
    bof_test_vncrelay_c_my_FD_ISSET["my_FD_ISSET"]
    class bof_test_vncrelay_c_my_FD_ISSET fn;
    bof_test_vncrelay_c --> bof_test_vncrelay_c_my_FD_ISSET
    bof_test_vncrelay_c_relay_traffic["relay_traffic"]
    class bof_test_vncrelay_c_relay_traffic fn;
    bof_test_vncrelay_c --> bof_test_vncrelay_c_relay_traffic
    bof_test_vncrelay_c_go["go"]
    class bof_test_vncrelay_c_go fn;
    bof_test_vncrelay_c --> bof_test_vncrelay_c_go
    bof_test_scan_shellcode_c["scan_shellcode.c (c)"]
    class bof_test_scan_shellcode_c mod;
    bof_test_scan_shellcode_c_go["go"]
    class bof_test_scan_shellcode_c_go fn;
    bof_test_scan_shellcode_c --> bof_test_scan_shellcode_c_go
    bof_test_scan_shellcode_c_WIN32_LEAN_AND_MEAN["WIN32_LEAN_AND_MEAN"]
    class bof_test_scan_shellcode_c_WIN32_LEAN_AND_MEAN fn;
    bof_test_scan_shellcode_c --> bof_test_scan_shellcode_c_WIN32_LEAN_AND_MEAN
    aes_c["aes.c (c)"]
    class aes_c mod;
    aes_c_getSBoxValue["getSBoxValue"]
    class aes_c_getSBoxValue fn;
    aes_c --> aes_c_getSBoxValue
    aes_c_getSBoxInvert["getSBoxInvert"]
    class aes_c_getSBoxInvert fn;
    aes_c --> aes_c_getSBoxInvert
    aes_c_Td0["Td0"]
    class aes_c_Td0 fn;
    aes_c --> aes_c_Td0
    aes_c_Td1["Td1"]
    class aes_c_Td1 fn;
    aes_c --> aes_c_Td1
    aes_c_Td2["Td2"]
    class aes_c_Td2 fn;
    aes_c --> aes_c_Td2
    bof_test_upload_c["upload.c (c)"]
    class bof_test_upload_c mod;
    bof_test_upload_c_my_strlen["my_strlen"]
    class bof_test_upload_c_my_strlen fn;
    bof_test_upload_c --> bof_test_upload_c_my_strlen
    bof_test_upload_c_my_memcpy["my_memcpy"]
    class bof_test_upload_c_my_memcpy fn;
    bof_test_upload_c --> bof_test_upload_c_my_memcpy
    bof_test_upload_c_my_memset["my_memset"]
    class bof_test_upload_c_my_memset fn;
    bof_test_upload_c --> bof_test_upload_c_my_memset
    bof_test_upload_c_my_contains_dotdot["my_contains_dotdot"]
    class bof_test_upload_c_my_contains_dotdot fn;
    bof_test_upload_c --> bof_test_upload_c_my_contains_dotdot
    bof_test_upload_c_my_strchr["my_strchr"]
    class bof_test_upload_c_my_strchr fn;
    bof_test_upload_c --> bof_test_upload_c_my_strchr
    bof_test_sock5_c["sock5.c (c)"]
    class bof_test_sock5_c mod;
    bof_test_sock5_c_WSAData["WSAData"]
    class bof_test_sock5_c_WSAData cls;
    bof_test_sock5_c --> bof_test_sock5_c_WSAData
    bof_test_sock5_c_fd_set["fd_set"]
    class bof_test_sock5_c_fd_set cls;
    bof_test_sock5_c --> bof_test_sock5_c_fd_set
    bof_test_sock5_c_timeval["timeval"]
    class bof_test_sock5_c_timeval cls;
    bof_test_sock5_c --> bof_test_sock5_c_timeval
    bof_test_sock5_c_in_addr["in_addr"]
    class bof_test_sock5_c_in_addr cls;
    bof_test_sock5_c --> bof_test_sock5_c_in_addr
    bof_test_sock5_c_sockaddr_in["sockaddr_in"]
    class bof_test_sock5_c_sockaddr_in cls;
    bof_test_sock5_c --> bof_test_sock5_c_sockaddr_in
    aes_h["aes.h (h)"]
    class aes_h mod;
    aes_h_AES_ctx["AES_ctx"]
    class aes_h_AES_ctx cls;
    aes_h --> aes_h_AES_ctx
    aes_h__AES_H_["_AES_H_"]
    class aes_h__AES_H_ fn;
    aes_h --> aes_h__AES_H_
    aes_h_CBC["CBC"]
    class aes_h_CBC fn;
    aes_h --> aes_h_CBC
    aes_h_ECB["ECB"]
    class aes_h_ECB fn;
    aes_h --> aes_h_ECB
    aes_h_CTR["CTR"]
    class aes_h_CTR fn;
    aes_h --> aes_h_CTR
    bof_test_persistsvc_c["persistsvc.c (c)"]
    class bof_test_persistsvc_c mod;
    bof_test_persistsvc_c_my_memcpy["my_memcpy"]
    class bof_test_persistsvc_c_my_memcpy fn;
    bof_test_persistsvc_c --> bof_test_persistsvc_c_my_memcpy
    bof_test_persistsvc_c_my_strlen["my_strlen"]
    class bof_test_persistsvc_c_my_strlen fn;
    bof_test_persistsvc_c --> bof_test_persistsvc_c_my_strlen
    bof_test_persistsvc_c_my_strcat["my_strcat"]
    class bof_test_persistsvc_c_my_strcat fn;
    bof_test_persistsvc_c --> bof_test_persistsvc_c_my_strcat
    bof_test_persistsvc_c_my_strcmp["my_strcmp"]
    class bof_test_persistsvc_c_my_strcmp fn;
    bof_test_persistsvc_c --> bof_test_persistsvc_c_my_strcmp
    bof_test_persistsvc_c_ServiceHandler["ServiceHandler"]
    class bof_test_persistsvc_c_ServiceHandler fn;
    bof_test_persistsvc_c --> bof_test_persistsvc_c_ServiceHandler
    bof_test_loadvnc_c["loadvnc.c (c)"]
    class bof_test_loadvnc_c mod;
    bof_test_loadvnc_c__PROCESSENTRY32["_PROCESSENTRY32"]
    class bof_test_loadvnc_c__PROCESSENTRY32 cls;
    bof_test_loadvnc_c --> bof_test_loadvnc_c__PROCESSENTRY32
    bof_test_loadvnc_c_execute_cmd_hidden["execute_cmd_hidden"]
    class bof_test_loadvnc_c_execute_cmd_hidden fn;
    bof_test_loadvnc_c --> bof_test_loadvnc_c_execute_cmd_hidden
    bof_test_loadvnc_c_go["go"]
    class bof_test_loadvnc_c_go fn;
    bof_test_loadvnc_c --> bof_test_loadvnc_c_go
    bof_test_loadvnc_c_TH32CS_SNAPPROCESS["TH32CS_SNAPPROCESS"]
    class bof_test_loadvnc_c_TH32CS_SNAPPROCESS fn;
    bof_test_loadvnc_c --> bof_test_loadvnc_c_TH32CS_SNAPPROCESS
    bof_test_make_table_c["make_table.c (c)"]
    class bof_test_make_table_c mod;
    bof_test_make_table_c_Copyright["Copyright"]
    class bof_test_make_table_c_Copyright fn;
    bof_test_make_table_c --> bof_test_make_table_c_Copyright
    bof_test_make_table_c_main["main"]
    class bof_test_make_table_c_main fn;
    bof_test_make_table_c --> bof_test_make_table_c_main
    bof_test_uacbypass_c["uacbypass.c (c)"]
    class bof_test_uacbypass_c mod;
    bof_test_uacbypass_c_execute_hidden_cmd["execute_hidden_cmd"]
    class bof_test_uacbypass_c_execute_hidden_cmd fn;
    bof_test_uacbypass_c --> bof_test_uacbypass_c_execute_hidden_cmd
    bof_test_uacbypass_c_go["go"]
    class bof_test_uacbypass_c_go fn;
    bof_test_uacbypass_c --> bof_test_uacbypass_c_go
    bof_calc_calc_c["calc.c (c)"]
    class bof_calc_calc_c mod;
    bof_calc_calc_c_go["go"]
    class bof_calc_calc_c_go fn;
    bof_calc_calc_c --> bof_calc_calc_c_go
    bof_etw_etw_c["etw.c (c)"]
    class bof_etw_etw_c mod;
    bof_etw_etw_c_go["go"]
    class bof_etw_etw_c_go fn;
    bof_etw_etw_c --> bof_etw_etw_c_go
    bof_test_amsibypass_c["amsibypass.c (c)"]
    class bof_test_amsibypass_c mod;
    bof_test_amsibypass_c_go["go"]
    class bof_test_amsibypass_c_go fn;
    bof_test_amsibypass_c --> bof_test_amsibypass_c_go
    bof_test_cmdwhoami_c["cmdwhoami.c (c)"]
    class bof_test_cmdwhoami_c mod;
    bof_test_cmdwhoami_c_go["go"]
    class bof_test_cmdwhoami_c_go fn;
    bof_test_cmdwhoami_c --> bof_test_cmdwhoami_c_go
    bof_test_getenv_c["getenv.c (c)"]
    class bof_test_getenv_c mod;
    bof_test_getenv_c_go["go"]
    class bof_test_getenv_c_go fn;
    bof_test_getenv_c --> bof_test_getenv_c_go
    bof_test_persist_c["persist.c (c)"]
    class bof_test_persist_c mod;
    bof_test_persist_c_go["go"]
    class bof_test_persist_c_go fn;
    bof_test_persist_c --> bof_test_persist_c_go
    bof_test_shellcode_c["shellcode.c (c)"]
    class bof_test_shellcode_c mod;
    bof_test_shellcode_c_go["go"]
    class bof_test_shellcode_c_go fn;
    bof_test_shellcode_c --> bof_test_shellcode_c_go
    bof_test_winver_c["winver.c (c)"]
    class bof_test_winver_c mod;
    bof_test_winver_c_go["go"]
    class bof_test_winver_c_go fn;
    bof_test_winver_c --> bof_test_winver_c_go
    bof_whoami_whoami_c["whoami.c (c)"]
    class bof_whoami_whoami_c mod;
    bof_whoami_whoami_c_go["go"]
    class bof_whoami_whoami_c_go fn;
    bof_whoami_whoami_c --> bof_whoami_whoami_c_go
    cJSON_h["cJSON.h (h)"]
    class cJSON_h mod;
    cJSON_h_cJSON["cJSON"]
    class cJSON_h_cJSON cls;
    cJSON_h --> cJSON_h_cJSON
    cJSON_h_cJSON_Hooks["cJSON_Hooks"]
    class cJSON_h_cJSON_Hooks cls;
    cJSON_h --> cJSON_h_cJSON_Hooks
    cJSON_h_cJSON__h["cJSON__h"]
    class cJSON_h_cJSON__h fn;
    cJSON_h --> cJSON_h_cJSON__h
    cJSON_h___WINDOWS__["__WINDOWS__"]
    class cJSON_h___WINDOWS__ fn;
    cJSON_h --> cJSON_h___WINDOWS__
    cJSON_h_CJSON_CDECL["CJSON_CDECL"]
    class cJSON_h_CJSON_CDECL fn;
    cJSON_h --> cJSON_h_CJSON_CDECL
    beacon_h["beacon.h (h)"]
    class beacon_h mod;
    beacon_h_BEACON_H["BEACON_H"]
    class beacon_h_BEACON_H fn;
    beacon_h --> beacon_h_BEACON_H
    beacon_h_CALLBACK_OUTPUT["CALLBACK_OUTPUT"]
    class beacon_h_CALLBACK_OUTPUT fn;
    beacon_h --> beacon_h_CALLBACK_OUTPUT
    beacon_h_CALLBACK_ERROR["CALLBACK_ERROR"]
    class beacon_h_CALLBACK_ERROR fn;
    beacon_h --> beacon_h_CALLBACK_ERROR
    bof_calc_beacon_h["beacon.h (h)"]
    class bof_calc_beacon_h mod;
    bof_calc_beacon_h_BEACON_H["BEACON_H"]
    class bof_calc_beacon_h_BEACON_H fn;
    bof_calc_beacon_h --> bof_calc_beacon_h_BEACON_H
    bof_calc_beacon_h_CALLBACK_OUTPUT["CALLBACK_OUTPUT"]
    class bof_calc_beacon_h_CALLBACK_OUTPUT fn;
    bof_calc_beacon_h --> bof_calc_beacon_h_CALLBACK_OUTPUT
    bof_calc_beacon_h_CALLBACK_ERROR["CALLBACK_ERROR"]
    class bof_calc_beacon_h_CALLBACK_ERROR fn;
    bof_calc_beacon_h --> bof_calc_beacon_h_CALLBACK_ERROR
    bof_etw_beacon_h["beacon.h (h)"]
    class bof_etw_beacon_h mod;
    bof_etw_beacon_h_BEACON_H["BEACON_H"]
    class bof_etw_beacon_h_BEACON_H fn;
    bof_etw_beacon_h --> bof_etw_beacon_h_BEACON_H
    bof_etw_beacon_h_CALLBACK_OUTPUT["CALLBACK_OUTPUT"]
    class bof_etw_beacon_h_CALLBACK_OUTPUT fn;
    bof_etw_beacon_h --> bof_etw_beacon_h_CALLBACK_OUTPUT
    bof_etw_beacon_h_CALLBACK_ERROR["CALLBACK_ERROR"]
    class bof_etw_beacon_h_CALLBACK_ERROR fn;
    bof_etw_beacon_h --> bof_etw_beacon_h_CALLBACK_ERROR
    bof_test_beacon_h["beacon.h (h)"]
    class bof_test_beacon_h mod;
    bof_test_beacon_h_BEACON_H["BEACON_H"]
    class bof_test_beacon_h_BEACON_H fn;
    bof_test_beacon_h --> bof_test_beacon_h_BEACON_H
    bof_test_beacon_h_CALLBACK_OUTPUT["CALLBACK_OUTPUT"]
    class bof_test_beacon_h_CALLBACK_OUTPUT fn;
    bof_test_beacon_h --> bof_test_beacon_h_CALLBACK_OUTPUT
    bof_test_beacon_h_CALLBACK_ERROR["CALLBACK_ERROR"]
    class bof_test_beacon_h_CALLBACK_ERROR fn;
    bof_test_beacon_h --> bof_test_beacon_h_CALLBACK_ERROR
    bof_whoami_beacon_h["beacon.h (h)"]
    class bof_whoami_beacon_h mod;
    bof_whoami_beacon_h_BEACON_H["BEACON_H"]
    class bof_whoami_beacon_h_BEACON_H fn;
    bof_whoami_beacon_h --> bof_whoami_beacon_h_BEACON_H
    bof_whoami_beacon_h_CALLBACK_OUTPUT["CALLBACK_OUTPUT"]
    class bof_whoami_beacon_h_CALLBACK_OUTPUT fn;
    bof_whoami_beacon_h --> bof_whoami_beacon_h_CALLBACK_OUTPUT
    bof_whoami_beacon_h_CALLBACK_ERROR["CALLBACK_ERROR"]
    class bof_whoami_beacon_h_CALLBACK_ERROR fn;
    bof_whoami_beacon_h --> bof_whoami_beacon_h_CALLBACK_ERROR
    COFFLoader_h["COFFLoader.h (h)"]
    class COFFLoader_h mod;
    COFFLoader_h_COFFLOADER_H["COFFLOADER_H"]
    class COFFLoader_h_COFFLOADER_H fn;
    COFFLoader_h --> COFFLoader_h_COFFLOADER_H
    bof_test_Test_c["Test.c (c)"]
    class bof_test_Test_c mod;
    bof_test_Test_c_go["go"]
    class bof_test_Test_c_go fn;
    bof_test_Test_c --> bof_test_Test_c_go
    app_py["app.py (py)"]
    class app_py mod;
    gen_beacon_sh["gen_beacon.sh (sh)"]
    class gen_beacon_sh mod;
    gen_beacon_sh_show_help["show_help"]
    class gen_beacon_sh_show_help fn;
    gen_beacon_sh --> gen_beacon_sh_show_help
    gen_beacon_sh_xor_string["xor_string"]
    class gen_beacon_sh_xor_string fn;
    gen_beacon_sh --> gen_beacon_sh_xor_string
    gen_beacon_sh_crc32["crc32"]
    class gen_beacon_sh_crc32 fn;
    gen_beacon_sh --> gen_beacon_sh_crc32
    gen_module_sh["gen_module.sh (sh)"]
    class gen_module_sh mod;
    gen_module_sh_show_help["show_help"]
    class gen_module_sh_show_help fn;
    gen_module_sh --> gen_module_sh_show_help
    gen_module_sh_xor_obfuscate["xor_obfuscate"]
    class gen_module_sh_xor_obfuscate fn;
    gen_module_sh --> gen_module_sh_xor_obfuscate
    gen_dll_rev_sh["gen_dll_rev.sh (sh)"]
    class gen_dll_rev_sh mod;
    gen_dll_rev_sh_usage["usage"]
    class gen_dll_rev_sh_usage fn;
    gen_dll_rev_sh --> gen_dll_rev_sh_usage
    gen_dll_ss_sh["gen_dll_ss.sh (sh)"]
    class gen_dll_ss_sh mod;
    gen_dll_ss_sh_usage["usage"]
    class gen_dll_ss_sh_usage fn;
    gen_dll_ss_sh --> gen_dll_ss_sh_usage
    gen_key_sh["gen_key.sh (sh)"]
    class gen_key_sh mod;
    gen_key_sh_usage["usage"]
    class gen_key_sh_usage fn;
    gen_key_sh --> gen_key_sh_usage
    bof_calc_build_sh["build.sh (sh)"]
    class bof_calc_build_sh mod;
    bof_etw_build_sh["build.sh (sh)"]
    class bof_etw_build_sh mod;
    bof_test_build_sh["build.sh (sh)"]
    class bof_test_build_sh mod;
    bof_whoami_build_sh["build.sh (sh)"]
    class bof_whoami_build_sh mod;
    build_sh["build.sh (sh)"]
    class build_sh mod;
    gen_dll_sh["gen_dll.sh (sh)"]
    class gen_dll_sh mod;
    install_sh["install.sh (sh)"]
    class install_sh mod;
    ext_windows_h["windows.h"]
    class ext_windows_h ext;
    COFFLoader_h -.->|imports| ext_windows_h
    COFFLoader3_c -.->|imports| ext_windows_h
    ext_stdio_h["stdio.h"]
    class ext_stdio_h ext;
    COFFLoader3_c -.->|imports| ext_stdio_h
    ext_stdlib_h["stdlib.h"]
    class ext_stdlib_h ext;
    COFFLoader3_c -.->|imports| ext_stdlib_h
    ext_string_h["string.h"]
    class ext_string_h ext;
    COFFLoader3_c -.->|imports| ext_string_h
    ext_stdint_h["stdint.h"]
    class ext_stdint_h ext;
    COFFLoader3_c -.->|imports| ext_stdint_h
    ext_beacon_h["beacon.h"]
    class ext_beacon_h ext;
    COFFLoader3_c -.->|imports| ext_beacon_h
    ext_aes_h["aes.h"]
    class ext_aes_h ext;
    aes_c -.->|imports| ext_aes_h
    aes_c -.->|imports| ext_string_h
    aes_h -.->|imports| ext_stdint_h
    ext_stddef_h["stddef.h"]
    class ext_stddef_h ext;
    aes_h -.->|imports| ext_stddef_h
    ext_os["os"]
    class ext_os ext;
    app_py -.->|imports| ext_os
    ext_winsock2_h["winsock2.h"]
    class ext_winsock2_h ext;
    beacon_c -.->|imports| ext_winsock2_h
    ext_ws2tcpip_h["ws2tcpip.h"]
    class ext_ws2tcpip_h ext;
    beacon_c -.->|imports| ext_ws2tcpip_h
    beacon_c -.->|imports| ext_windows_h
    ext_winnt_h["winnt.h"]
    class ext_winnt_h ext;
    beacon_c -.->|imports| ext_winnt_h
    ext_winhttp_h["winhttp.h"]
    class ext_winhttp_h ext;
    beacon_c -.->|imports| ext_winhttp_h
    ext_wincrypt_h["wincrypt.h"]
    class ext_wincrypt_h ext;
    beacon_c -.->|imports| ext_wincrypt_h
    ext_ntstatus_h["ntstatus.h"]
    class ext_ntstatus_h ext;
    beacon_c -.->|imports| ext_ntstatus_h
    ext_tlhelp32_h["tlhelp32.h"]
    class ext_tlhelp32_h ext;
    beacon_c -.->|imports| ext_tlhelp32_h
    beacon_c -.->|imports| ext_stdio_h
    beacon_c -.->|imports| ext_stdlib_h
    beacon_c -.->|imports| ext_string_h
    ext_io_h["io.h"]
    class ext_io_h ext;
    beacon_c -.->|imports| ext_io_h
    ext_process_h["process.h"]
    class ext_process_h ext;
    beacon_c -.->|imports| ext_process_h
    ext_time_h["time.h"]
    class ext_time_h ext;
    beacon_c -.->|imports| ext_time_h
    ext_iphlpapi_h["iphlpapi.h"]
    class ext_iphlpapi_h ext;
    beacon_c -.->|imports| ext_iphlpapi_h
    ext_icmpapi_h["icmpapi.h"]
    class ext_icmpapi_h ext;
    beacon_c -.->|imports| ext_icmpapi_h
    ext_bcrypt_h["bcrypt.h"]
    class ext_bcrypt_h ext;
    beacon_c -.->|imports| ext_bcrypt_h
    ext_shlobj_h["shlobj.h"]
    class ext_shlobj_h ext;
    beacon_c -.->|imports| ext_shlobj_h
    ext_objbase_h["objbase.h"]
    class ext_objbase_h ext;
    beacon_c -.->|imports| ext_objbase_h
    ext_shellapi_h["shellapi.h"]
    class ext_shellapi_h ext;
    beacon_c -.->|imports| ext_shellapi_h
    ext_winioctl_h["winioctl.h"]
    class ext_winioctl_h ext;
    beacon_c -.->|imports| ext_winioctl_h
    ext_setjmp_h["setjmp.h"]
    class ext_setjmp_h ext;
    beacon_c -.->|imports| ext_setjmp_h
    beacon_c -.->|imports| ext_aes_h
    ext_cJSON_h["cJSON.h"]
    class ext_cJSON_h ext;
    beacon_c -.->|imports| ext_cJSON_h
    beacon_c -.->|imports| ext_beacon_h
    ext_COFFLoader_h["COFFLoader.h"]
    class ext_COFFLoader_h ext;
    beacon_c -.->|imports| ext_COFFLoader_h
    beacon_h -.->|imports| ext_windows_h
    bof_calc_beacon_h -.->|imports| ext_windows_h
    bof_calc_calc_c -.->|imports| ext_windows_h
    bof_calc_calc_c -.->|imports| ext_beacon_h
    bof_etw_beacon_h -.->|imports| ext_windows_h
    bof_etw_etw_c -.->|imports| ext_windows_h
    bof_etw_etw_c -.->|imports| ext_beacon_h
    bof_test_Test_c -.->|imports| ext_beacon_h
    bof_test_amsibypass_c -.->|imports| ext_windows_h
    bof_test_amsibypass_c -.->|imports| ext_beacon_h
    bof_test_beacon_h -.->|imports| ext_windows_h
    bof_test_cmdwhoami_c -.->|imports| ext_windows_h
    bof_test_cmdwhoami_c -.->|imports| ext_beacon_h
    bof_test_disablelog_c -.->|imports| ext_windows_h
    bof_test_disablelog_c -.->|imports| ext_tlhelp32_h
    ext_psapi_h["psapi.h"]
    class ext_psapi_h ext;
    bof_test_disablelog_c -.->|imports| ext_psapi_h
    ext_winternl_h["winternl.h"]
    class ext_winternl_h ext;
    bof_test_disablelog_c -.->|imports| ext_winternl_h
    bof_test_disablelog_c -.->|imports| ext_beacon_h
    bof_test_getenv_c -.->|imports| ext_windows_h
    bof_test_getenv_c -.->|imports| ext_beacon_h
    bof_test_loadvnc_c -.->|imports| ext_windows_h
    bof_test_loadvnc_c -.->|imports| ext_beacon_h
    bof_test_make_table_c -.->|imports| ext_stdint_h
    bof_test_make_table_c -.->|imports| ext_stdio_h
    bof_test_persist_c -.->|imports| ext_windows_h
    bof_test_persist_c -.->|imports| ext_beacon_h
    bof_test_persistsvc_c -.->|imports| ext_windows_h
    bof_test_persistsvc_c -.->|imports| ext_beacon_h
    bof_test_scan_shellcode_c -.->|imports| ext_windows_h
    bof_test_scan_shellcode_c -.->|imports| ext_tlhelp32_h
    bof_test_scan_shellcode_c -.->|imports| ext_beacon_h
    bof_test_shellcode_c -.->|imports| ext_windows_h
    bof_test_shellcode_c -.->|imports| ext_beacon_h
    bof_test_sock5_c -.->|imports| ext_windows_h
    bof_test_sock5_c -.->|imports| ext_beacon_h
    ext_requests["requests"]
    class ext_requests ext;
    bof_test_tel_py -.->|imports| ext_requests
    ext_re["re"]
    class ext_re ext;
    bof_test_tel_py -.->|imports| ext_re
    ext_uuid["uuid"]
    class ext_uuid ext;
    bof_test_tel_py -.->|imports| ext_uuid
    ext_json["json"]
    class ext_json ext;
    bof_test_tel_py -.->|imports| ext_json
    ext_Crypto_Cipher["Crypto.Cipher"]
    class ext_Crypto_Cipher ext;
    bof_test_tel_py -.->|imports| ext_Crypto_Cipher
    ext_datetime["datetime"]
    class ext_datetime ext;
    bof_test_tel_py -.->|imports| ext_datetime
    bof_test_uacbypass_c -.->|imports| ext_windows_h
    bof_test_uacbypass_c -.->|imports| ext_beacon_h
    bof_test_upload_c -.->|imports| ext_windows_h
    bof_test_upload_c -.->|imports| ext_beacon_h
    bof_test_vncrelay_c -.->|imports| ext_winsock2_h
    bof_test_vncrelay_c -.->|imports| ext_windows_h
    bof_test_vncrelay_c -.->|imports| ext_beacon_h
    bof_test_winver_c -.->|imports| ext_windows_h
    bof_test_winver_c -.->|imports| ext_beacon_h
    bof_whoami_beacon_h -.->|imports| ext_windows_h
    bof_whoami_whoami_c -.->|imports| ext_windows_h
    bof_whoami_whoami_c -.->|imports| ext_beacon_h
    cJSON_c -.->|imports| ext_string_h
    cJSON_c -.->|imports| ext_stdio_h
    ext_math_h["math.h"]
    class ext_math_h ext;
    cJSON_c -.->|imports| ext_math_h
    cJSON_c -.->|imports| ext_stdlib_h
    ext_limits_h["limits.h"]
    class ext_limits_h ext;
    cJSON_c -.->|imports| ext_limits_h
    ext_ctype_h["ctype.h"]
    class ext_ctype_h ext;
    cJSON_c -.->|imports| ext_ctype_h
    ext_float_h["float.h"]
    class ext_float_h ext;
    cJSON_c -.->|imports| ext_float_h
    ext_locale_h["locale.h"]
    class ext_locale_h ext;
    cJSON_c -.->|imports| ext_locale_h
    cJSON_c -.->|imports| ext_cJSON_h
    cJSON_h -.->|imports| ext_stddef_h
    ext_argparse["argparse"]
    class ext_argparse ext;
    generate_hashs_py -.->|imports| ext_argparse
    ext_sys["sys"]
    class ext_sys ext;
    generate_hashs_py -.->|imports| ext_sys
    generate_hashs_py -.->|imports| ext_re
    ext_pygments["pygments"]
    class ext_pygments ext;
    generate_hashs_py -.->|imports| ext_pygments
    ext_pygments_lexers["pygments.lexers"]
    class ext_pygments_lexers ext;
    generate_hashs_py -.->|imports| ext_pygments_lexers
    ext_pygments_formatters["pygments.formatters"]
    class ext_pygments_formatters ext;
    generate_hashs_py -.->|imports| ext_pygments_formatters
```

---

## Architecture Reference

### C (23 files)

#### `COFFLoader3.c`
**Path:** `COFFLoader3.c`

**Functions:**
- `djb2_hash` (line 632) - *pragma pack(pop) === Función hash DJB2 ===*
- `create_trampoline` (line 912)
- `handle_relocation` (line 940)
- `get_symbol_name` (line 1079)
- `__attribute__` (line 1102)
- `RunCOFF` (line 1112) - *=== Cargador COFF  ===*

**Macros:**
- `IMAGE_REL_AMD64_ABSOLUTE` (line 568)
- `IMAGE_REL_AMD64_ADDR64` (line 569)
- `IMAGE_REL_AMD64_ADDR32` (line 570)
- `IMAGE_REL_AMD64_ADDR32NB` (line 571)
- `IMAGE_REL_AMD64_REL32` (line 572)
- `IMAGE_REL_AMD64_REL32_1` (line 573)
- `IMAGE_REL_AMD64_REL32_2` (line 574)
- `IMAGE_REL_AMD64_REL32_3` (line 575)
- `IMAGE_REL_AMD64_REL32_4` (line 576)
- `IMAGE_REL_AMD64_REL32_5` (line 577)
- `IMAGE_REL_AMD64_SECTION` (line 578)
- `IMAGE_REL_AMD64_SECREL` (line 579)
- `IMAGE_REL_AMD64_SECREL7` (line 580)
- `IMAGE_REL_AMD64_TOKEN` (line 581)
- `IMAGE_REL_AMD64_SREL32` (line 582)
- `IMAGE_REL_AMD64_PAIR` (line 583)
- `IMAGE_REL_AMD64_SSPAN32` (line 584)

#### `aes.c`
**Path:** `aes.c`

**Functions:**
- `getSBoxValue` (line 12) - *aes.c - tiny-AES-c (https://github.com/kokke/tiny-AES-c) include "aes.h" include <string.h> define Nb 4 define KEYLEN_256 32 define RKLENGTH (4 * (...*
- `getSBoxInvert` (line 34)
- `Td0` (line 56)
- `Td1` (line 58)
- `Td2` (line 59)
- `Td3` (line 60)
- `Td4` (line 61)
- `KeyExpansion` (line 166) - *static uint8_t getSBoxValue(uint8_t num) { return sbox[num]; }  define getSBoxValue(num) (sbox[(num)]) This function produces Nb(Nr+1) round keys. ...*
- `AES_init_ctx` (line 238)
- `AES_init_ctx_iv` (line 244) - *if (defined(CBC) && (CBC == 1)) || (defined(CTR) && (CTR == 1))*
- `AES_ctx_set_iv` (line 249)
- `AddRoundKey` (line 257) - *endif This function adds the round key to state. The round key is added to the state by an XOR function.*
- `SubBytes` (line 271) - *The SubBytes Function Substitutes the values in the state matrix with values in an S-box.*
- `ShiftRows` (line 286) - *The ShiftRows() function shifts the rows in the state to the left. Each row is shifted with different offset. Offset = Row number. So the first row...*
- `xtime` (line 313)
- `MixColumns` (line 320) - *MixColumns function mixes the columns of the state matrix*
- `Multiply` (line 340) - *Multiply is used to multiply numbers in the field GF(2^8) Note: The last call to xtime() is unneeded, but often ends up generating a smaller binary...*
- `InvMixColumns` (line 370) - *static uint8_t getSBoxInvert(uint8_t num) { return rsbox[num]; }  define getSBoxInvert(num) (rsbox[(num)]) MixColumns function mixes the columns of...*
- `InvSubBytes` (line 391) - *The SubBytes Function Substitutes the values in the state matrix with values in an S-box.*
- `InvShiftRows` (line 402)
- `Cipher` (line 433) - *endif // #if (defined(CBC) && CBC == 1) || (defined(ECB) && ECB == 1) Cipher is the main function that encrypts the PlainText.*
- `InvCipher` (line 459) - *if (defined(CBC) && CBC == 1) || (defined(ECB) && ECB == 1)*
- `AES_ECB_encrypt` (line 488) - *AddRoundKey(round, state, RoundKey); if (round == 0) { break; } InvMixColumns(state); }  } #endif // #if (defined(CBC) && CBC == 1) || (defined(ECB...*
- `AES_ECB_decrypt` (line 495)
- `XorWithIv` (line 510) - *endif // #if defined(ECB) && (ECB == 1) if defined(CBC) && (CBC == 1)*
- `AES_CBC_encrypt_buffer` (line 520)
- `AES_CBC_decrypt_buffer` (line 535)
- `AES_CTR_xcrypt_buffer` (line 558) - *XorWithIv(buf, ctx->Iv); memcpy(ctx->Iv, storeNextIv, AES_BLOCKLEN); buf += AES_BLOCKLEN; }  }  #endif // #if defined(CBC) && (CBC == 1)    #if def...*

**Macros:**
- `Nb` (line 4)
- `KEYLEN_256` (line 6)
- `RKLENGTH` (line 10)
- `BLOCKLEN` (line 11)
- `Nb` (line 67)
- `Nk` (line 70)
- `Nr` (line 71)
- `Nk` (line 73)
- `Nr` (line 74)
- `Nk` (line 76)
- `Nr` (line 77)
- `MULTIPLY_AS_A_FUNCTION` (line 84)
- `getSBoxValue` (line 163)
- `Multiply` (line 349)
- `getSBoxInvert` (line 365)

#### `beacon.c`
**Path:** `beacon.c`

**Functions:**
- `ExceptionFilter` (line 253)
- `get_shell_cmd` (line 334)
- `__declspec` (line 416) - *=== Beacon API: implementaciones exportables para BOFs ===*
- `__declspec` (line 422)
- `__declspec` (line 430)
- `__declspec` (line 435)
- `__declspec` (line 440)
- `__declspec` (line 445)
- `__declspec` (line 455)
- `__declspec` (line 503)
- `MapDllNameToModule` (line 521) - *=== MAP DLL NAME TO REAL DLL ===*
- `GetSyscallNumber` (line 548)
- `HellsGate` (line 560)
- `__attribute__` (line 565)
- `GetProcessIdByName` (line 581)
- `ExecuteTLSCallbacks` (line 600) - *=== EJECUTAR TLS CALLBACKS ===*
- `MapModuleToMemory` (line 617) - *=== Carga un módulo en memoria ===*
- `ExecuteModule` (line 706) - *=== Ejecuta el módulo (DllMain o EntryPoint) ===*
- `LoadModuleFromURL` (line 751) - *=== Carga y ejecuta un módulo desde URL ===*
- `xor_string` (line 915) - *=== XOR ===*
- `anti_analysis` (line 922) - *=== ANTI-ANALYSIS ===*
- `load_lazyconf` (line 945)
- `GetNtdllBase` (line 1183)
- `isVMByMAC` (line 1231)
- `extract_shellcode` (line 1303) - *=== EXTRAER SHELLCODE ===*
- `hex_char_to_byte` (line 1334) - *Función para convertir hex a bytes*
- `hex_to_bytes` (line 1340)
- `executeLoader` (line 1348) - *=== executeLoader ===*
- `ReverseShell` (line 1404) - *======================== FUNCIÓN DE INYECCIÓN DE SHELL ========================*
- `ReadFromProcess` (line 1513) - *=== Hilo para leer salida del proceso (como en el ejemplo que funciona) ===*
- `GetJitteredSleep` (line 1586)
- `GetUsefulSoftware` (line 1591)
- `base64_encode` (line 1626)
- `base64_decode` (line 1662)
- `discoverLocalHosts` (line 1695)
- `initProxy` (line 1752) - *startProxy.c*
- `relay_thread` (line 1763) - *Función para reenviar datos entre sockets*
- `proxy_thread` (line 1784) - *Tu función proxy_thread usando tus estructuras exactas*
- `proxy_accept_thread` (line 1855) - *Thread para aceptar conexiones*
- `startProxy` (line 1922)
- `stopProxy` (line 2009)
- `cleanupProxy` (line 2061)
- `compressDirectory` (line 2094) - *Función simplificada para compresión de directorios*
- `getNetworkConfig` (line 2104) - *Para netconfig*
- `UploadFileToC2` (line 2107)
- `handleUpload` (line 2280) - *=== handleUpload: envía del beacon al C2 ===*
- `FileExistsA` (line 2301) - *Función para verificar si un archivo existe*
- `selfDestruct` (line 2306) - *selfdestruct.c*
- `stristr` (line 2361)
- `isSensitiveFile` (line 2378)
- `searchCredentials` (line 2424)
- `UTF8ToWide` (line 2551) - *Convierte UTF-8 a wide string*
- `obfuscateFileTimestamp` (line 2562) - *Ofusca los timestamps de un archivo*
- `obfuscateFileTimestamps` (line 2592) - *Recorre directorios buscando archivos sensibles*
- `simulateLegitimateTraffic` (line 2656) - *traffic.c*
- `restartClient` (line 2734)
- `checkDebuggers` (line 2776)
- `MapPEToMemory` (line 2837)
- `downloadAndExecute` (line 2860)
- `DecryptPacket` (line 2910)
- `GetIPs` (line 3006)
- `GetHostname` (line 3039)
- `GetUsername` (line 3056)
- `patchAMSI` (line 3072)
- `get_nt_headers` (line 3092) - *==================================================================== PE HELPERS (usando winnt.h) ==================================================...*
- `is_64bit` (line 3100)
- `get_image_size` (line 3106)
- `get_entry_point_rva` (line 3112)
- `pe_buffer_to_virtual_image` (line 3117)
- `create_suspended_process` (line 3148) - *==================================================================== PROCESS MANIPULATION =========================================================...*
- `get_remote_image_base` (line 3154)
- `update_remote_entry_point` (line 3249)
- `overWrite` (line 3277) - *==================================================================== MAIN FUNCTION: overWrite =====================================================...*
- `cleanSystemLogs` (line 3384) - *Limpia el historial de comandos de la consola actual*
- `ensurePersistence` (line 3421) - *ensurePersistence.c*
- `isSandboxEnvironment` (line 3482) - *isSandboxEnvironment.c*
- `tryPrivilegeEscalation` (line 3551)
- `executeUACBypass` (line 3556)
- `scanPort` (line 3610)
- `PortScanner` (line 3661) - *PortScanner.c*
- `PortScannerWrapper` (line 3705)
- `EarlyBirdInject` (line 3729) - *================================================================================================= Early Bird APC Injection ========================...*
- `init_aes_context` (line 3898)
- `retry_http_request` (line 3918) - *retry_http_request.c*
- `exec_cmd` (line 4172) - *exec_cmd.c*
- `GetC2Command` (line 4200) - *================================================================================================= C2 Communication & File Download ================...*
- `DownloadToBuffer` (line 4346)
- `DownloadFromURL` (line 4422)
- `encrypt_data` (line 4452)
- `isValidUUID` (line 4511)
- `deleteFilesDelay` (line 4536)
- `executeCommand` (line 4550)
- `handleAtomic` (line 4559)
- `handleDownload` (line 4683) - *=== handleDownload: descarga del C2 al beacon ===*
- `SerializeBeaconString` (line 4702)
- `BeaconDataSerializeString` (line 4711)
- `go` (line 4719)
- `handleAdversary` (line 4738) - *Función principal de manejo de comandos*
- `main` (line 5233) - *main.c*

**Macros:**
- `PSAPI_VERSION` (line 19)
- `WIN32_LEAN_AND_MEAN` (line 21)
- `XOR_KEY` (line 71)
- `DEBUG` (line 72)
- `TIMEOUT` (line 73)
- `MAX_RESPONSE_SIZE` (line 74)
- `C2_URL` (line 75)
- `MALEABLE` (line 76)
- `CLIENT_ID` (line 77)
- `SLEEP_BASE` (line 78)
- `MIN_JITTER` (line 79)
- `MAX_JITTER` (line 80)
- `MAX_RETRIES` (line 81)
- `C2_HOST` (line 82)
- `LC2_HOST` (line 83)
- `C2_USER` (line 84)
- `C2_PASS` (line 85)
- `C2_PORT` (line 86)
- `CONFIG_PATH` (line 87)
- `C2_PATH` (line 88)
- `LC2_PATH` (line 89)
- `min` (line 91)
- `SECURITY_FLAG_IGNORE_REVOCATION` (line 94)
- `INVALID_SOCKET` (line 97)
- `USER_AGENT` (line 99)
- `USER_AGENT_A` (line 100)
- `IMAGE_DOS_SIGNATURE` (line 101)
- `IMAGE_NT_SIGNATURE` (line 102)
- `IMAGE_NT_OPTIONAL_HDR32_MAGIC` (line 103)
- `IMAGE_NT_OPTIONAL_HDR64_MAGIC` (line 104)
- `SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE` (line 106)
- `SECURITY_FLAG_IGNORE_INVALID_POLICY` (line 109)
- `_SECURITY_PACKAGE_DEFINITION_` (line 112)
- `_PROCESS_BASIC_INFORMATION_` (line 115)
- `_SP_LSA_MODE_INITIALIZE_DEFINED_` (line 117)
- `ProcessBasicInformation` (line 123)
- `CHECK_ERROR` (line 125)
- `NUM_USER_AGENTS` (line 231)
- `NUM_URLS` (line 240)
- `NUM_UAS` (line 247)
- `NT_SUCCESS` (line 300)

**Structs:**
- `_PROCESS_BASIC_INFORMATION` (line 129) - *define _PROCESS_BASIC_INFORMATION_ ifndef _SP_LSA_MODE_INITIALIZE_DEFINED_ define _SP_LSA_MODE_INITIALIZE_DEFINED_ endif Also define the ProcessInf...*
- `_UNICODE_STRING` (line 262) - *=== ESTRUCTURAS NECESARIAS (MinGW-safe) ===*
- `_LDR_DATA_TABLE_ENTRY` (line 268)
- `_PEB_LDR_DATA` (line 278)
- `_PEB` (line 287)

#### `calc.c`
**Path:** `bof/calc/calc.c`

**Functions:**
- `go` (line 34) - *================================ FUNCIÓN PRINCIPAL ================================*

#### `etw.c`
**Path:** `bof/etw/etw.c`

**Functions:**
- `go` (line 26)

#### `Test.c`
**Path:** `bof/test/Test.c`

**Functions:**
- `go` (line 2) - *include "beacon.h"*

#### `amsibypass.c`
**Path:** `bof/test/amsibypass.c`

**Functions:**
- `go` (line 34) - *================================ FUNCIÓN PRINCIPAL ================================*

#### `cmdwhoami.c`
**Path:** `bof/test/cmdwhoami.c`

**Functions:**
- `go` (line 42)

#### `disablelog.c`
**Path:** `bof/test/disablelog.c`

**Functions:**
- `my_wcscmp` (line 36) - *ifndef NT_SUCCESS define NT_SUCCESS(x) ((x) >= 0) endif*
- `go` (line 68)

**Macros:**
- `WIN32_LEAN_AND_MEAN` (line 20)
- `NT_SUCCESS` (line 34)

#### `getenv.c`
**Path:** `bof/test/getenv.c`

**Functions:**
- `go` (line 24)

#### `loadvnc.c`
**Path:** `bof/test/loadvnc.c`

**Functions:**
- `execute_cmd_hidden` (line 51) - *================================ FUNCIÓN AUX: EJECUTAR COMANDO OCULTO ================================*
- `go` (line 81) - *================================ FUNCIÓN PRINCIPAL ================================*

**Macros:**
- `TH32CS_SNAPPROCESS` (line 33)

**Structs:**
- `_PROCESSENTRY32` (line 35) - *================================ DEFINICIONES MANUALES ================================ define TH32CS_SNAPPROCESS 0x00000002*

#### `make_table.c`
**Path:** `bof/test/make_table.c`

**Functions:**
- `Copyright` (line 16)
- `main` (line 33)

#### `persist.c`
**Path:** `bof/test/persist.c`

**Functions:**
- `go` (line 26)

#### `persistsvc.c`
**Path:** `bof/test/persistsvc.c`

**Functions:**
- `my_memcpy` (line 33) - *================================ FUNCIONES AUXILIARES ================================*
- `my_strlen` (line 39)
- `my_strcat` (line 46)
- `my_strcmp` (line 54)
- `ServiceHandler` (line 82) - *================================ MANEJADOR DE CONTROL DEL SERVICIO ================================*
- `ServiceMain` (line 116) - *================================ FUNCIÓN PRINCIPAL DEL SERVICIO ================================*
- `go` (line 251) - *================================ FUNCIÓN PRINCIPAL DEL BOF ================================*

**Macros:**
- `WIN32_LEAN_AND_MEAN` (line 19)
- `RESOLVE_API` (line 65)
- `cleanup` (line 131)
- `cleanup` (line 183)

#### `scan_shellcode.c`
**Path:** `bof/test/scan_shellcode.c`

**Functions:**
- `go` (line 84)

**Macros:**
- `WIN32_LEAN_AND_MEAN` (line 19)

#### `shellcode.c`
**Path:** `bof/test/shellcode.c`

**Functions:**
- `go` (line 25)

#### `sock5.c`
**Path:** `bof/test/sock5.c`

**Functions:**
- `my_FD_ISSET` (line 107) - *typedef int       (WINAPI *LISTEN)(SOCKET, int); typedef SOCKET    (WINAPI *ACCEPT)(SOCKET, struct sockaddr*, int*); typedef int       (WINAPI *CON...*
- `HandleSocks5Connection` (line 118) - *typedef USHORT    (WINAPI *NTOHS)(USHORT);  /* ===== AUXILIARES ===== static int my_FD_ISSET(SOCKET s, fd_set *set) { if (!set) return 0; for (u_in...*
- `ProxyThread` (line 261) - *break; } if (pSend(client_sock, buf, n, 0) != n) { BeaconPrintf(CALLBACK_ERROR, "[SOCKS5] Falló al reenviar al cliente\n"); break; } BeaconPrintf(C...*
- `go` (line 358) - *cleanup_srv: pCloseSocket(srv); cleanup_wsa: pWSACleanup(); cleanup_event: if (g_hShutdownEvent) { ((BOOL (WINAPI*)(HANDLE))__imp_CloseHandle)(g_hS...*

**Macros:**
- `WIN32_LEAN_AND_MEAN` (line 1)
- `INVALID_SOCKET` (line 7)
- `SOCKET_ERROR` (line 8)
- `AF_INET` (line 9)
- `SOCK_STREAM` (line 10)
- `IPPROTO_TCP` (line 11)
- `INADDR_ANY` (line 12)
- `INADDR_LOOPBACK` (line 13)
- `FD_SETSIZE` (line 36)
- `FD_CLR` (line 38)
- `FD_SET` (line 39)
- `FD_ZERO` (line 40)
- `FD_ISSET` (line 41)
- `h_addr` (line 64)
- `SOCKS5_LISTEN_PORT` (line 75)
- `SOCKS5_CONTROL_PORT` (line 76)
- `MAX_PENDING_CONNECTIONS` (line 77)
- `BUFFER_SIZE` (line 78)

**Structs:**
- `WSAData` (line 16) - *define INVALID_SOCKET  ((SOCKET)~0) define SOCKET_ERROR    (-1) define AF_INET         2 define SOCK_STREAM     1 define IPPROTO_TCP     6 define I...*
- `fd_set` (line 27) - *pragma pack(pop)*
- `timeval` (line 32)
- `in_addr` (line 47)
- `sockaddr_in` (line 49)
- `sockaddr` (line 56)
- `hostent` (line 58)

#### `uacbypass.c`
**Path:** `bof/test/uacbypass.c`

**Functions:**
- `execute_hidden_cmd` (line 33) - *================================ FUNCIÓN AUX: EJECUTAR COMANDO OCULTO ================================*
- `go` (line 61) - *================================ FUNCIÓN PRINCIPAL ================================*

#### `upload.c`
**Path:** `bof/test/upload.c`

**Functions:**
- `my_strlen` (line 53) - *================================ FUNCIONES AUXILIARES ================================*
- `my_memcpy` (line 58)
- `my_memset` (line 65)
- `my_contains_dotdot` (line 71)
- `my_strchr` (line 80)
- `xtime` (line 93) - *================================ AES (sin datos globales) ================================*
- `AddRoundKey` (line 98)
- `SubBytes` (line 105)
- `ShiftRows` (line 112)
- `MixColumns` (line 120)
- `Cipher` (line 132)
- `KeyExpansion` (line 145)
- `AES_init_ctx` (line 173)
- `AES_CFB_encrypt_buffer` (line 177)
- `my_base64_encode` (line 205) - *================================ BASE64 ================================*
- `ParseUploadArgs` (line 230)
- `go` (line 273) - *================================ FUNCIÓN PRINCIPAL ================================*

**Macros:**
- `WIN32_LEAN_AND_MEAN` (line 1)
- `PROV_RSA_AES` (line 20)
- `CRYPT_VERIFYCONTEXT` (line 21)
- `AES_BLOCKLEN` (line 22)
- `AES256_KEYLEN` (line 24)
- `Nr` (line 25)
- `Nk` (line 26)
- `Nb` (line 27)
- `SECURITY_FLAG_IGNORE_UNKNOWN_CA` (line 28)
- `SECURITY_FLAG_IGNORE_CERT_CN_INVALID` (line 30)
- `SECURITY_FLAG_IGNORE_CERT_DATE_INVALID` (line 31)
- `WINHTTP_OPTION_SECURITY_FLAGS` (line 32)
- `WINHTTP_ACCESS_TYPE_NO_PROXY` (line 35)
- `WINHTTP_NO_PROXY_NAME` (line 39)
- `WINHTTP_NO_PROXY_BYPASS` (line 43)
- `NEXT_TOKEN` (line 244)

#### `vncrelay.c`
**Path:** `bof/test/vncrelay.c`

**Functions:**
- `my_FD_ISSET` (line 62) - *================================ FD_ISSET MANUAL ================================*
- `relay_traffic` (line 75) - *================================ RELAY TRAFFIC ================================*
- `go` (line 132) - *================================ FUNCIÓN PRINCIPAL — ¡CORREGIDO! ================================*

#### `winver.c`
**Path:** `bof/test/winver.c`

**Functions:**
- `go` (line 24)

#### `whoami.c`
**Path:** `bof/whoami/whoami.c`

**Functions:**
- `go` (line 34) - *================================ FUNCIÓN PRINCIPAL ================================*

#### `cJSON.c`
**Path:** `cJSON.c`

**Functions:**
- `CJSON_PUBLIC` (line 94)
- `CJSON_PUBLIC` (line 99)
- `CJSON_PUBLIC` (line 109)
- `CJSON_PUBLIC` (line 124) - *CJSON_PUBLIC(double) cJSON_GetNumberValue(const cJSON * const item) { if (!cJSON_IsNumber(item)) { return (double) NAN; }  return item->valuedouble...*
- `case_insensitive_strcmp` (line 134) - */* This is a safeguard to prevent copy-pasters from using incompatible C and header files #if (CJSON_VERSION_MAJOR != 1) || (CJSON_VERSION_MINOR !=...*
- `internal_malloc` (line 166) - *}  return tolower(*string1) - tolower(*string2); }  typedef struct internal_hooks { void *(CJSON_CDECL *allocate)(size_t size); void (CJSON_CDECL *...*
- `internal_free` (line 170)
- `internal_realloc` (line 174)
- `cJSON_strdup` (line 188)
- `CJSON_PUBLIC` (line 209)
- `cJSON_New_Item` (line 242) - *if (hooks->free_fn != NULL) { global_hooks.deallocate = hooks->free_fn; }  /* use realloc only if both free and malloc are used global_hooks.reallo...*
- `get_decimal_point` (line 281) - *item->valuestring = NULL; } if (!(item->type & cJSON_StringIsConst) && (item->string != NULL)) { global_hooks.deallocate(item->string); item->strin...*
- `parse_number` (line 309) - *size_t offset; size_t depth; /* How deeply nested (in arrays/objects) is the input at the current offset. internal_hooks hooks; } parse_buffer;  /*...*
- `ensure` (line 494) - *}  typedef struct { unsigned char *buffer; size_t length; size_t offset; size_t depth; /* current nesting depth (for formatted printing) cJSON_bool...*
- `update_offset` (line 579) - *p->buffer = NULL;  return NULL; } memcpy(newbuffer, p->buffer, p->offset + 1); p->hooks.deallocate(p->buffer); } p->length = newsize; p->buffer = n...*
- `compare_double` (line 592) - */* calculate the new length of the string in a printbuffer and update the offset static void update_offset(printbuffer * const buffer) { const unsi...*
- `print_number` (line 599) - *} buffer_pointer = buffer->buffer + buffer->offset;  buffer->offset += strlen((const char*)buffer_pointer); }  /* securely comparison of floating-p...*
- `parse_hex4` (line 669) - *output_pointer[i] = '.'; continue; }  output_pointer[i] = number_buffer[i]; } output_pointer[i] = '\0';  output_buffer->offset += (size_t)length;  ...*
- `utf16_literal_to_utf8` (line 706) - *converts a UTF-16 literal to UTF-8 * A literal can be one or two sequences of the form \uXXXX*
- `parse_string` (line 827) - *else { (*output_pointer)[0] = (unsigned char)(codepoint & 0x7F); }  output_pointer += utf8_length;  return sequence_length;  fail: return 0; }  /* ...*
- `print_string_ptr` (line 957) - *{ input_buffer->hooks.deallocate(output); output = NULL; }  if (input_pointer != NULL) { input_buffer->offset = (size_t)(input_pointer - input_buff...*
- `print_string` (line 1079) - */* escape and print as unicode codepoint sprintf((char*)output_pointer, "u%04x", *input_pointer); output_pointer += 4; break; } } } output[output_l...*
- `buffer_skip_whitespace` (line 1093) - *static cJSON_bool print_string(const cJSON * const item, printbuffer * const p) { return print_string_ptr((unsigned char*)item->valuestring, p); } ...*
- `skip_utf8_bom` (line 1119) - *while (can_access_at_index(buffer, 0) && (buffer_at_offset(buffer)[0] <= 32)) { buffer->offset++; }  if (buffer->offset == buffer->length) { buffer...*
- `CJSON_PUBLIC` (line 1133)
- `CJSON_PUBLIC` (line 1235)
- `print` (line 1242) - *define cjson_min(a, b) (((a) < (b)) ? (a) : (b))*
- `CJSON_PUBLIC` (line 1315)
- `CJSON_PUBLIC` (line 1320)
- `CJSON_PUBLIC` (line 1351)
- `parse_value` (line 1372) - *return false; }  p.buffer = (unsigned char*)buffer; p.length = (size_t)length; p.offset = 0; p.noalloc = true; p.format = format; p.hooks = global_...*
- `print_value` (line 1427) - *if (can_access_at_index(input_buffer, 0) && (buffer_at_offset(input_buffer)[0] == '[')) { return parse_array(item, input_buffer); } /* object if (c...*
- `parse_array` (line 1501) - *return print_string(item, output_buffer);  case cJSON_Array: return print_array(item, output_buffer);  case cJSON_Object: return print_object(item,...*
- `print_array` (line 1599) - *input_buffer->offset++;  return true;  fail: if (head != NULL) { cJSON_Delete(head); }  return false; }  /* Render an array to text*
- `parse_object` (line 1661) - *output_pointer = ensure(output_buffer, 2); if (output_pointer == NULL) { return false; } output_pointer++ = ']'; output_pointer = '\0'; output_buff...*
- `print_object` (line 1780) - *input_buffer->offset++;  return true;  fail: if (head != NULL) { cJSON_Delete(head); }  return false; }  /* Render an object to text.*
- `get_array_item` (line 1915)
- `CJSON_PUBLIC` (line 1934)
- `get_object_item` (line 1944)
- `CJSON_PUBLIC` (line 1976)
- `CJSON_PUBLIC` (line 1981)
- `CJSON_PUBLIC` (line 1986)
- `suffix_object` (line 1993) - *return get_object_item(object, string, false); }  CJSON_PUBLIC(cJSON *) cJSON_GetObjectItemCaseSensitive(const cJSON * const object, const char * c...*
- `create_reference` (line 2000) - *CJSON_PUBLIC(cJSON_bool) cJSON_HasObjectItem(const cJSON *object, const char *string) { return cJSON_GetObjectItem(object, string) ? 1 : 0; }  /* U...*
- `add_item_to_array` (line 2020)
- `cast_away_const` (line 2066) - */* Add item to array/object. CJSON_PUBLIC(cJSON_bool) cJSON_AddItemToArray(cJSON *array, cJSON *item) { return add_item_to_array(array, item); }  #...*
- `add_item_to_object` (line 2073) - *if defined(__clang__) || (defined(__GNUC__) && ((__GNUC__ > 4) || ((__GNUC__ == 4) && (__GNUC__-MINOR__ > 5)))) pragma GCC diagnostic pop endif*
- `CJSON_PUBLIC` (line 2111)
- `CJSON_PUBLIC` (line 2122)
- `CJSON_PUBLIC` (line 2132)
- `CJSON_PUBLIC` (line 2142)
- `CJSON_PUBLIC` (line 2154)
- `CJSON_PUBLIC` (line 2166)
- `CJSON_PUBLIC` (line 2178)
- `CJSON_PUBLIC` (line 2190)
- `CJSON_PUBLIC` (line 2202)
- `CJSON_PUBLIC` (line 2214)
- `CJSON_PUBLIC` (line 2226)
- `CJSON_PUBLIC` (line 2238)
- `CJSON_PUBLIC` (line 2250)
- `CJSON_PUBLIC` (line 2286)
- `CJSON_PUBLIC` (line 2296)
- `CJSON_PUBLIC` (line 2301)
- `CJSON_PUBLIC` (line 2308)
- `CJSON_PUBLIC` (line 2315)
- `CJSON_PUBLIC` (line 2320)
- `CJSON_PUBLIC` (line 2362)
- `CJSON_PUBLIC` (line 2412)
- `replace_item_in_object` (line 2422)
- `CJSON_PUBLIC` (line 2445)
- `CJSON_PUBLIC` (line 2450)
- `CJSON_PUBLIC` (line 2467)
- `CJSON_PUBLIC` (line 2478)
- `CJSON_PUBLIC` (line 2489)
- `CJSON_PUBLIC` (line 2500)
- `CJSON_PUBLIC` (line 2525)
- `CJSON_PUBLIC` (line 2542)
- `CJSON_PUBLIC` (line 2554)
- `CJSON_PUBLIC` (line 2566)
- `CJSON_PUBLIC` (line 2578)
- `CJSON_PUBLIC` (line 2595)
- `CJSON_PUBLIC` (line 2606)
- `CJSON_PUBLIC` (line 2658)
- `CJSON_PUBLIC` (line 2698)
- `CJSON_PUBLIC` (line 2738)
- `cJSON_Duplicate_rec` (line 2785)
- `skip_oneline_comment` (line 2872)
- `skip_multiline_comment` (line 2885)
- `minify_string` (line 2899)
- `CJSON_PUBLIC` (line 2921)
- `CJSON_PUBLIC` (line 2971)
- `CJSON_PUBLIC` (line 2981)
- `CJSON_PUBLIC` (line 2991)
- `CJSON_PUBLIC` (line 3001)
- `CJSON_PUBLIC` (line 3011)
- `CJSON_PUBLIC` (line 3021)
- `CJSON_PUBLIC` (line 3031)
- `CJSON_PUBLIC` (line 3041)
- `CJSON_PUBLIC` (line 3051)
- `CJSON_PUBLIC` (line 3061)
- `CJSON_PUBLIC` (line 3071)
- `cJSON_ArrayForEach` (line 3157)
- `cJSON_ArrayForEach` (line 3173) - *doing this twice, once on a and b to prevent true comparison if a subset of b * TODO: Do this the proper way, this is just a fix for now*
- `CJSON_PUBLIC` (line 3193)
- `CJSON_PUBLIC` (line 3198)

**Macros:**
- `_CRT_SECURE_NO_DEPRECATE` (line 28)
- `true` (line 65)
- `false` (line 70)
- `isinf` (line 74)
- `isnan` (line 77)
- `NAN` (line 82)
- `NAN` (line 84)
- `internal_malloc` (line 179)
- `internal_free` (line 180)
- `internal_realloc` (line 181)
- `static_strlen` (line 185)
- `can_read` (line 301)
- `can_access_at_index` (line 303)
- `cannot_access_at_index` (line 304)
- `buffer_at_offset` (line 306)
- `cjson_min` (line 1240)

**Structs:**
- `internal_hooks` (line 157)

### H (8 files)

#### `COFFLoader.h`
**Path:** `COFFLoader.h`

**Macros:**
- `COFFLOADER_H` (line 21)

#### `aes.h`
**Path:** `aes.h`

**Macros:**
- `_AES_H_` (line 2)
- `CBC` (line 9)
- `ECB` (line 12)
- `CTR` (line 15)
- `AES256` (line 17)
- `AES_BLOCKLEN` (line 19)
- `AES_KEYLEN` (line 23)
- `AES_keyExpSize` (line 24)
- `AES_KEYLEN` (line 26)
- `AES_keyExpSize` (line 27)
- `AES_KEYLEN` (line 29)
- `AES_keyExpSize` (line 30)

**Structs:**
- `AES_ctx` (line 33) - *define AES_BLOCKLEN 16 // Block length in bytes - AES is 128b block only if defined(AES256) && (AES256 == 1) define AES_KEYLEN 32 define AES_keyExp...*

#### `beacon.h`
**Path:** `beacon.h`

**Macros:**
- `BEACON_H` (line 21)
- `CALLBACK_OUTPUT` (line 40)
- `CALLBACK_ERROR` (line 42)

#### `beacon.h`
**Path:** `bof/calc/beacon.h`

**Macros:**
- `BEACON_H` (line 21)
- `CALLBACK_OUTPUT` (line 40)
- `CALLBACK_ERROR` (line 42)

#### `beacon.h`
**Path:** `bof/etw/beacon.h`

**Macros:**
- `BEACON_H` (line 21)
- `CALLBACK_OUTPUT` (line 40)
- `CALLBACK_ERROR` (line 42)

#### `beacon.h`
**Path:** `bof/test/beacon.h`

**Macros:**
- `BEACON_H` (line 21)
- `CALLBACK_OUTPUT` (line 40)
- `CALLBACK_ERROR` (line 42)

#### `beacon.h`
**Path:** `bof/whoami/beacon.h`

**Macros:**
- `BEACON_H` (line 21)
- `CALLBACK_OUTPUT` (line 40)
- `CALLBACK_ERROR` (line 42)

#### `cJSON.h`
**Path:** `cJSON.h`

**Macros:**
- `cJSON__h` (line 24)
- `__WINDOWS__` (line 32)
- `CJSON_CDECL` (line 43)
- `CJSON_STDCALL` (line 45)
- `CJSON_EXPORT_SYMBOLS` (line 49)
- `CJSON_PUBLIC` (line 53)
- `CJSON_PUBLIC` (line 55)
- `CJSON_PUBLIC` (line 57)
- `CJSON_CDECL` (line 60)
- `CJSON_STDCALL` (line 61)
- `CJSON_PUBLIC` (line 64)
- `CJSON_PUBLIC` (line 66)
- `CJSON_VERSION_MAJOR` (line 71)
- `CJSON_VERSION_MINOR` (line 72)
- `CJSON_VERSION_PATCH` (line 73)
- `cJSON_Invalid` (line 78)
- `cJSON_False` (line 79)
- `cJSON_True` (line 80)
- `cJSON_NULL` (line 81)
- `cJSON_Number` (line 82)
- `cJSON_String` (line 83)
- `cJSON_Array` (line 84)
- `cJSON_Object` (line 85)
- `cJSON_Raw` (line 86)
- `cJSON_IsReference` (line 87)
- `cJSON_StringIsConst` (line 89)
- `CJSON_NESTING_LIMIT` (line 126)
- `CJSON_CIRCULAR_LIMIT` (line 132)
- `cJSON_SetIntValue` (line 270)
- `cJSON_SetNumberValue` (line 273)
- `cJSON_SetBoolValue` (line 278)
- `cJSON_ArrayForEach` (line 285)

**Structs:**
- `cJSON` (line 92) - *#define cJSON_Invalid (0) #define cJSON_False  (1 << 0) #define cJSON_True   (1 << 1) #define cJSON_NULL   (1 << 2) #define cJSON_Number (1 << 3) #...*
- `cJSON_Hooks` (line 114)

### PY (3 files)

#### `app.py`
**Path:** `app.py`

*No symbols extracted*

#### `tel.py`
**Path:** `bof/test/tel.py`

**Functions:**
- `get_machine_id` (line 8)
- `get_version` (line 20)
- `to_numbers` (line 31) - *Simula la función toNumbers de JavaScript*
- `to_hex` (line 35) - *Simula la función toHex de JavaScript*
- `decrypt_cookie` (line 39) - *Descifra usando AES en modo CBC (como slowAES.decrypt(c,2,a,b))*
- `main` (line 45) - *Sistema de telemetría de uso por instalación no invasiva.*

#### `generate_hashs.py`
**Path:** `generate_hashs.py`

**Functions:**
- `djb2` (line 23)
- `generate_coff_loader` (line 223)
- `generate_bof_test` (line 491)
- `main` (line 553)

### SH (12 files)

#### `build.sh`
**Path:** `bof/calc/build.sh`

*No symbols extracted*

#### `build.sh`
**Path:** `bof/etw/build.sh`

*No symbols extracted*

#### `build.sh`
**Path:** `bof/test/build.sh`

*No symbols extracted*

#### `build.sh`
**Path:** `bof/whoami/build.sh`

*No symbols extracted*

#### `build.sh`
**Path:** `build.sh`

*No symbols extracted*

#### `gen_beacon.sh`
**Path:** `gen_beacon.sh`

**Functions:**
- `show_help` (line 34) - *=== LEER ARGUMENTOS === Uso: script.sh [TARGET] [URL] [MALEABLE] [CLIENT_ID] ... [OUTPUT] Puedes pasar hasta 14 argumentos (todos los que tienes) =...*
- `xor_string` (line 138) - *=== XOR STRING TO BYTES ===*
- `crc32` (line 5916)

#### `gen_dll.sh`
**Path:** `gen_dll.sh`

*No symbols extracted*

#### `gen_dll_rev.sh`
**Path:** `gen_dll_rev.sh`

**Functions:**
- `usage` (line 12) - *=== USO ===*

#### `gen_dll_ss.sh`
**Path:** `gen_dll_ss.sh`

**Functions:**
- `usage` (line 10) - *=== USO ===*

#### `gen_key.sh`
**Path:** `gen_key.sh`

**Functions:**
- `usage` (line 10) - *=== USO ===*

#### `gen_module.sh`
**Path:** `gen_module.sh`

**Functions:**
- `show_help` (line 18) - *=== FUNCIONES ===*
- `xor_obfuscate` (line 35) - *Función para ofuscar binario con XOR y convertir a \x..*

#### `install.sh`
**Path:** `install.sh`

*No symbols extracted*

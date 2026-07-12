# Polyglot Codebase Knowledge Graph

> Generated offline by **readmenator**. Supports C, C++, Python, Go, Rust, JS/TS, Java, C#, Shell, PHP, Dart, GDScript, Nim, ASM.
> No LLMs. No tokens. Pure static analysis. See more [here](https://github.com/grisuno/ReadMenator)

**Total Files Parsed:** 46 | **Total Symbols Extracted:** 514 | **Total Imports:** 107

## Structural Knowledge Map
```mermaid
graph TD
    classDef mod fill:#1e1e1e,stroke:#ff6666,stroke-width:2px,color:#fff;
    classDef cls fill:#2d2d2d,stroke:#4ec9b0,stroke-width:2px,color:#fff;
    classDef fn fill:#333,stroke:#dcdcaa,stroke-width:1px,color:#dcdcaa;
    classDef ext fill:#111,stroke:#666,stroke-dasharray:5 5,color:#aaa;
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
- `djb2_hash` (line 632) `static uint32_t djb2_hash(const char* str)` - *=== Función hash DJB2 ===*
- `create_trampoline` (line 912) `static void* create_trampoline(void* target)`
- `handle_relocation` (line 940) `BOOL handle_relocation(COFFRelocation* rel, void* patch_addr, void* target, 
                    ...`
- `get_symbol_name` (line 1079) `static char* get_symbol_name(COFFSymbol* s, char* strtab, uint32_t strtab_size)`
- `__attribute__` (line 1102) `__attribute__((noinline))
static void call_go_aligned(void* func, char* arg1, int arg2)`
- `RunCOFF` (line 1112) `int RunCOFF(const char* functionname, unsigned char* coff_data, uint32_t filesize, unsigned char*...` - *=== Cargador COFF  ===*

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
- `getSBoxValue` (line 12) `static uint8_t getSBoxValue(uint8_t num)` - *define KEYLEN_256 32 define RKLENGTH (4 * (Nr + 1)) define BLOCKLEN 16*
- `getSBoxInvert` (line 34) `static uint8_t getSBoxInvert(uint8_t num)`
- `Td0` (line 56) `static uint8_t Td0(int x)`
- `Td1` (line 58) `static uint8_t Td1(int x)`
- `Td2` (line 59) `static uint8_t Td2(int x)`
- `Td3` (line 60) `static uint8_t Td3(int x)`
- `Td4` (line 61) `static uint8_t Td4(int x)`
- `KeyExpansion` (line 166) `static void KeyExpansion(uint8_t* RoundKey, const uint8_t* Key)` - *This function produces Nb(Nr+1) round keys. The round keys are used in each round to decrypt the states.*
- `AES_init_ctx` (line 238) `void AES_init_ctx(struct AES_ctx* ctx, const uint8_t* key)`
- `AES_init_ctx_iv` (line 244) `void AES_init_ctx_iv(struct AES_ctx* ctx, const uint8_t* key, const uint8_t* iv)` - *if (defined(CBC) && (CBC == 1)) || (defined(CTR) && (CTR == 1))*
- `AES_ctx_set_iv` (line 249) `void AES_ctx_set_iv(struct AES_ctx* ctx, const uint8_t* iv)`
- `AddRoundKey` (line 257) `static void AddRoundKey(uint8_t round, state_t* state, const uint8_t* RoundKey)` - *This function adds the round key to state. The round key is added to the state by an XOR function.*
- `SubBytes` (line 271) `static void SubBytes(state_t* state)` - *The SubBytes Function Substitutes the values in the state matrix with values in an S-box.*
- `ShiftRows` (line 286) `static void ShiftRows(state_t* state)` - *The ShiftRows() function shifts the rows in the state to the left. Each row is shifted with different offset. Offset = Row number. So the first row...*
- `xtime` (line 313) `static uint8_t xtime(uint8_t x)`
- `MixColumns` (line 320) `static void MixColumns(state_t* state)` - *MixColumns function mixes the columns of the state matrix*
- `Multiply` (line 340) `static uint8_t Multiply(uint8_t x, uint8_t y)` - *Multiply is used to multiply numbers in the field GF(2^8) Note: The last call to xtime() is unneeded, but often ends up generating a smaller binary...*
- `InvMixColumns` (line 370) `static void InvMixColumns(state_t* state)` - *MixColumns function mixes the columns of the state matrix. The method used to multiply may be difficult to understand for the inexperienced. Please...*
- `InvSubBytes` (line 391) `static void InvSubBytes(state_t* state)` - *The SubBytes Function Substitutes the values in the state matrix with values in an S-box.*
- `InvShiftRows` (line 402) `static void InvShiftRows(state_t* state)`
- `Cipher` (line 433) `static void Cipher(state_t* state, const uint8_t* RoundKey)` - *Cipher is the main function that encrypts the PlainText.*
- `InvCipher` (line 459) `static void InvCipher(state_t* state, const uint8_t* RoundKey)` - *if (defined(CBC) && CBC == 1) || (defined(ECB) && ECB == 1)*
- `AES_ECB_encrypt` (line 488) `void AES_ECB_encrypt(const struct AES_ctx* ctx, uint8_t* buf)` - *AddRoundKey(round, state, RoundKey); if (round == 0) { break; } InvMixColumns(state); } } #endif // #if (defined(CBC) && CBC == 1) || (defined(ECB)...*
- `AES_ECB_decrypt` (line 495) `void AES_ECB_decrypt(const struct AES_ctx* ctx, uint8_t* buf)`
- `XorWithIv` (line 510) `static void XorWithIv(uint8_t* buf, const uint8_t* Iv)` - *if defined(CBC) && (CBC == 1)*
- `AES_CBC_encrypt_buffer` (line 520) `void AES_CBC_encrypt_buffer(struct AES_ctx *ctx, uint8_t* buf, size_t length)`
- `AES_CBC_decrypt_buffer` (line 535) `void AES_CBC_decrypt_buffer(struct AES_ctx* ctx, uint8_t* buf, size_t length)`
- `AES_CTR_xcrypt_buffer` (line 558) `void AES_CTR_xcrypt_buffer(struct AES_ctx* ctx, uint8_t* buf, size_t length)` - *XorWithIv(buf, ctx->Iv); memcpy(ctx->Iv, storeNextIv, AES_BLOCKLEN); buf += AES_BLOCKLEN; } } #endif // #if defined(CBC) && (CBC == 1) #if defined(...*

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
- `ExceptionFilter` (line 253) `static LONG WINAPI ExceptionFilter(EXCEPTION_POINTERS *ExceptionInfo)`
- `get_shell_cmd` (line 334) `const char* get_shell_cmd()`
- `__declspec` (line 416) `__declspec(dllexport) void BeaconDataParse(datap * parser, char * buffer, int size)` - *=== Beacon API: implementaciones exportables para BOFs ===*
- `__declspec` (line 422) `__declspec(dllexport) char * BeaconDataPtr(datap * parser, int size)`
- `__declspec` (line 430) `__declspec(dllexport) int BeaconDataInt(datap * parser)`
- `__declspec` (line 435) `__declspec(dllexport) short BeaconDataShort(datap * parser)`
- `__declspec` (line 440) `__declspec(dllexport) int BeaconDataLength(datap * parser)`
- `__declspec` (line 445) `__declspec(dllexport) char * BeaconDataExtract(datap * parser, int * size)`
- `__declspec` (line 455) `__declspec(dllexport) void BeaconPrintf(int type, const char * fmt, ...)`
- `__declspec` (line 503) `__declspec(dllexport) void BeaconOutput(int type, const char * data, int len)`
- `MapDllNameToModule` (line 521) `HMODULE MapDllNameToModule(char* dllName)` - *=== MAP DLL NAME TO REAL DLL ===*
- `GetSyscallNumber` (line 548) `DWORD GetSyscallNumber(PVOID func_addr)`
- `HellsGate` (line 560) `DWORD HellsGate(DWORD ssn)`
- `__attribute__` (line 565) `__attribute__((naked))
NTSTATUS HellDescent(
    DWORD64 arg1, DWORD64 arg2, DWORD64 arg3,
    DW...`
- `GetProcessIdByName` (line 581) `DWORD GetProcessIdByName(const char* processName)`
- `ExecuteTLSCallbacks` (line 600) `void ExecuteTLSCallbacks(PVOID moduleBase)` - *=== EJECUTAR TLS CALLBACKS ===*
- `MapModuleToMemory` (line 617) `PVOID MapModuleToMemory(unsigned char* fileBuffer, DWORD fileSize)` - *=== Carga un módulo en memoria ===*
- `ExecuteModule` (line 706) `BOOL ExecuteModule(PVOID moduleBase)` - *=== Ejecuta el módulo (DllMain o EntryPoint) ===*
- `LoadModuleFromURL` (line 751) `BOOL LoadModuleFromURL(const char* url)` - *=== Carga y ejecuta un módulo desde URL ===*
- `xor_string` (line 915) `void xor_string(char* data, size_t len, char key)` - *=== XOR ===*
- `anti_analysis` (line 922) `BOOL anti_analysis()` - *=== ANTI-ANALYSIS ===*
- `load_lazyconf` (line 945) `BOOL load_lazyconf()`
- `GetNtdllBase` (line 1183) `HMODULE GetNtdllBase()`
- `isVMByMAC` (line 1231) `BOOL isVMByMAC()`
- `extract_shellcode` (line 1303) `int extract_shellcode(const char* input, size_t len, unsigned char** out)` - *=== EXTRAER SHELLCODE ===*
- `hex_char_to_byte` (line 1334) `BYTE hex_char_to_byte(char c)` - *Función para convertir hex a bytes*
- `hex_to_bytes` (line 1340) `void hex_to_bytes(const char* hex, BYTE* output, size_t len)`
- `executeLoader` (line 1348) `void executeLoader(void *arg)` - *=== executeLoader ===*
- `ReverseShell` (line 1404) `void __cdecl ReverseShell(void* arg)` - *======================== FUNCIÓN DE INYECCIÓN DE SHELL ========================*
- `ReadFromProcess` (line 1513) `DWORD WINAPI ReadFromProcess(LPVOID lpParam)` - *=== Hilo para leer salida del proceso (como en el ejemplo que funciona) ===*
- `GetJitteredSleep` (line 1586) `DWORD GetJitteredSleep(DWORD base_ms)`
- `GetUsefulSoftware` (line 1591) `char* GetUsefulSoftware()`
- `base64_encode` (line 1626) `char* base64_encode(const unsigned char* data, size_t inputLen)`
- `base64_decode` (line 1662) `char* base64_decode(const char* input, size_t* out_len)`
- `discoverLocalHosts` (line 1695) `void discoverLocalHosts()`
- `initProxy` (line 1752) `void initProxy()` - *startProxy.c*
- `relay_thread` (line 1763) `void WINAPI relay_thread(void* param)` - *Función para reenviar datos entre sockets*
- `proxy_thread` (line 1784) `void WINAPI proxy_thread(void* param)` - *Tu función proxy_thread usando tus estructuras exactas*
- `proxy_accept_thread` (line 1855) `void WINAPI proxy_accept_thread(void* param)` - *Thread para aceptar conexiones*
- `startProxy` (line 1922) `BOOL startProxy(const char* listenAddr, const char* targetAddr)`
- `stopProxy` (line 2009) `BOOL stopProxy(const char* listenAddr)`
- `cleanupProxy` (line 2061) `void cleanupProxy()`
- `compressDirectory` (line 2094) `BOOL compressDirectory(const char* dirPath)` - *Función simplificada para compresión de directorios*
- `getNetworkConfig` (line 2104) `char* getNetworkConfig()` - *Para netconfig*
- `UploadFileToC2` (line 2107) `BOOL UploadFileToC2(const char* url, const char* filePath)`
- `handleUpload` (line 2280) `BOOL handleUpload(const char* command)` - *=== handleUpload: envía del beacon al C2 ===*
- `FileExistsA` (line 2301) `BOOL FileExistsA(const char* filePath)` - *Función para verificar si un archivo existe*
- `selfDestruct` (line 2306) `void selfDestruct()` - *selfdestruct.c*
- `stristr` (line 2361) `char* stristr(const char* str, const char* pattern)`
- `isSensitiveFile` (line 2378) `int isSensitiveFile(const char* filename)`
- `searchCredentials` (line 2424) `char* searchCredentials(const char* basePath)`
- `UTF8ToWide` (line 2551) `WCHAR* UTF8ToWide(const char* utf8)` - *Convierte UTF-8 a wide string*
- `obfuscateFileTimestamp` (line 2562) `BOOL obfuscateFileTimestamp(const char* filepath)` - *Ofusca los timestamps de un archivo*
- `obfuscateFileTimestamps` (line 2592) `void obfuscateFileTimestamps(const char* basePath, int depth)` - *Recorre directorios buscando archivos sensibles*
- `simulateLegitimateTraffic` (line 2656) `void simulateLegitimateTraffic(void* param)` - *traffic.c*
- `restartClient` (line 2734) `void restartClient()`
- `checkDebuggers` (line 2776) `BOOL checkDebuggers()`
- `MapPEToMemory` (line 2837) `unsigned char* MapPEToMemory(unsigned char* rawPE, DWORD rawSize, DWORD* mappedSize)`
- `downloadAndExecute` (line 2860) `BOOL downloadAndExecute(const char* url, const char* targetProcess)`
- `DecryptPacket` (line 2910) `BOOL DecryptPacket(BYTE* buffer, DWORD* buffer_len)`
- `GetIPs` (line 3006) `char* GetIPs()`
- `GetHostname` (line 3039) `char* GetHostname()`
- `GetUsername` (line 3056) `char* GetUsername()`
- `patchAMSI` (line 3072) `BOOL patchAMSI(void)`
- `get_nt_headers` (line 3092) `PIMAGE_NT_HEADERS get_nt_headers(BYTE* buffer)` - *==================================================================== PE HELPERS (usando winnt.h) ==================================================...*
- `is_64bit` (line 3100) `BOOL is_64bit(BYTE* buffer)`
- `get_image_size` (line 3106) `DWORD get_image_size(BYTE* buffer)`
- `get_entry_point_rva` (line 3112) `DWORD get_entry_point_rva(BYTE* buffer)`
- `pe_buffer_to_virtual_image` (line 3117) `BYTE* pe_buffer_to_virtual_image(BYTE* raw_buffer, DWORD* out_size)`
- `create_suspended_process` (line 3148) `BOOL create_suspended_process(char* path, PROCESS_INFORMATION* pi)` - *==================================================================== PROCESS MANIPULATION =========================================================...*
- `get_remote_image_base` (line 3154) `ULONGLONG get_remote_image_base(PROCESS_INFORMATION* pi, BOOL is_32bit_target)`
- `update_remote_entry_point` (line 3249) `BOOL update_remote_entry_point(PROCESS_INFORMATION* pi, ULONGLONG entry_point_va, BOOL is_32bit)`
- `overWrite` (line 3277) `void overWrite(const char* targetPath, const char* payloadPath)` - *==================================================================== MAIN FUNCTION: overWrite =====================================================...*
- `cleanSystemLogs` (line 3384) `void cleanSystemLogs()` - *Limpia el historial de comandos de la consola actual*
- `ensurePersistence` (line 3421) `BOOL ensurePersistence()` - *ensurePersistence.c*
- `isSandboxEnvironment` (line 3482) `BOOL isSandboxEnvironment()` - *isSandboxEnvironment.c*
- `tryPrivilegeEscalation` (line 3551) `void tryPrivilegeEscalation()`
- `executeUACBypass` (line 3556) `BOOL executeUACBypass(const char* payloadPath)`
- `scanPort` (line 3610) `void scanPort(void* arg)`
- `PortScanner` (line 3661) `void PortScanner(char* targetIP, int* ports, int numPorts)` - *PortScanner.c*
- `PortScannerWrapper` (line 3705) `void PortScannerWrapper(void* arg)`
- `EarlyBirdInject` (line 3729) `BOOL EarlyBirdInject(unsigned char* shellcode, int shellcode_len)` - *=== INYECCIÓN EARLY BIRD + SYSCALL ===*
- `init_aes_context` (line 3898) `PacketEncryptionContext* init_aes_context(const char* key_hex)`
- `retry_http_request` (line 3918) `char* retry_http_request(const char* url, const char* method, const char* data, int max_retries)` - *retry_http_request.c*
- `exec_cmd` (line 4172) `char* exec_cmd(const char* cmd)` - *exec_cmd.c*
- `GetC2Command` (line 4200) `char* GetC2Command(const char* host, const char* path)` - *c2.c (reemplaza la función actual)*
- `DownloadToBuffer` (line 4346) `unsigned char* DownloadToBuffer(const char* url, DWORD* fileSize)`
- `DownloadFromURL` (line 4422) `BOOL DownloadFromURL(const char* url, const char* filepath)`
- `encrypt_data` (line 4452) `char* encrypt_data(const char* data)`
- `isValidUUID` (line 4511) `BOOL isValidUUID(const char* uuid)`
- `deleteFilesDelay` (line 4536) `void deleteFilesDelay(void* arg)`
- `executeCommand` (line 4550) `void executeCommand(void* cmdPtr)`
- `handleAtomic` (line 4559) `void handleAtomic(char* command)`
- `handleDownload` (line 4683) `BOOL handleDownload(const char* command)` - *=== handleDownload: descarga del C2 al beacon ===*
- `SerializeBeaconString` (line 4702) `void SerializeBeaconString(char* buffer, int* offset, const char* str)`
- `BeaconDataSerializeString` (line 4711) `void BeaconDataSerializeString(char* buffer, int* offset, const char* str)`
- `go` (line 4719) `void go(unsigned char * bof_data, int bof_size, char * args, int args_len)`
- `handleAdversary` (line 4738) `void handleAdversary(char* command)` - *Función principal de manejo de comandos*
- `main` (line 5233) `int main()` - *main.c*

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
- `_PROCESS_BASIC_INFORMATION` (line 129)
- `_UNICODE_STRING` (line 262) - *=== ESTRUCTURAS NECESARIAS (MinGW-safe) ===*
- `_LDR_DATA_TABLE_ENTRY` (line 268)
- `_PEB_LDR_DATA` (line 278)
- `_PEB` (line 287)

#### `calc.c`
**Path:** `bof/calc/calc.c`

**Functions:**
- `go` (line 34) `void go(char *args, int alen)` - *================================ FUNCIÓN PRINCIPAL ================================*

#### `etw.c`
**Path:** `bof/etw/etw.c`

**Functions:**
- `go` (line 26) `void go(char *a,int l)`

#### `Test.c`
**Path:** `bof/test/Test.c`

**Functions:**
- `go` (line 2) `void go(char *args, int alen)` - *include "beacon.h"*

#### `amsibypass.c`
**Path:** `bof/test/amsibypass.c`

**Functions:**
- `go` (line 34) `void go(char *args, int alen)` - *================================ FUNCIÓN PRINCIPAL ================================*

#### `cmdwhoami.c`
**Path:** `bof/test/cmdwhoami.c`

**Functions:**
- `go` (line 42) `void go(char *args, int alen)`

#### `disablelog.c`
**Path:** `bof/test/disablelog.c`

**Functions:**
- `my_wcscmp` (line 36) `static int my_wcscmp(const wchar_t *s1, const wchar_t *s2)` - *ifndef NT_SUCCESS define NT_SUCCESS(x) ((x) >= 0) endif*
- `go` (line 68) `void go(char *args, int alen)`

**Macros:**
- `WIN32_LEAN_AND_MEAN` (line 20)
- `NT_SUCCESS` (line 34)

#### `getenv.c`
**Path:** `bof/test/getenv.c`

**Functions:**
- `go` (line 24) `void go(char *args, int alen)`

#### `loadvnc.c`
**Path:** `bof/test/loadvnc.c`

**Functions:**
- `execute_cmd_hidden` (line 51) `void execute_cmd_hidden(char* cmd)` - *================================ FUNCIÓN AUX: EJECUTAR COMANDO OCULTO ================================*
- `go` (line 81) `void go(char *args, int alen)` - *================================ FUNCIÓN PRINCIPAL ================================*

**Macros:**
- `TH32CS_SNAPPROCESS` (line 33)

**Structs:**
- `_PROCESSENTRY32` (line 35)

#### `make_table.c`
**Path:** `bof/test/make_table.c`

**Functions:**
- `Copyright` (line 16) `Copyright (c) LazyOwn RedTeam 2025. All rights reserved.
*/

#include <stdint.h>
#include <stdio....`
- `main` (line 33) `void main()`

#### `persist.c`
**Path:** `bof/test/persist.c`

**Functions:**
- `go` (line 26) `void go(char *args, int alen)`

#### `persistsvc.c`
**Path:** `bof/test/persistsvc.c`

**Functions:**
- `my_memcpy` (line 33) `static void* my_memcpy(void* dst, const void* src, size_t len)` - *================================ FUNCIONES AUXILIARES ================================*
- `my_strlen` (line 39) `static int my_strlen(const char* str)`
- `my_strcat` (line 46) `static char* my_strcat(char* dest, const char* src)`
- `my_strcmp` (line 54) `static int my_strcmp(const char* s1, const char* s2)`
- `ServiceHandler` (line 82) `DWORD WINAPI ServiceHandler(DWORD dwControl, DWORD dwEventType, LPVOID lpEventData, LPVOID lpCont...` - *================================ MANEJADOR DE CONTROL DEL SERVICIO ================================*
- `ServiceMain` (line 116) `VOID WINAPI ServiceMain(DWORD dwArgc, LPSTR *lpszArgv)` - *================================ FUNCIÓN PRINCIPAL DEL SERVICIO ================================*
- `go` (line 251) `void go(char *args, int alen)` - *================================ FUNCIÓN PRINCIPAL DEL BOF ================================*

**Macros:**
- `WIN32_LEAN_AND_MEAN` (line 19)
- `RESOLVE_API` (line 65)
- `cleanup` (line 131)
- `cleanup` (line 183)

#### `scan_shellcode.c`
**Path:** `bof/test/scan_shellcode.c`

**Functions:**
- `go` (line 84) `void go(char *args, int alen)`

**Macros:**
- `WIN32_LEAN_AND_MEAN` (line 19)

#### `shellcode.c`
**Path:** `bof/test/shellcode.c`

**Functions:**
- `go` (line 25) `void go(char *args, int alen)`

#### `sock5.c`
**Path:** `bof/test/sock5.c`

**Functions:**
- `my_FD_ISSET` (line 107) `static int my_FD_ISSET(SOCKET s, fd_set *set)` - *typedef int       (WINAPI *LISTEN)(SOCKET, int); typedef SOCKET    (WINAPI *ACCEPT)(SOCKET, struct sockaddr*, int*); typedef int       (WINAPI *CON...*
- `HandleSocks5Connection` (line 118) `static void HandleSocks5Connection(SOCKET client_sock,
    CONNECT pConnect, RECV pRecv, SEND pSe...` - *typedef USHORT    (WINAPI *NTOHS)(USHORT); /* ===== AUXILIARES ===== static int my_FD_ISSET(SOCKET s, fd_set *set) { if (!set) return 0; for (u_int...*
- `ProxyThread` (line 261) `DWORD WINAPI ProxyThread(LPVOID _)` - *break; } if (pSend(client_sock, buf, n, 0) != n) { BeaconPrintf(CALLBACK_ERROR, "[SOCKS5] Falló al reenviar al cliente\n"); break; } BeaconPrintf(C...*
- `go` (line 358) `void go(char *args, int alen)` - *cleanup_srv: pCloseSocket(srv); cleanup_wsa: pWSACleanup(); cleanup_event: if (g_hShutdownEvent) { ((BOOL (WINAPI*)(HANDLE))__imp_CloseHandle)(g_hS...*

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
- `WSAData` (line 16) - *pragma pack(push,1)*
- `fd_set` (line 27)
- `timeval` (line 32)
- `in_addr` (line 47)
- `sockaddr_in` (line 49)
- `sockaddr` (line 56)
- `hostent` (line 58)

#### `uacbypass.c`
**Path:** `bof/test/uacbypass.c`

**Functions:**
- `execute_hidden_cmd` (line 33) `void execute_hidden_cmd(char* cmd)` - *================================ FUNCIÓN AUX: EJECUTAR COMANDO OCULTO ================================*
- `go` (line 61) `void go(char *args, int alen)` - *================================ FUNCIÓN PRINCIPAL ================================*

#### `upload.c`
**Path:** `bof/test/upload.c`

**Functions:**
- `my_strlen` (line 53) `static int my_strlen(const char *s)` - *================================ FUNCIONES AUXILIARES ================================*
- `my_memcpy` (line 58) `static void* my_memcpy(void* dst, const void* src, size_t len)`
- `my_memset` (line 65) `static void* my_memset(void* dst, int val, size_t len)`
- `my_contains_dotdot` (line 71) `static BOOL my_contains_dotdot(const char* path)`
- `my_strchr` (line 80) `static char* my_strchr(const char *s, int c)`
- `xtime` (line 93) `static uint8_t xtime(uint8_t x)` - *================================ AES (sin datos globales) ================================*
- `AddRoundKey` (line 98) `static void AddRoundKey(uint8_t round, state_t* state, const uint8_t* RoundKey)`
- `SubBytes` (line 105) `static void SubBytes(state_t* state, const uint8_t* sbox)`
- `ShiftRows` (line 112) `static void ShiftRows(state_t* state)`
- `MixColumns` (line 120) `static void MixColumns(state_t* state)`
- `Cipher` (line 132) `static void Cipher(state_t* state, const uint8_t* RoundKey, const uint8_t* sbox)`
- `KeyExpansion` (line 145) `static void KeyExpansion(uint8_t* RoundKey, const uint8_t* Key, const uint8_t* sbox, const uint8_...`
- `AES_init_ctx` (line 173) `void AES_init_ctx(AES_ctx* ctx, const uint8_t* key, const uint8_t* sbox, const uint8_t* Rcon)`
- `AES_CFB_encrypt_buffer` (line 177) `void AES_CFB_encrypt_buffer(AES_ctx* ctx, uint8_t* iv, uint8_t* buf, uint32_t length, const uint8...`
- `my_base64_encode` (line 205) `static char* my_base64_encode(const uint8_t* data, uint32_t len,
    LPVOID (WINAPI *pVirtualAllo...` - *================================ BASE64 ================================*
- `ParseUploadArgs` (line 230) `static void ParseUploadArgs(const char* args, int alen,
                            char* local_p...`
- `go` (line 273) `void go(char *args, int alen)` - *================================ FUNCIÓN PRINCIPAL ================================*

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
- `my_FD_ISSET` (line 62) `int my_FD_ISSET(SOCKET sock, fd_set *set)` - *================================ FD_ISSET MANUAL ================================*
- `relay_traffic` (line 75) `void relay_traffic(SOCKET client_sock, SOCKET vnc_sock)` - *================================ RELAY TRAFFIC ================================*
- `go` (line 132) `void go(char *args, int alen)` - *================================ FUNCIÓN PRINCIPAL — ¡CORREGIDO! ================================*

#### `winver.c`
**Path:** `bof/test/winver.c`

**Functions:**
- `go` (line 24) `void go(char *args, int alen)`

#### `whoami.c`
**Path:** `bof/whoami/whoami.c`

**Functions:**
- `go` (line 34) `void go(char *args, int alen)` - *================================ FUNCIÓN PRINCIPAL ================================*

#### `cJSON.c`
**Path:** `cJSON.c`

**Functions:**
- `CJSON_PUBLIC` (line 94) `CJSON_PUBLIC(const char *) cJSON_GetErrorPtr(void)`
- `CJSON_PUBLIC` (line 99) `CJSON_PUBLIC(char *) cJSON_GetStringValue(const cJSON * const item)`
- `CJSON_PUBLIC` (line 109) `CJSON_PUBLIC(double) cJSON_GetNumberValue(const cJSON * const item)`
- `CJSON_PUBLIC` (line 124) `CJSON_PUBLIC(const char*) cJSON_Version(void)` - *CJSON_PUBLIC(double) cJSON_GetNumberValue(const cJSON * const item) { if (!cJSON_IsNumber(item)) { return (double) NAN; } return item->valuedouble;...*
- `case_insensitive_strcmp` (line 134) `static int case_insensitive_strcmp(const unsigned char *string1, const unsigned char *string2)` - */* This is a safeguard to prevent copy-pasters from using incompatible C and header files #if (CJSON_VERSION_MAJOR != 1) || (CJSON_VERSION_MINOR !=...*
- `internal_malloc` (line 166) `static void * CJSON_CDECL internal_malloc(size_t size)` - *} return tolower(*string1) - tolower(*string2); } typedef struct internal_hooks { void *(CJSON_CDECL *allocate)(size_t size); void (CJSON_CDECL *de...*
- `internal_free` (line 170) `static void CJSON_CDECL internal_free(void *pointer)`
- `internal_realloc` (line 174) `static void * CJSON_CDECL internal_realloc(void *pointer, size_t size)`
- `cJSON_strdup` (line 188) `static unsigned char* cJSON_strdup(const unsigned char* string, const internal_hooks * const hooks)`
- `CJSON_PUBLIC` (line 209) `CJSON_PUBLIC(void) cJSON_InitHooks(cJSON_Hooks* hooks)`
- `cJSON_New_Item` (line 242) `static cJSON *cJSON_New_Item(const internal_hooks * const hooks)` - *if (hooks->free_fn != NULL) { global_hooks.deallocate = hooks->free_fn; } /* use realloc only if both free and malloc are used global_hooks.realloc...*
- `get_decimal_point` (line 281) `static unsigned char get_decimal_point(void)` - *item->valuestring = NULL; } if (!(item->type & cJSON_StringIsConst) && (item->string != NULL)) { global_hooks.deallocate(item->string); item->strin...*
- `parse_number` (line 309) `static cJSON_bool parse_number(cJSON * const item, parse_buffer * const input_buffer)` - *size_t offset; size_t depth; /* How deeply nested (in arrays/objects) is the input at the current offset. internal_hooks hooks; } parse_buffer; /* ...*
- `ensure` (line 494) `static unsigned char* ensure(printbuffer * const p, size_t needed)` - *} typedef struct { unsigned char *buffer; size_t length; size_t offset; size_t depth; /* current nesting depth (for formatted printing) cJSON_bool ...*
- `update_offset` (line 579) `static void update_offset(printbuffer * const buffer)` - *p->buffer = NULL; return NULL; } memcpy(newbuffer, p->buffer, p->offset + 1); p->hooks.deallocate(p->buffer); } p->length = newsize; p->buffer = ne...*
- `compare_double` (line 592) `static cJSON_bool compare_double(double a, double b)` - */* calculate the new length of the string in a printbuffer and update the offset static void update_offset(printbuffer * const buffer) { const unsi...*
- `print_number` (line 599) `static cJSON_bool print_number(const cJSON * const item, printbuffer * const output_buffer)` - *} buffer_pointer = buffer->buffer + buffer->offset; buffer->offset += strlen((const char*)buffer_pointer); } /* securely comparison of floating-poi...*
- `parse_hex4` (line 669) `static unsigned parse_hex4(const unsigned char * const input)` - *output_pointer[i] = '.'; continue; } output_pointer[i] = number_buffer[i]; } output_pointer[i] = '\0'; output_buffer->offset += (size_t)length; ret...*
- `utf16_literal_to_utf8` (line 706) `static unsigned char utf16_literal_to_utf8(const unsigned char * const input_pointer, const unsig...` - *converts a UTF-16 literal to UTF-8 * A literal can be one or two sequences of the form \uXXXX*
- `parse_string` (line 827) `static cJSON_bool parse_string(cJSON * const item, parse_buffer * const input_buffer)` - *else { (*output_pointer)[0] = (unsigned char)(codepoint & 0x7F); } output_pointer += utf8_length; return sequence_length; fail: return 0; } /* Pars...*
- `print_string_ptr` (line 957) `static cJSON_bool print_string_ptr(const unsigned char * const input, printbuffer * const output_...` - *{ input_buffer->hooks.deallocate(output); output = NULL; } if (input_pointer != NULL) { input_buffer->offset = (size_t)(input_pointer - input_buffe...*
- `print_string` (line 1079) `static cJSON_bool print_string(const cJSON * const item, printbuffer * const p)` - */* escape and print as unicode codepoint sprintf((char*)output_pointer, "u%04x", *input_pointer); output_pointer += 4; break; } } } output[output_l...*
- `buffer_skip_whitespace` (line 1093) `static parse_buffer *buffer_skip_whitespace(parse_buffer * const buffer)` - *static cJSON_bool print_string(const cJSON * const item, printbuffer * const p) { return print_string_ptr((unsigned char*)item->valuestring, p); } ...*
- `skip_utf8_bom` (line 1119) `static parse_buffer *skip_utf8_bom(parse_buffer * const buffer)` - *while (can_access_at_index(buffer, 0) && (buffer_at_offset(buffer)[0] <= 32)) { buffer->offset++; } if (buffer->offset == buffer->length) { buffer-...*
- `CJSON_PUBLIC` (line 1133) `CJSON_PUBLIC(cJSON *) cJSON_ParseWithOpts(const char *value, const char **return_parse_end, cJSON...`
- `CJSON_PUBLIC` (line 1235) `CJSON_PUBLIC(cJSON *) cJSON_ParseWithLength(const char *value, size_t buffer_length)`
- `print` (line 1242) `static unsigned char *print(const cJSON * const item, cJSON_bool format, const internal_hooks * c...` - *define cjson_min(a, b) (((a) < (b)) ? (a) : (b))*
- `CJSON_PUBLIC` (line 1315) `CJSON_PUBLIC(char *) cJSON_PrintUnformatted(const cJSON *item)`
- `CJSON_PUBLIC` (line 1320) `CJSON_PUBLIC(char *) cJSON_PrintBuffered(const cJSON *item, int prebuffer, cJSON_bool fmt)`
- `CJSON_PUBLIC` (line 1351) `CJSON_PUBLIC(cJSON_bool) cJSON_PrintPreallocated(cJSON *item, char *buffer, const int length, con...`
- `parse_value` (line 1372) `static cJSON_bool parse_value(cJSON * const item, parse_buffer * const input_buffer)` - *return false; } p.buffer = (unsigned char*)buffer; p.length = (size_t)length; p.offset = 0; p.noalloc = true; p.format = format; p.hooks = global_h...*
- `print_value` (line 1427) `static cJSON_bool print_value(const cJSON * const item, printbuffer * const output_buffer)` - *if (can_access_at_index(input_buffer, 0) && (buffer_at_offset(input_buffer)[0] == '[')) { return parse_array(item, input_buffer); } /* object if (c...*
- `parse_array` (line 1501) `static cJSON_bool parse_array(cJSON * const item, parse_buffer * const input_buffer)` - *return print_string(item, output_buffer); case cJSON_Array: return print_array(item, output_buffer); case cJSON_Object: return print_object(item, o...*
- `print_array` (line 1599) `static cJSON_bool print_array(const cJSON * const item, printbuffer * const output_buffer)` - *input_buffer->offset++; return true; fail: if (head != NULL) { cJSON_Delete(head); } return false; } /* Render an array to text*
- `parse_object` (line 1661) `static cJSON_bool parse_object(cJSON * const item, parse_buffer * const input_buffer)` - *output_pointer = ensure(output_buffer, 2); if (output_pointer == NULL) { return false; } output_pointer++ = ']'; output_pointer = '\0'; output_buff...*
- `print_object` (line 1780) `static cJSON_bool print_object(const cJSON * const item, printbuffer * const output_buffer)` - *input_buffer->offset++; return true; fail: if (head != NULL) { cJSON_Delete(head); } return false; } /* Render an object to text.*
- `get_array_item` (line 1915) `static cJSON* get_array_item(const cJSON *array, size_t index)`
- `CJSON_PUBLIC` (line 1934) `CJSON_PUBLIC(cJSON *) cJSON_GetArrayItem(const cJSON *array, int index)`
- `get_object_item` (line 1944) `static cJSON *get_object_item(const cJSON * const object, const char * const name, const cJSON_bo...`
- `CJSON_PUBLIC` (line 1976) `CJSON_PUBLIC(cJSON *) cJSON_GetObjectItem(const cJSON * const object, const char * const string)`
- `CJSON_PUBLIC` (line 1981) `CJSON_PUBLIC(cJSON *) cJSON_GetObjectItemCaseSensitive(const cJSON * const object, const char * c...`
- `CJSON_PUBLIC` (line 1986) `CJSON_PUBLIC(cJSON_bool) cJSON_HasObjectItem(const cJSON *object, const char *string)`
- `suffix_object` (line 1993) `static void suffix_object(cJSON *prev, cJSON *item)` - *return get_object_item(object, string, false); } CJSON_PUBLIC(cJSON *) cJSON_GetObjectItemCaseSensitive(const cJSON * const object, const char * co...*
- `create_reference` (line 2000) `static cJSON *create_reference(const cJSON *item, const internal_hooks * const hooks)` - *CJSON_PUBLIC(cJSON_bool) cJSON_HasObjectItem(const cJSON *object, const char *string) { return cJSON_GetObjectItem(object, string) ? 1 : 0; } /* Ut...*
- `add_item_to_array` (line 2020) `static cJSON_bool add_item_to_array(cJSON *array, cJSON *item)`
- `cast_away_const` (line 2066) `static void* cast_away_const(const void* string)` - */* Add item to array/object. CJSON_PUBLIC(cJSON_bool) cJSON_AddItemToArray(cJSON *array, cJSON *item) { return add_item_to_array(array, item); } #i...*
- `add_item_to_object` (line 2073) `static cJSON_bool add_item_to_object(cJSON * const object, const char * const string, cJSON * con...` - *if defined(__clang__) || (defined(__GNUC__) && ((__GNUC__ > 4) || ((__GNUC__ == 4) && (__GNUC__-MINOR__ > 5)))) pragma GCC diagnostic pop endif*
- `CJSON_PUBLIC` (line 2111) `CJSON_PUBLIC(cJSON_bool) cJSON_AddItemToObject(cJSON *object, const char *string, cJSON *item)`
- `CJSON_PUBLIC` (line 2122) `CJSON_PUBLIC(cJSON_bool) cJSON_AddItemReferenceToArray(cJSON *array, cJSON *item)`
- `CJSON_PUBLIC` (line 2132) `CJSON_PUBLIC(cJSON_bool) cJSON_AddItemReferenceToObject(cJSON *object, const char *string, cJSON ...`
- `CJSON_PUBLIC` (line 2142) `CJSON_PUBLIC(cJSON*) cJSON_AddNullToObject(cJSON * const object, const char * const name)`
- `CJSON_PUBLIC` (line 2154) `CJSON_PUBLIC(cJSON*) cJSON_AddTrueToObject(cJSON * const object, const char * const name)`
- `CJSON_PUBLIC` (line 2166) `CJSON_PUBLIC(cJSON*) cJSON_AddFalseToObject(cJSON * const object, const char * const name)`
- `CJSON_PUBLIC` (line 2178) `CJSON_PUBLIC(cJSON*) cJSON_AddBoolToObject(cJSON * const object, const char * const name, const c...`
- `CJSON_PUBLIC` (line 2190) `CJSON_PUBLIC(cJSON*) cJSON_AddNumberToObject(cJSON * const object, const char * const name, const...`
- `CJSON_PUBLIC` (line 2202) `CJSON_PUBLIC(cJSON*) cJSON_AddStringToObject(cJSON * const object, const char * const name, const...`
- `CJSON_PUBLIC` (line 2214) `CJSON_PUBLIC(cJSON*) cJSON_AddRawToObject(cJSON * const object, const char * const name, const ch...`
- `CJSON_PUBLIC` (line 2226) `CJSON_PUBLIC(cJSON*) cJSON_AddObjectToObject(cJSON * const object, const char * const name)`
- `CJSON_PUBLIC` (line 2238) `CJSON_PUBLIC(cJSON*) cJSON_AddArrayToObject(cJSON * const object, const char * const name)`
- `CJSON_PUBLIC` (line 2250) `CJSON_PUBLIC(cJSON *) cJSON_DetachItemViaPointer(cJSON *parent, cJSON * const item)`
- `CJSON_PUBLIC` (line 2286) `CJSON_PUBLIC(cJSON *) cJSON_DetachItemFromArray(cJSON *array, int which)`
- `CJSON_PUBLIC` (line 2296) `CJSON_PUBLIC(void) cJSON_DeleteItemFromArray(cJSON *array, int which)`
- `CJSON_PUBLIC` (line 2301) `CJSON_PUBLIC(cJSON *) cJSON_DetachItemFromObject(cJSON *object, const char *string)`
- `CJSON_PUBLIC` (line 2308) `CJSON_PUBLIC(cJSON *) cJSON_DetachItemFromObjectCaseSensitive(cJSON *object, const char *string)`
- `CJSON_PUBLIC` (line 2315) `CJSON_PUBLIC(void) cJSON_DeleteItemFromObject(cJSON *object, const char *string)`
- `CJSON_PUBLIC` (line 2320) `CJSON_PUBLIC(void) cJSON_DeleteItemFromObjectCaseSensitive(cJSON *object, const char *string)`
- `CJSON_PUBLIC` (line 2362) `CJSON_PUBLIC(cJSON_bool) cJSON_ReplaceItemViaPointer(cJSON * const parent, cJSON * const item, cJ...`
- `CJSON_PUBLIC` (line 2412) `CJSON_PUBLIC(cJSON_bool) cJSON_ReplaceItemInArray(cJSON *array, int which, cJSON *newitem)`
- `replace_item_in_object` (line 2422) `static cJSON_bool replace_item_in_object(cJSON *object, const char *string, cJSON *replacement, c...`
- `CJSON_PUBLIC` (line 2445) `CJSON_PUBLIC(cJSON_bool) cJSON_ReplaceItemInObject(cJSON *object, const char *string, cJSON *newi...`
- `CJSON_PUBLIC` (line 2450) `CJSON_PUBLIC(cJSON_bool) cJSON_ReplaceItemInObjectCaseSensitive(cJSON *object, const char *string...`
- `CJSON_PUBLIC` (line 2467) `CJSON_PUBLIC(cJSON *) cJSON_CreateTrue(void)`
- `CJSON_PUBLIC` (line 2478) `CJSON_PUBLIC(cJSON *) cJSON_CreateFalse(void)`
- `CJSON_PUBLIC` (line 2489) `CJSON_PUBLIC(cJSON *) cJSON_CreateBool(cJSON_bool boolean)`
- `CJSON_PUBLIC` (line 2500) `CJSON_PUBLIC(cJSON *) cJSON_CreateNumber(double num)`
- `CJSON_PUBLIC` (line 2525) `CJSON_PUBLIC(cJSON *) cJSON_CreateString(const char *string)`
- `CJSON_PUBLIC` (line 2542) `CJSON_PUBLIC(cJSON *) cJSON_CreateStringReference(const char *string)`
- `CJSON_PUBLIC` (line 2554) `CJSON_PUBLIC(cJSON *) cJSON_CreateObjectReference(const cJSON *child)`
- `CJSON_PUBLIC` (line 2566) `CJSON_PUBLIC(cJSON *) cJSON_CreateArrayReference(const cJSON *child)`
- `CJSON_PUBLIC` (line 2578) `CJSON_PUBLIC(cJSON *) cJSON_CreateRaw(const char *raw)`
- `CJSON_PUBLIC` (line 2595) `CJSON_PUBLIC(cJSON *) cJSON_CreateArray(void)`
- `CJSON_PUBLIC` (line 2606) `CJSON_PUBLIC(cJSON *) cJSON_CreateObject(void)`
- `CJSON_PUBLIC` (line 2658) `CJSON_PUBLIC(cJSON *) cJSON_CreateFloatArray(const float *numbers, int count)`
- `CJSON_PUBLIC` (line 2698) `CJSON_PUBLIC(cJSON *) cJSON_CreateDoubleArray(const double *numbers, int count)`
- `CJSON_PUBLIC` (line 2738) `CJSON_PUBLIC(cJSON *) cJSON_CreateStringArray(const char *const *strings, int count)`
- `cJSON_Duplicate_rec` (line 2785) `cJSON * cJSON_Duplicate_rec(const cJSON *item, size_t depth, cJSON_bool recurse)`
- `skip_oneline_comment` (line 2872) `static void skip_oneline_comment(char **input)`
- `skip_multiline_comment` (line 2885) `static void skip_multiline_comment(char **input)`
- `minify_string` (line 2899) `static void minify_string(char **input, char **output)`
- `CJSON_PUBLIC` (line 2921) `CJSON_PUBLIC(void) cJSON_Minify(char *json)`
- `CJSON_PUBLIC` (line 2971) `CJSON_PUBLIC(cJSON_bool) cJSON_IsInvalid(const cJSON * const item)`
- `CJSON_PUBLIC` (line 2981) `CJSON_PUBLIC(cJSON_bool) cJSON_IsFalse(const cJSON * const item)`
- `CJSON_PUBLIC` (line 2991) `CJSON_PUBLIC(cJSON_bool) cJSON_IsTrue(const cJSON * const item)`
- `CJSON_PUBLIC` (line 3001) `CJSON_PUBLIC(cJSON_bool) cJSON_IsBool(const cJSON * const item)`
- `CJSON_PUBLIC` (line 3011) `CJSON_PUBLIC(cJSON_bool) cJSON_IsNull(const cJSON * const item)`
- `CJSON_PUBLIC` (line 3021) `CJSON_PUBLIC(cJSON_bool) cJSON_IsNumber(const cJSON * const item)`
- `CJSON_PUBLIC` (line 3031) `CJSON_PUBLIC(cJSON_bool) cJSON_IsString(const cJSON * const item)`
- `CJSON_PUBLIC` (line 3041) `CJSON_PUBLIC(cJSON_bool) cJSON_IsArray(const cJSON * const item)`
- `CJSON_PUBLIC` (line 3051) `CJSON_PUBLIC(cJSON_bool) cJSON_IsObject(const cJSON * const item)`
- `CJSON_PUBLIC` (line 3061) `CJSON_PUBLIC(cJSON_bool) cJSON_IsRaw(const cJSON * const item)`
- `CJSON_PUBLIC` (line 3071) `CJSON_PUBLIC(cJSON_bool) cJSON_Compare(const cJSON * const a, const cJSON * const b, const cJSON_...`
- `cJSON_ArrayForEach` (line 3157) `cJSON_ArrayForEach(a_element, a)`
- `cJSON_ArrayForEach` (line 3173) `cJSON_ArrayForEach(b_element, b)` - *doing this twice, once on a and b to prevent true comparison if a subset of b * TODO: Do this the proper way, this is just a fix for now*
- `CJSON_PUBLIC` (line 3193) `CJSON_PUBLIC(void *) cJSON_malloc(size_t size)`
- `CJSON_PUBLIC` (line 3198) `CJSON_PUBLIC(void) cJSON_free(void *object)`

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
- `AES_ctx` (line 33)

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
- `get_machine_id` (line 8) `def get_machine_id()`
- `get_version` (line 20) `def get_version()`
- `to_numbers` (line 31) `def to_numbers(hex_str)` - *Simula la función toNumbers de JavaScript*
- `to_hex` (line 35) `def to_hex(byte_list)` - *Simula la función toHex de JavaScript*
- `decrypt_cookie` (line 39) `def decrypt_cookie(encrypted, key, iv)` - *Descifra usando AES en modo CBC (como slowAES.decrypt(c,2,a,b))*
- `main` (line 45) `def main()` - *Sistema de telemetría de uso por instalación no invasiva.*

#### `generate_hashs.py`
**Path:** `generate_hashs.py`

**Functions:**
- `djb2` (line 23) `def djb2(s)`
- `generate_coff_loader` (line 223) `def generate_coff_loader()`
- `generate_bof_test` (line 491) `def generate_bof_test()`
- `main` (line 553) `def main()`

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
- `show_help` (line 34) - *=== FUNCIONES ===*
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

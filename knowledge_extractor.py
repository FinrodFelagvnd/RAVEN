import json
import openai
from config import *
import time
import os

def load_data():
    # for filename in os.listdir(RAW_DATA_PATH):
    #     file_path = os.path.join(RAW_DATA_PATH, filename)

    sub_path = 'PairVul/full-dataset/Linux_kernel_clean_data_top5_CWEs.json'
    full_path = os.path.join(RAW_DATA_PATH, sub_path)

    with open(full_path, 'r', encoding='utf-8') as f:
        data = json.load(f)
    
    processed_entries = []

    for cwe, items in data.items():
        for entry in items:
            processed_entries.append({
                "cwe": cwe,
                "cve": entry["cve_id"],
                "describe": entry.get("cve_description", ""),
                "code": entry["code_before_change"],
                # "code_after": entry["code_after_change"],
                # "patch": entry.get("patch", ""),
                "id": entry["id"]
            })

    return processed_entries

def load_clean_data():
    full_path = os.path.join(RESULT_SAVE_PATH, "clean_data.json") 
    with open(full_path, 'r', encoding='utf-8') as f:
        data = json.load(f)
    
    processed_entries = []

    for entry in data:
        processed_entries.append({
            "cwe": entry.get("cwe", []), 
            "cve": entry["cve_id"],
            "describe": entry.get("cve_description", ""),
            "code": entry["code_before_change"],
            # "code_after": entry["code_after_change"],
            # "patch": entry.get("patch", ""),
            "id": entry["id"]
        })

    return processed_entries

def gen_extract_prompt(entry):
    openai.api_key = OPENAI_API_KEY

    input_info = f"""Here is a vulnerable code snippet and related information:

    CWE Type: {entry["cwe"]}
    CVE ID: {entry["cve"]}

    Code snippet:
    '''
    {entry["code"]}
    '''

    Vulnerability Description:
    {entry["describe"]}

    The vulnerability is fixed after patching. Patch Difference:
    {entry["diff"]}
    """

    # code purpose
    purpose_prompt = f"""{input_info}\n
Please complete the following tasks step by step:
1. Carefully analyse the overall intent and core functionality of the above code snippet;
2. Please summarize the purpose of the code in one sentence, and strictly output it in the following format:
Code purpose: \"\"\"Fill in the summary here\"\"\"
"""

    # vulnerability cause
    vulnerability_prompt = f"""{input_info}\n
Please complete the following tasks step by step:
1. Carefully analyse the Functionity and logic of the above code snippet;
2. Based on the provided vulnerability information, CWE type, and CVE ID, thoroughly consider the root cause of the vulnerability;
3. Combining the provided patch difference, analyse how the vulnerability was fixed;
4. Summarize the cause of the vulnerability in one sentence, and
output it strictly in the following format:
Vulnerability cause: \"\"\"Fill in the summary here\"\"\"
"""

    # funcion relationship
    function_prompt = f"""{input_info}\n

Please complete the following tasks step by step:
1. Carefully analyse the Functionity and logic of the above code snippet;
2. Extract all Function information from the code (including: function, parameters, caller, and callees), and output it strictly in the following structured format:
1. Functions:
- Function name: xxx
- Parameters: [param1, param2, ...]
- Caller: xxx (if applicable)
- Callees: [funcA, funcB, ...]

2. ...
"""

    return purpose_prompt, vulnerability_prompt, function_prompt

def gen_message(prompt, model=MODEL_DS_CHAT):
    client = openai.OpenAI(api_key=OPENAI_API_KEY, base_url="https://api.deepseek.com") 
    try:
        response = client.chat.completions.create(
            model=model,
            messages=[
                {"role": "system", "content": DEFAULT_SYS_PROMPT},
                {"role": "user", "content": prompt}
            ],
            temperature=DEFAULT_TEMPERATURE
        )
        return response.choices[0].message.content
    except Exception as e:
        print("Error:", e)
        return None

def query_llm(entry):
    purpose_prompt, vulnerability_prompt, function_prompt = gen_extract_prompt(entry)
    purpose_message = gen_message(purpose_prompt)
    vulnerability_message = gen_message(vulnerability_prompt)
    function_message = gen_message(function_prompt)
    
    return purpose_message, vulnerability_message, function_message

def test():
    data = {
        "cve_id": "CVE-2006-3635",
        "code_before_change": "void __init\nsetup_arch (char **cmdline_p)\n{\n\tunw_init();\n\n\tia64_patch_vtop((u64) __start___vtop_patchlist, (u64) __end___vtop_patchlist);\n\n\t*cmdline_p = __va(ia64_boot_param->command_line);\n\tstrlcpy(boot_command_line, *cmdline_p, COMMAND_LINE_SIZE);\n\n\tefi_init();\n\tio_port_init();\n\n#ifdef CONFIG_IA64_GENERIC\n\t/* machvec needs to be parsed from the command line\n\t * before parse_early_param() is called to ensure\n\t * that ia64_mv is initialised before any command line\n\t * settings may cause console setup to occur\n\t */\n\tmachvec_init_from_cmdline(*cmdline_p);\n#endif\n\n\tparse_early_param();\n\n\tif (early_console_setup(*cmdline_p) == 0)\n\t\tmark_bsp_online();\n\n#ifdef CONFIG_ACPI\n\t/* Initialize the ACPI boot-time table parser */\n\tacpi_table_init();\n# ifdef CONFIG_ACPI_NUMA\n\tacpi_numa_init();\n\tper_cpu_scan_finalize((cpus_weight(early_cpu_possible_map) == 0 ?\n\t\t32 : cpus_weight(early_cpu_possible_map)), additional_cpus);\n# endif\n#else\n# ifdef CONFIG_SMP\n\tsmp_build_cpu_map();\t/* happens, e.g., with the Ski simulator */\n# endif\n#endif /* CONFIG_APCI_BOOT */\n\n\tfind_memory();\n\n\t/* process SAL system table: */\n\tia64_sal_init(__va(efi.sal_systab));\n\n#ifdef CONFIG_SMP\n\tcpu_physical_id(0) = hard_smp_processor_id();\n#endif\n\n\tcpu_init();\t/* initialize the bootstrap CPU */\n\tmmu_context_init();\t/* initialize context_id bitmap */\n\n\tcheck_sal_cache_flush();\n\n#ifdef CONFIG_ACPI\n\tacpi_boot_init();\n#endif\n\n#ifdef CONFIG_VT\n\tif (!conswitchp) {\n# if defined(CONFIG_DUMMY_CONSOLE)\n\t\tconswitchp = &dummy_con;\n# endif\n# if defined(CONFIG_VGA_CONSOLE)\n\t\t/*\n\t\t * Non-legacy systems may route legacy VGA MMIO range to system\n\t\t * memory.  vga_con probes the MMIO hole, so memory looks like\n\t\t * a VGA device to it.  The EFI memory map can tell us if it's\n\t\t * memory so we can avoid this problem.\n\t\t */\n\t\tif (efi_mem_type(0xA0000) != EFI_CONVENTIONAL_MEMORY)\n\t\t\tconswitchp = &vga_con;\n# endif\n\t}\n#endif\n\n\t/* enable IA-64 Machine Check Abort Handling unless disabled */\n\tif (!nomca)\n\t\tia64_mca_init();\n\n\tplatform_setup(cmdline_p);\n\tpaging_init();\n}",
        "code_after_change": "void __init\nsetup_arch (char **cmdline_p)\n{\n\tunw_init();\n\n\tia64_patch_vtop((u64) __start___vtop_patchlist, (u64) __end___vtop_patchlist);\n\n\t*cmdline_p = __va(ia64_boot_param->command_line);\n\tstrlcpy(boot_command_line, *cmdline_p, COMMAND_LINE_SIZE);\n\n\tefi_init();\n\tio_port_init();\n\n#ifdef CONFIG_IA64_GENERIC\n\t/* machvec needs to be parsed from the command line\n\t * before parse_early_param() is called to ensure\n\t * that ia64_mv is initialised before any command line\n\t * settings may cause console setup to occur\n\t */\n\tmachvec_init_from_cmdline(*cmdline_p);\n#endif\n\n\tparse_early_param();\n\n\tif (early_console_setup(*cmdline_p) == 0)\n\t\tmark_bsp_online();\n\n#ifdef CONFIG_ACPI\n\t/* Initialize the ACPI boot-time table parser */\n\tacpi_table_init();\n# ifdef CONFIG_ACPI_NUMA\n\tacpi_numa_init();\n\tper_cpu_scan_finalize((cpus_weight(early_cpu_possible_map) == 0 ?\n\t\t32 : cpus_weight(early_cpu_possible_map)), additional_cpus);\n# endif\n#else\n# ifdef CONFIG_SMP\n\tsmp_build_cpu_map();\t/* happens, e.g., with the Ski simulator */\n# endif\n#endif /* CONFIG_APCI_BOOT */\n\n\tfind_memory();\n\n\t/* process SAL system table: */\n\tia64_sal_init(__va(efi.sal_systab));\n\n#ifdef CONFIG_ITANIUM\n\tia64_patch_rse((u64) __start___rse_patchlist, (u64) __end___rse_patchlist);\n#else\n\t{\n\t\tu64 num_phys_stacked;\n\n\t\tif (ia64_pal_rse_info(&num_phys_stacked, 0) == 0 && num_phys_stacked > 96)\n\t\t\tia64_patch_rse((u64) __start___rse_patchlist, (u64) __end___rse_patchlist);\n\t}\n#endif\n\n#ifdef CONFIG_SMP\n\tcpu_physical_id(0) = hard_smp_processor_id();\n#endif\n\n\tcpu_init();\t/* initialize the bootstrap CPU */\n\tmmu_context_init();\t/* initialize context_id bitmap */\n\n\tcheck_sal_cache_flush();\n\n#ifdef CONFIG_ACPI\n\tacpi_boot_init();\n#endif\n\n#ifdef CONFIG_VT\n\tif (!conswitchp) {\n# if defined(CONFIG_DUMMY_CONSOLE)\n\t\tconswitchp = &dummy_con;\n# endif\n# if defined(CONFIG_VGA_CONSOLE)\n\t\t/*\n\t\t * Non-legacy systems may route legacy VGA MMIO range to system\n\t\t * memory.  vga_con probes the MMIO hole, so memory looks like\n\t\t * a VGA device to it.  The EFI memory map can tell us if it's\n\t\t * memory so we can avoid this problem.\n\t\t */\n\t\tif (efi_mem_type(0xA0000) != EFI_CONVENTIONAL_MEMORY)\n\t\t\tconswitchp = &vga_con;\n# endif\n\t}\n#endif\n\n\t/* enable IA-64 Machine Check Abort Handling unless disabled */\n\tif (!nomca)\n\t\tia64_mca_init();\n\n\tplatform_setup(cmdline_p);\n\tpaging_init();\n}",
        "patch": "--- code before\n+++ code after\n@@ -44,6 +44,17 @@\n \t/* process SAL system table: */\n \tia64_sal_init(__va(efi.sal_systab));\n \n+#ifdef CONFIG_ITANIUM\n+\tia64_patch_rse((u64) __start___rse_patchlist, (u64) __end___rse_patchlist);\n+#else\n+\t{\n+\t\tu64 num_phys_stacked;\n+\n+\t\tif (ia64_pal_rse_info(&num_phys_stacked, 0) == 0 && num_phys_stacked > 96)\n+\t\t\tia64_patch_rse((u64) __start___rse_patchlist, (u64) __end___rse_patchlist);\n+\t}\n+#endif\n+\n #ifdef CONFIG_SMP\n \tcpu_physical_id(0) = hard_smp_processor_id();\n #endif",
        "function_modified_lines": {
            "added": [
                "#ifdef CONFIG_ITANIUM",
                "\tia64_patch_rse((u64) __start___rse_patchlist, (u64) __end___rse_patchlist);",
                "#else",
                "\t{",
                "\t\tu64 num_phys_stacked;",
                "",
                "\t\tif (ia64_pal_rse_info(&num_phys_stacked, 0) == 0 && num_phys_stacked > 96)",
                "\t\t\tia64_patch_rse((u64) __start___rse_patchlist, (u64) __end___rse_patchlist);",
                "\t}",
                "#endif",
                ""
            ],
            "deleted": []
        },
        "cwe": [
            "CWE-119"
        ],
        "cve_description": "The ia64 subsystem in the Linux kernel before 2.6.26 allows local users to cause a denial of service (stack consumption and system crash) via a crafted application that leverages the mishandling of invalid Register Stack Engine (RSE) state.",
        "id": 1
    }

    entry = {
        "cwe": data["cwe"][0], 
        "cve": data["cve_id"],
        "describe": data.get("cve_description", ""),
        "code": data["code_before_change"],
        # "code_after": data["code_after_change"],
        # "patch": data.get("patch", ""),
        "id": data["id"]
    }

    purpose_prompt, vulnerability_prompt, function_prompt = gen_extract_prompt(entry)

    purpose_message = gen_message(purpose_prompt)
    vulnerability_message = gen_message(vulnerability_prompt)
    function_message = gen_message(function_prompt)

    print("\n--- Code Purpose ---")
    print(purpose_message)

    print("\n--- Vulnerability Cause ---")
    print(vulnerability_message)

    print("\n--- Functions ---")
    print(function_message)

def main():
    # entries = load_data()
    entries = load_clean_data()  
    print(f"Loaded {len(entries)} vulnerability entries.")

    results = []
    retry_list = [] 

    start_idx = 1100

    os.makedirs(RESULT_SAVE_PATH, exist_ok=True)
    for idx, entry in enumerate(entries):
        if idx < start_idx:
            continue   

        print(f"\nProcessing {idx+1}/{len(entries)} entries: CVE ID {entry['cve']}")

        try:
            purpose_message, vulnerability_message, function_message = query_llm(entry)
            
            if purpose_message and vulnerability_message and function_message:
                results.append({
                    "id": entry["id"],
                    "cwe": entry["cwe"],
                    "cve": entry["cve"],
                    "purpose": purpose_message,
                    "vulnerability_cause": vulnerability_message,
                    "functions": function_message
                })
            else:
                print(f"Num {idx+1} is empty, skipping.")
                retry_list.append(idx)
        
        except Exception as e:
            print(f"❌ Processing entry {idx+1} failed: {e}")
            continue

        # time.sleep(1)

        if (idx + 1) % 10 == 0:
            save_path = os.path.join(RESULT_SAVE_PATH, "clean_intermediate_results.json")
            with open(save_path, 'w', encoding='utf-8') as f:
                json.dump(results, f, ensure_ascii=False, indent=2)
            print(f"Intermediate results saved to {save_path}")


    if retry_list:
        print("\nRetrying the following entries:", retry_list)
        for idx in retry_list:
            entry = entries[idx]
            try:
                purpose_message, vulnerability_message, function_message = query_llm(entry)
                if purpose_message and vulnerability_message and function_message:
                    results.append({
                        "id": entry["id"],
                        "cwe": entry["cwe"],
                        "cve": entry["cve"],
                        "purpose": purpose_message,
                        "vulnerability_cause": vulnerability_message,
                        "functions": function_message
                    })
                else:
                    print(f"Retrying entry {idx+1} is still empty, giving up.")
            except Exception as e:
                print(f"Retrying entry {idx+1} failed: {e}")

    final_save_path = os.path.join(RESULT_SAVE_PATH, "clean_extraction.json")
    with open(final_save_path, 'w', encoding='utf-8') as f:
        json.dump(results, f, ensure_ascii=False, indent=2)
    print(f"\nAll done, final results saved to {final_save_path}")

if __name__ == "__main__":
    main()
    # test()
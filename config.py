# config.py
OPENAI_API_KEY = "skxxxxxxxxxxxxxxxxxxxxxxxxx"
EMBEDDING_MODEL = "all-MiniLM-L6-v2" 
EMBEDDING_DIM = 384
FAISS_INDEX_PATH = "vector_index/faiss_index.bin"
RAW_DATA_PATH = "dataset"

RESULT_SAVE_PATH = "output"
# VECTOR_DB_SAVE_PATH = "vector_db"

DEFAULT_SYS_PROMPT = "You are an expert in vulnerability analysis.\n"   # "You are a helpful assistant."
DEFAULT_TEMPERATURE = 1.0

MODEL_DS_CHAT = "deepseek-chat"
MODEL_DS_REASON = "deepseek-reasoner"

POS_ANS = "YES"
NEG_ANS = "NO"

CWE_ID = ["CWE-119", "CWE-362", "CWE-416", "CWE-476", "CWE-787"]
CWE_DESCRIPTIONS = {
    "CWE-119": {
        "cwe_id": "CWE-119",
        "cwe_name": "Improper Restriction of Operations within the Bounds of a Memory Buffer",
        "description": "The product performs operations on a memory buffer, but it can read from or write to a memory location that is outside of the intended boundary of the buffer.",
        "extended_description": "\n            Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced. This can cause read or write operations to be performed on memory locations that may be associated with other variables, data structures, or internal program data.\n            As a result, an attacker may be able to execute arbitrary code, alter the intended control flow, read sensitive information, or cause the system to crash.\n         \n         ",
        "url": "https://cwe.mitre.org/data/definitions/119.html",
        "is_category": False
    },
    "CWE-362": {
        "cwe_id": "CWE-362",
        "cwe_name": "Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition')",
        "description": "The product contains a code sequence that can run concurrently with other code, and the code sequence requires temporary, exclusive access to a shared resource, but a timing window exists in which the shared resource can be modified by another code sequence that is operating concurrently.",
        "extended_description": "\n            This can have security implications when the expected synchronization is in security-critical code, such as recording whether a user is authenticated or modifying important state information that should not be influenced by an outsider.\n            A race condition occurs within concurrent environments, and is effectively a property of a code sequence. Depending on the context, a code sequence may be in the form of a function call, a small number of instructions, a series of program invocations, etc.\n            A race condition violates these properties, which are closely related:\n               \n                  Exclusivity - the code sequence is given exclusive access to the shared resource, i.e., no other code sequence can modify properties of the shared resource before the original sequence has completed execution.\n                  Atomicity - the code sequence is behaviorally atomic, i.e., no other thread or process can concurrently execute the same sequence of instructions (or a subset) against the same resource.\n               \n            A race condition exists when an \"interfering code sequence\" can still access the shared resource, violating exclusivity. Programmers may assume that certain code sequences execute too quickly to be affected by an interfering code sequence; when they are not, this violates atomicity. For example, the single \"x++\" statement may appear atomic at the code layer, but it is actually non-atomic at the instruction layer, since it involves a read (the original value of x), followed by a computation (x+1), followed by a write (save the result to x).\n            The interfering code sequence could be \"trusted\" or \"untrusted.\" A trusted interfering code sequence occurs within the product; it cannot be modified by the attacker, and it can only be invoked indirectly. An untrusted interfering code sequence can be authored directly by the attacker, and typically it is external to the vulnerable product.\n         \n         ",
        "url": "https://cwe.mitre.org/data/definitions/362.html",
        "is_category": False
    },
    "CWE-416": {
        "cwe_id": "CWE-416",
        "cwe_name": "Use After Free",
        "description": "Referencing memory after it has been freed can cause a program to crash, use unexpected values, or execute code.",
        "extended_description": "\n            The use of previously-freed memory can have any number of adverse consequences, ranging from the corruption of valid data to the execution of arbitrary code, depending on the instantiation and timing of the flaw. The simplest way data corruption may occur involves the system's reuse of the freed memory. Use-after-free errors have two common and sometimes overlapping causes:\n               \n                  Error conditions and other exceptional circumstances.\n                  Confusion over which part of the program is responsible for freeing the memory.\n               \n            In this scenario, the memory in question is allocated to another pointer validly at some point after it has been freed. The original pointer to the freed memory is used again and points to somewhere within the new allocation. As the data is changed, it corrupts the validly used memory; this induces undefined behavior in the process.\n            If the newly allocated data happens to hold a class, in C++ for example, various function pointers may be scattered within the heap data. If one of these function pointers is overwritten with an address to valid shellcode, execution of arbitrary code can be achieved.\n         \n         ",
        "url": "https://cwe.mitre.org/data/definitions/416.html",
        "is_category": False
    },
    "CWE-476": {
        "cwe_id": "CWE-476",
        "cwe_name": "NULL Pointer Dereference",
        "description": "A NULL pointer dereference occurs when the application dereferences a pointer that it expects to be valid, but is NULL, typically causing a crash or exit.",
        "extended_description": "NULL pointer dereference issues can occur through a number of flaws, including race conditions, and simple programming omissions.\n         ",
        "url": "https://cwe.mitre.org/data/definitions/476.html",
        "is_category": False
    },
    "CWE-787": {
        "cwe_id": "CWE-787",
        "cwe_name": "Out-of-bounds Write",
        "description": "The product writes data past the end, or before the beginning, of the intended buffer.",
        "extended_description": "Typically, this can result in corruption of data, a crash, or code execution.  The product may modify an index or perform pointer arithmetic that references a memory location that is outside of the boundaries of the buffer.  A subsequent write operation then produces undefined or unexpected results.\n         ",
        "url": "https://cwe.mitre.org/data/definitions/787.html",
        "is_category": False
    }
}

# id = 1
VECTOR_MATCH_SAMPLE = {
    "id": 1,
    "cwe": "CWE-119",
    "cve": "CVE-2006-3635",
    "purpose": "Code purpose:\"\"\"Initialize the system environment of the IA-64 architecture, including hardware-related Settings such as the processor, memory, ACPI, and console, and handle startup parameters.\"\"\"",
    "vulnerability_cause": "Vulnerability cause: \"\"\"In the ia64 subsystem of the Linux kernel, improper handling of the Invalid Register Stack Engine (RSE) status enables local users to consume stack space through specially crafted applications, resulting in system crashes.\"\"\"",
    "functions": "Functions:\n1. Function: setup_arch\n- parameter: [char **cmdline_p]\n- Callar: Not shown\n- Callee: [unw_init, ia64_patch_vtop, __va, strlcpy, efi_init, io_port_init, machvec_init_from_cmdline, parse_early_param, early_console_setup, mark_bsp_online, acpi_table_init, acpi_numa_init, per_cpu_scan_finalize, cpus_weight, smp_build_cpu_map, find_memory, ia64_sal_init, hard_smp_processor_id, cpu_init, mmu_context_init, check_sal_cache_flush, acpi_boot_init, efi_mem_type, ia64_mca_init, platform_setup, paging_init]\n\n2. Function: unw_init\n- Parameter: []\n- Caller: setup_arch\n- Callee: []\n\n3. Function: ia64_patch_vtop\n- Parameter: [(u64) __start___vtop_patchlist, (u64) __end___vtop_patchlist]\n- Caller: setup_arch\n- Callee: []\n\n4. Function: __va\n- Parameter: [ia64_boot_param->command_line]\n- Caller: setup_arch\n- Callee: []\n\n5. Function: strlcpy\n- Parameter: [boot_command_line, *cmdline_p, COMMAND_LINE_SIZE]\n- Caller: setup_arch\n- Callee: []\n\n6. Function: efi_init\n- Parameter: []\n- Caller: setup_arch\n- Callee: []\n\n7. Function: io_port_init\n- Parameter: []\n- Caller: setup_arch\n- Callee: []\n\n8. Function: machvec_init_from_cmdline\n- Parameter: [*cmdline_p]\n- Caller: setup_arch\n- Callee: []\n\n9. Function: parse_early_param\n- Parameter: []\n- Caller: setup_arch\n- Callee: []\n\n10. Function: early_console_setup\n- Parameter: [*cmdline_p]\n- Caller: setup_arch\n- Callee: []\n\n11. Function: mark_bsp_online\n- Parameter: []\n- Caller: setup_arch\n- Callee: []\n\n12. Function: acpi_table_init\n- Parameter: []\n- Caller: setup_arch\n- Callee: []\n\n13. Function: acpi_numa_init\n- Parameter: []\n- Caller: setup_arch\n- Callee: []\n\n14. Function: per_cpu_scan_finalize\n- Parameter: [(cpus_weight(early_cpu_possible_map) == 0 ? 32 : cpus_weight(early_cpu_possible_map)), additional_cpus]\n- Caller: setup_arch\n- Callee: [cpus_weight]\n\n15. Function: cpus_weight\n- Parameter: [early_cpu_possible_map]\n- Caller: per_cpu_scan_finalize\n- Callee: []\n\n16. Function: smp_build_cpu_map\n- Parameter: []\n- Caller: setup_arch\n- Callee: []\n\n17. Function: find_memory\n- Parameter: []\n- Caller: setup_arch\n- Callee: []\n\n18. Function: ia64_sal_init\n- Parameter: [__va(efi.sal_systab)]\n- Caller: setup_arch\n- Callee: [__va]\n\n19. Function: hard_smp_processor_id\n- Parameter: []\n- Caller: setup_arch\n- Callee: []\n\n20. Function: cpu_init\n- Parameter: []\n- Caller: setup_arch\n- Callee: []\n\n21. Function: mmu_context_init\n- Parameter: []\n- Caller: setup_arch\n- Callee: []\n\n22. Function: check_sal_cache_flush\n- Parameter: []\n- Caller: setup_arch\n- Callee: []\n\n23. Function: acpi_boot_init\n- Parameter: []\n- Caller: setup_arch\n- Callee: []\n\n24. Function: efi_mem_type\n- Parameter: [0xA0000]\n- Caller: setup_arch\n- Callee: []\n\n25. Function: ia64_mca_init\n- Parameter: []\n- Caller: setup_arch\n- Callee: []\n\n26. Function: platform_setup\n- Parameter: [cmdline_p]\n- Caller: setup_arch\n- Callee: []\n\n27. Function: paging_init\n- Parameter: []\n- Caller: setup_arch\n- Callee: []"
}

VECTOR_MATCH_SAMPLE2 = {
    "id": 4271,
    "cwe": "CWE-416",
    "cve": "CVE-2023-5633",
    "purpose": "Code purpose:\"\"\"This code is used to resize the COTable (command table) in VMware graphics devices, including allocating new buffers, copying old data, switching buffer references, and handling possible error situations.\"\"\"",
    "vulnerability_cause": "Vulnerability cause: \"\"\"During the processing of memory objects, a post-release reuse vulnerability occurs due to improper management of reference counting\"\"\"",
    "functions": "Functions:\n1. Function: vmw_cotable_resize\n- Parameter: [struct vmw_resource *res, size_t new_size]\n- Caller: N/A \n- Callee: [vmw_cotable, MKS_STAT_TIME_DECL, MKS_STAT_TIME_PUSH, vmw_cotable_readback, vmw_bo_create, ttm_bo_reserve, ttm_bo_wait, ttm_bo_kmap, ttm_kmap_obj_virtual, ttm_bo_kunmap, vmw_bo_placement_set, ttm_bo_validate, vmw_resource_mob_detach, vmw_cotable_unscrub, vmw_resource_mob_attach, vmw_bo_unreference, dma_resv_reserve_fences, ttm_bo_unpin, MKS_STAT_TIME_POP]\n\n2. Function: vmw_cotable\n- Parameter: [struct vmw_resource *res]\n- Caller: vmw_cotable_resize\n- Callee: []\n\n3. Function: MKS_STAT_TIME_DECL\n- Parameter: [MKSSTAT_KERN_COTABLE_RESIZE]\n- Caller: vmw_cotable_resize\n- Callee: []\n\n4. Function: MKS_STAT_TIME_PUSH\n- Parameter: [MKSSTAT_KERN_COTABLE_RESIZE]\n- Caller: vmw_cotable_resize\n- Callee: []\n\n5. Function: vmw_cotable_readback\n- Parameter: [struct vmw_resource *res]\n- Caller: vmw_cotable_resize\n- Callee: []\n\n6. Function: vmw_bo_create\n- Parameter: [struct vmw_private *dev_priv, struct vmw_bo_params *bo_params, struct vmw_bo **buf]\n- Caller: vmw_cotable_resize\n- Callee: []\n\n7. Function: ttm_bo_reserve\n- Parameter: [struct ttm_buffer_object *bo, bool interruptible, bool no_wait, NULL]\n- Caller: vmw_cotable_resize\n- Callee: []\n\n8. Function: ttm_bo_wait\n- Parameter: [struct ttm_buffer_object *old_bo, false, false]\n- Caller: vmw_cotable_resize\n- Callee: []\n\n9. Function: ttm_bo_kmap\n- Parameter: [struct ttm_buffer_object *bo, size_t i, 1, struct ttm_bo_kmap_obj *map]\n- Caller: vmw_cotable_resize\n- Callee: []\n\n10. Function: ttm_kmap_obj_virtual\n- Parameter: [struct ttm_bo_kmap_obj *map, bool *dummy]\n- Caller: vmw_cotable_resize\n- Callee: []\n\n11. Function: ttm_bo_kunmap\n- Parameter: [struct ttm_bo_kmap_obj *map]\n- Caller: vmw_cotable_resize\n- Callee: []\n\n12. Function: vmw_bo_placement_set\n- Parameter: [struct vmw_bo *buf, VMW_BO_DOMAIN_MOB, VMW_BO_DOMAIN_MOB]\n- Caller: vmw_cotable_resize\n- Callee: []\n\n13. Function: ttm_bo_validate\n- Parameter: [struct ttm_buffer_object *bo, struct ttm_placement *placement, struct ttm_operation_ctx *ctx]\n- Caller: vmw_cotable_resize\n- Callee: []\n\n14. Function: vmw_resource_mob_detach\n- Parameter: [struct vmw_resource *res]\n- Caller: vmw_cotable_resize\n- Callee: []\n\n15. Function: vmw_cotable_unscrub\n- Parameter: [struct vmw_resource *res]\n- Caller: vmw_cotable_resize\n- Callee: []\n\n16. Function: vmw_resource_mob_attach\n- Parameter: [struct vmw_resource *res]\n- Caller: vmw_cotable_resize\n- Callee: []\n\n17. Function: vmw_bo_unreference\n- Parameter: [struct vmw_bo **old_buf]\n- Caller: vmw_cotable_resize\n- Callee: []\n\n18. Function: dma_resv_reserve_fences\n- Parameter: [struct dma_resv *resv, 1]\n- Caller: vmw_cotable_resize\n- Callee: []\n\n19. Function: ttm_bo_unpin\n- Parameter: [struct ttm_buffer_object *bo]\n- Caller: vmw_cotable_resize\n- Callee: []\n\n20. Function: MKS_STAT_TIME_POP\n- Parameter: [MKSSTAT_KERN_COTABLE_RESIZE]\n- Caller: vmw_cotable_resize\n- Callee: []"
}
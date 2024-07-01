#!/usr/bin/env bash
_dnx_completions()
{
  COMPREPLY=($( COMP_WORDS="${COMP_WORDS[*]}" \
                COMP_CWORD=$COMP_CWORD \
                COMP_LINE=$COMP_LINE   \
                python3 ${HOME}/dnxfirewall/dnx_cli/dnx_completions.py
            ) )
}

complete -F _dnx_completions dnx

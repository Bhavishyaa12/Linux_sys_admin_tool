#!/usr/bin/env bash
# Bash tab-completion for Linux_sys_admin.py
#
# Usage:
#   source this file (. filename) or drop it in /etc/bash_completion.d/ then run
#   ./linux_audit.py --<tab>
main(){
	Linux_sys_admin_script_completion()
	{
    	local cur prev opts file_opts

    	cur="${COMP_WORDS[COMP_CWORD]}"
    	prev="${COMP_WORDS[COMP_CWORD-1]}"

    	# Options for our script
    	opts="--file_integrity --check --list --remove --audit --users \
	--permissions --suid --processes --network --services --logs --system \
	--version --help"

    	file_opts="-f --file_integrity --remove"

    	for opt in $file_opts; do
       		if [[ "$prev" == "$opt" ]]; then
            	COMPREPLY=($(compgen -f -- "$cur"))
            	return 0
        	fi
    	done

    	if [[ "$cur" == -* ]]; then
        	COMPREPLY=($(compgen -W "$opts" -- "$cur"))
    	    return 0
	    fi
	}

	# Complete when the script is run directly (e.g. ./Linux_sys_admin.py or
	# just Linux_sys_admin.py if it's on PATH and executable) 
	# If you always run it as ./Linux_sys_admin.py --<options>)
	# The bash completion might not work.In this case uncomment the below line  
	# complete -F Linux_sys_admin_script_completion Linux_sys_admin.py

	# This is for sudo *.py --<tab>
	complete -F Linux_sys_admin_script_completion sudo
}

main

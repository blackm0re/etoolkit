# etoolkit bash-completion
# -*- shell-script -*-

_instances() {

    local instances

    if [[ -n ${2} ]]; then
        instances="$(etoolkit -c $2 -l 2> /dev/null)"
    else
        instances="$(etoolkit -l 2> /dev/null)"
    fi

    if [[ $? -eq 0 ]]; then
        COMPREPLY+=($(compgen -W "$instances" -- "$1"))
    fi

}


_etoolkit() {

    local all_params config_file c cur i no_output numwords prev spawn
    COMPREPLY=()
    cur="${COMP_WORDS[COMP_CWORD]}"
    prev="${COMP_WORDS[COMP_CWORD-1]}"
    numwords=${#COMP_WORDS[*]}
    no_output=0
    spawn=0
    all_params="-d --decrypt-value -e --encrypt-value -l --list -h --help
                -P --master-password-prompt -p --generate-master-password-hash
                -c --config-file -E --echo -m --multiple-values -q --no-output
                -r --reencrypt -s --spawn -v --version"
    # if [ ${prev:0:1} == "-" ]

    if [ ${COMP_CWORD} -eq 1 ]; then
        # first param
        COMPREPLY=($(compgen -W "$all_params" -- "$cur"))
        _instances "$cur"
        return
    else
        # param >= 2
        # handle all instance-relevant params
        for ((i = 0; i < ${numwords} + 1; i++ )); do
            c=${COMP_WORDS[${i}]}
            if [[ ${c} == "-c" || ${c} == "--config-file" ]]; then
                config_file="${COMP_WORDS[${i} + 1]}"
            elif [[ ${c} == "-s" || ${c} == "--spawn" ]]; then
                spawn=1
            elif [[ ${c} == "-q" || ${c} == "--no-output" ]]; then
                no_output=1
            fi
        done
    fi

    case $prev in
        "-c" | "--config-file")
            COMPREPLY=($(compgen -f -- "$cur"))
            return
            ;;
        "-d" | "--decrypt-value")
            COMPREPLY=($(compgen -W "-m --multiple-values -P --master-password-prompt" -- "$cur"))
            return
            ;;
        "-e" | "--encrypt-value")
            COMPREPLY=($(compgen -W "-E --echo -m --multiple-values -P --master-password-prompt" -- "$cur"))
            return
            ;;
        "-E" | "--echo")
            COMPREPLY=($(compgen -W "-e --encrypt-value -m --multiple-values -P --master-password-prompt" -- "$cur"))
            return
            ;;
        "-m" | "--multiple-values")
            COMPREPLY=($(compgen -W "-d --decrypt-value -E -e --echo --encrypt-value -P --master-password-prompt" -- "$cur"))
            return
            ;;
        "-P" | "--master-password-prompt")
            COMPREPLY=($(compgen -W "-d --decrypt-value -E -e --echo --encrypt-value -m --multiple-values" -- "$cur"))
            return
            ;;
        "-r" | "--reencrypt")
            COMPREPLY=($(compgen -W "all" -- "$cur"))
            _instances "$cur"
            return
            ;;
        "-s" | "--spawn")
            COMPREPLY=($(compgen -c -- "$cur"))
            return
            ;;
    esac

    # assume instance and handle only instance params
    if [[ -z ${config_file} ]]; then
        COMPREPLY+=($(compgen -W "-c --config-file" -- "$cur"))
    fi

    if [[ ${spawn} -ne 1 ]]; then
        COMPREPLY+=($(compgen -W "-s --spawn" -- "$cur"))
    fi

    if [[ ${no_output} -ne 1 ]]; then
        COMPREPLY+=($(compgen -W "--no-output -q" -- "$cur"))
    fi

    _instances "$cur" "$config_file"

}


complete -F _etoolkit etoolkit

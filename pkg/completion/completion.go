package completion

import (
	"fmt"
	"strings"
)

const FishScript = `# Fish completion for smartnet and smartdns
# Install: smartnet completion fish > ~/.config/fish/completions/smartnet.fish

function __smartnet_profiles
    smartnet list 2>/dev/null | string match -r '^[ ● ]*([a-zA-Z0-9_-]+)' | string replace -r '^[ ● ]*([a-zA-Z0-9_-]+).*' '$1'
end

function __smartnet_domains
    echo "cloudaicompanion.googleapis.com"
    echo "chatgpt.com"
    echo "claude.ai"
    echo "gemini.google.com"
    echo "spotify.com"
    echo "canva.com"
    echo "linkedin.com"
    echo "rutracker.org"
    echo "notion.so"
    echo "google.com"
end

set -l commands on off toggle status test list use add remove setup service daemon update completion run env proxy fakeip bypass tun vpn dns uninstall version help

for cmd in smartnet smartdns
    complete -c $cmd -f

    # Main commands
    complete -c $cmd -n "not __fish_seen_subcommand_from $commands" -a on -d "Enable SmartDNS on active network interface"
    complete -c $cmd -n "not __fish_seen_subcommand_from $commands" -a off -d "Disable SmartDNS (revert to DHCP)"
    complete -c $cmd -n "not __fish_seen_subcommand_from $commands" -a toggle -d "Toggle DNS state (on / off)"
    complete -c $cmd -n "not __fish_seen_subcommand_from $commands" -a status -d "Show hybrid DNS, VPN, TUN, and egress status"
    complete -c $cmd -n "not __fish_seen_subcommand_from $commands" -a test -d "Test latency, TLS ping, and routing"
    complete -c $cmd -n "not __fish_seen_subcommand_from $commands" -a list -d "List all configured profiles"
    complete -c $cmd -n "not __fish_seen_subcommand_from $commands" -a use -d "Switch active profile"
    complete -c $cmd -n "not __fish_seen_subcommand_from $commands" -a add -d "Add a new DoH profile"
    complete -c $cmd -n "not __fish_seen_subcommand_from $commands" -a remove -d "Remove a profile"
    complete -c $cmd -n "not __fish_seen_subcommand_from $commands" -a setup -d "Quick configure DoH on a new machine"
    complete -c $cmd -n "not __fish_seen_subcommand_from $commands" -a service -d "Manage system daemon (launchd/systemd)"
    complete -c $cmd -n "not __fish_seen_subcommand_from $commands" -a daemon -d "Run DNS and proxy server in foreground"
    complete -c $cmd -n "not __fish_seen_subcommand_from $commands" -a update -d "Update SmartNet to latest version"
    complete -c $cmd -n "not __fish_seen_subcommand_from $commands" -a uninstall -d "Completely remove SmartNet from system"
    complete -c $cmd -n "not __fish_seen_subcommand_from $commands" -a completion -d "Generate shell auto-completion script"
    complete -c $cmd -n "not __fish_seen_subcommand_from $commands" -a run -d "Run command with proxy environment injected"
    complete -c $cmd -n "not __fish_seen_subcommand_from $commands" -a env -d "Output proxy environment exports for shell"
    complete -c $cmd -n "not __fish_seen_subcommand_from $commands" -a proxy -d "Manage local Mixed HTTP/SOCKS5 proxy bridge"
    complete -c $cmd -n "not __fish_seen_subcommand_from $commands" -a fakeip -d "Manage zero-latency Fake-IP engine"
    complete -c $cmd -n "not __fish_seen_subcommand_from $commands" -a bypass -d "Manage Split DNS direct resolution rules"
    complete -c $cmd -n "not __fish_seen_subcommand_from $commands" -a tun -d "Manage Virtual TUN adapter (tun2socks mode)"
    complete -c $cmd -n "not __fish_seen_subcommand_from $commands" -a vpn -d "Manage VLESS-Reality VPN tunnel (anti-DPI)"
    complete -c $cmd -n "not __fish_seen_subcommand_from $commands" -a dns -d "Manage SmartDNS resolution mode"
    complete -c $cmd -n "not __fish_seen_subcommand_from $commands" -a version -d "Show version"
    complete -c $cmd -n "not __fish_seen_subcommand_from $commands" -a help -d "Show help"

    # Subcommands
    complete -c $cmd -n "__fish_seen_subcommand_from use remove" -a "(__smartnet_profiles)" -d "Profile"
    complete -c $cmd -n "__fish_seen_subcommand_from on" -a "(__smartnet_profiles)" -d "Profile"
    complete -c $cmd -n "__fish_seen_subcommand_from test" -a "(__smartnet_domains)" -d "Domain"
    complete -c $cmd -n "__fish_seen_subcommand_from service" -a "install uninstall start stop restart status"
    complete -c $cmd -n "__fish_seen_subcommand_from uninstall" -l purge -d "Purge all configuration profiles and data"
    complete -c $cmd -n "__fish_seen_subcommand_from proxy" -a "status run set"
    complete -c $cmd -n "__fish_seen_subcommand_from fakeip" -a "on off status clear"
    complete -c $cmd -n "__fish_seen_subcommand_from bypass" -a "add remove list"
    complete -c $cmd -n "__fish_seen_subcommand_from tun" -a "on off status"
    complete -c $cmd -n "__fish_seen_subcommand_from vpn" -a "on off toggle status set"
    complete -c $cmd -n "__fish_seen_subcommand_from dns" -a "on off toggle status"
    complete -c $cmd -n "__fish_seen_subcommand_from env" -a "fish zsh bash powershell"
    complete -c $cmd -n "__fish_seen_subcommand_from completion" -a "fish zsh bash powershell"
end
`

const BashScript = `# Bash completion for smartnet and smartdns
# Install: smartnet completion bash > /etc/bash_completion.d/smartnet (Linux)
# Or: smartnet completion bash >> ~/.bashrc

_smartnet_completions() {
    local cur prev commands
    cur="${COMP_WORDS[COMP_CWORD]}"
    prev="${COMP_WORDS[COMP_CWORD-1]}"
    commands="on off toggle status test list use add remove setup service daemon update uninstall completion run env proxy fakeip bypass tun vpn dns version help"

    case "$prev" in
        smartnet|smartdns)
            COMPREPLY=($(compgen -W "$commands" -- "$cur"))
            return 0
            ;;
        uninstall)
            COMPREPLY=($(compgen -W "--purge --all" -- "$cur"))
            return 0
            ;;
        use|remove|on)
            local profiles=$(smartnet list 2>/dev/null | grep -E '^[ ● ]*[a-zA-Z0-9_-]+' | awk '{for(i=1;i<=NF;i++) if($i ~ /^[a-zA-Z0-9_-]+$/) {print $i; break}}')
            COMPREPLY=($(compgen -W "$profiles" -- "$cur"))
            return 0
            ;;
        service)
            COMPREPLY=($(compgen -W "install uninstall start stop restart status" -- "$cur"))
            return 0
            ;;
        proxy)
            COMPREPLY=($(compgen -W "status run set" -- "$cur"))
            return 0
            ;;
        fakeip)
            COMPREPLY=($(compgen -W "on off status clear" -- "$cur"))
            return 0
            ;;
        bypass)
            COMPREPLY=($(compgen -W "add remove list" -- "$cur"))
            return 0
            ;;
        tun)
            COMPREPLY=($(compgen -W "on off status" -- "$cur"))
            return 0
            ;;
        vpn)
            COMPREPLY=($(compgen -W "on off toggle status set" -- "$cur"))
            return 0
            ;;
        dns)
            COMPREPLY=($(compgen -W "on off toggle status" -- "$cur"))
            return 0
            ;;
        env|completion)
            COMPREPLY=($(compgen -W "fish zsh bash powershell" -- "$cur"))
            return 0
            ;;
        test)
            local domains="cloudaicompanion.googleapis.com chatgpt.com claude.ai gemini.google.com spotify.com canva.com rutracker.org notion.so google.com"
            COMPREPLY=($(compgen -W "$domains" -- "$cur"))
            return 0
            ;;
    esac
}
complete -F _smartnet_completions smartnet smartdns
`

const ZshScript = `#compdef smartnet smartdns
# Zsh completion for smartnet and smartdns
# Install: smartnet completion zsh > ~/.zsh/completion/_smartnet (ensure dir is in $fpath)

_smartnet() {
    local -a commands
    commands=(
        'on:Enable SmartDNS on active network interface'
        'off:Disable SmartDNS (revert to DHCP)'
        'toggle:Toggle DNS state'
        'status:Show hybrid DNS, VPN, TUN, and egress status'
        'test:Test latency, TLS ping, and routing'
        'list:List all configured profiles'
        'use:Switch active profile'
        'add:Add a new DoH profile'
        'remove:Remove a profile'
        'setup:Quick configure DoH on a new machine'
        'service:Manage system daemon (launchd/systemd)'
        'daemon:Run DNS and proxy server in foreground'
        'update:Update SmartNet to latest version'
        'uninstall:Completely remove SmartNet from system'
        'completion:Generate shell auto-completion script'
        'run:Run command with proxy environment injected'
        'env:Output proxy environment exports for shell'
        'proxy:Manage local Mixed HTTP/SOCKS5 proxy bridge'
        'fakeip:Manage zero-latency Fake-IP engine'
        'bypass:Manage Split DNS direct resolution rules'
        'tun:Manage Virtual TUN adapter (tun2socks mode)'
        'vpn:Manage VLESS-Reality VPN tunnel (anti-DPI)'
        'dns:Manage SmartDNS resolution mode'
        'version:Show version'
        'help:Show help'
    )

    _arguments -C \
        '1: :->command' \
        '*:: :->args'

    case $state in
        command)
            _describe -t commands 'smartnet commands' commands
            ;;
        args)
            case $words[1] in
                use|remove|on)
                    local profiles=(${(f)"$(smartnet list 2>/dev/null | grep -E '^[ ● ]*[a-zA-Z0-9_-]+' | awk '{for(i=1;i<=NF;i++) if($i ~ /^[a-zA-Z0-9_-]+$/) {print $i; break}}')"})
                    _values 'profiles' $profiles
                    ;;
                service)
                    _values 'service commands' install uninstall start stop restart status
                    ;;
                proxy)
                    _values 'proxy commands' status run set
                    ;;
                fakeip)
                    _values 'fakeip commands' on off status clear
                    ;;
                bypass)
                    _values 'bypass commands' add remove list
                    ;;
                tun)
                    _values 'tun commands' on off status
                    ;;
                vpn)
                    _values 'vpn commands' on off toggle status set
                    ;;
                dns)
                    _values 'dns commands' on off toggle status
                    ;;
                env|completion)
                    _values 'shell' fish zsh bash powershell
                    ;;
                uninstall)
                    _values 'flags' --purge --all
                    ;;
                test)
                    _values 'domains' cloudaicompanion.googleapis.com chatgpt.com claude.ai gemini.google.com spotify.com canva.com rutracker.org notion.so google.com
                    ;;
            esac
            ;;
    esac
}

_smartnet "$@"
`

const PowerShellScript = `# PowerShell completion for smartnet and smartdns
# Install: Add to your $PROFILE:
#   smartnet completion powershell | Out-String | Invoke-Expression

Register-ArgumentCompleter -Native -CommandName smartnet, smartdns -ScriptBlock {
    param($wordToComplete, $commandAst, $cursorPosition)

    $elements = $commandAst.Elements
    $count = $elements.Count

    if ($count -eq 1 -or ($count -eq 2 -and -not $wordToComplete)) {
        $commands = @(
            [System.Management.Automation.CompletionResult]::new('on', 'on', 'ParameterValue', 'Enable SmartDNS on active network interface'),
            [System.Management.Automation.CompletionResult]::new('off', 'off', 'ParameterValue', 'Disable SmartDNS (revert to DHCP)'),
            [System.Management.Automation.CompletionResult]::new('toggle', 'toggle', 'ParameterValue', 'Toggle DNS state'),
            [System.Management.Automation.CompletionResult]::new('status', 'status', 'ParameterValue', 'Show hybrid DNS, VPN, TUN, and egress status'),
            [System.Management.Automation.CompletionResult]::new('test', 'test', 'ParameterValue', 'Test latency, TLS ping, and routing'),
            [System.Management.Automation.CompletionResult]::new('list', 'list', 'ParameterValue', 'List all configured profiles'),
            [System.Management.Automation.CompletionResult]::new('use', 'use', 'ParameterValue', 'Switch active profile'),
            [System.Management.Automation.CompletionResult]::new('add', 'add', 'ParameterValue', 'Add a new DoH profile'),
            [System.Management.Automation.CompletionResult]::new('remove', 'remove', 'ParameterValue', 'Remove a profile'),
            [System.Management.Automation.CompletionResult]::new('setup', 'setup', 'ParameterValue', 'Quick configure DoH on a new machine'),
            [System.Management.Automation.CompletionResult]::new('service', 'service', 'ParameterValue', 'Manage system daemon'),
            [System.Management.Automation.CompletionResult]::new('daemon', 'daemon', 'ParameterValue', 'Run DNS and proxy server in foreground'),
            [System.Management.Automation.CompletionResult]::new('update', 'update', 'ParameterValue', 'Update SmartNet to latest version'),
            [System.Management.Automation.CompletionResult]::new('uninstall', 'uninstall', 'ParameterValue', 'Completely remove SmartNet from system'),
            [System.Management.Automation.CompletionResult]::new('completion', 'completion', 'ParameterValue', 'Generate shell auto-completion script'),
            [System.Management.Automation.CompletionResult]::new('run', 'run', 'ParameterValue', 'Run command with proxy environment injected'),
            [System.Management.Automation.CompletionResult]::new('env', 'env', 'ParameterValue', 'Output proxy environment exports for shell'),
            [System.Management.Automation.CompletionResult]::new('proxy', 'proxy', 'ParameterValue', 'Manage local Mixed HTTP/SOCKS5 proxy bridge'),
            [System.Management.Automation.CompletionResult]::new('fakeip', 'fakeip', 'ParameterValue', 'Manage zero-latency Fake-IP engine'),
            [System.Management.Automation.CompletionResult]::new('bypass', 'bypass', 'ParameterValue', 'Manage Split DNS direct resolution rules'),
            [System.Management.Automation.CompletionResult]::new('tun', 'tun', 'ParameterValue', 'Manage Virtual TUN adapter (tun2socks mode)'),
            [System.Management.Automation.CompletionResult]::new('vpn', 'vpn', 'ParameterValue', 'Manage VLESS-Reality VPN tunnel (anti-DPI)'),
            [System.Management.Automation.CompletionResult]::new('dns', 'dns', 'ParameterValue', 'Manage SmartDNS resolution mode'),
            [System.Management.Automation.CompletionResult]::new('version', 'version', 'ParameterValue', 'Show version'),
            [System.Management.Automation.CompletionResult]::new('help', 'help', 'ParameterValue', 'Show help')
        )
        $commands | Where-Object { $_.CompletionText -like "$wordToComplete*" }
        return
    }

    $subcommand = $elements[1].Value

    switch ($subcommand) {
        { $_ -in 'use', 'remove', 'on' } {
            $profiles = & smartnet list 2>$null | Select-String '^[ ● ]*([a-zA-Z0-9_-]+)' | ForEach-Object {
                if ($_ -match '^[ ● ]*([a-zA-Z0-9_-]+)') { $matches[1] }
            }
            $profiles | Where-Object { $_ -like "$wordToComplete*" } | ForEach-Object {
                [System.Management.Automation.CompletionResult]::new($_, $_, 'ParameterValue', 'Profile')
            }
        }
        'service' {
            $subs = @('install', 'uninstall', 'start', 'stop', 'restart', 'status')
            $subs | Where-Object { $_ -like "$wordToComplete*" } | ForEach-Object {
                [System.Management.Automation.CompletionResult]::new($_, $_, 'ParameterValue', 'Service command')
            }
        }
        'proxy' {
            $subs = @('status', 'run', 'set')
            $subs | Where-Object { $_ -like "$wordToComplete*" } | ForEach-Object {
                [System.Management.Automation.CompletionResult]::new($_, $_, 'ParameterValue', 'Proxy command')
            }
        }
        'fakeip' {
            $subs = @('on', 'off', 'status', 'clear')
            $subs | Where-Object { $_ -like "$wordToComplete*" } | ForEach-Object {
                [System.Management.Automation.CompletionResult]::new($_, $_, 'ParameterValue', 'Fake-IP command')
            }
        }
        'bypass' {
            $subs = @('add', 'remove', 'list')
            $subs | Where-Object { $_ -like "$wordToComplete*" } | ForEach-Object {
                [System.Management.Automation.CompletionResult]::new($_, $_, 'ParameterValue', 'Bypass command')
            }
        }
        'tun' {
            $subs = @('on', 'off', 'status')
            $subs | Where-Object { $_ -like "$wordToComplete*" } | ForEach-Object {
                [System.Management.Automation.CompletionResult]::new($_, $_, 'ParameterValue', 'TUN command')
            }
        }
        'vpn' {
            $subs = @('on', 'off', 'toggle', 'status', 'set')
            $subs | Where-Object { $_ -like "$wordToComplete*" } | ForEach-Object {
                [System.Management.Automation.CompletionResult]::new($_, $_, 'ParameterValue', 'VPN command')
            }
        }
        'dns' {
            $subs = @('on', 'off', 'toggle', 'status')
            $subs | Where-Object { $_ -like "$wordToComplete*" } | ForEach-Object {
                [System.Management.Automation.CompletionResult]::new($_, $_, 'ParameterValue', 'DNS command')
            }
        }
        'uninstall' {
            $subs = @('--purge', '--all')
            $subs | Where-Object { $_ -like "$wordToComplete*" } | ForEach-Object {
                [System.Management.Automation.CompletionResult]::new($_, $_, 'ParameterValue', 'Purge option')
            }
        }
        { $_ -in 'env', 'completion' } {
            $shells = @('fish', 'zsh', 'bash', 'powershell', 'pwsh')
            $shells | Where-Object { $_ -like "$wordToComplete*" } | ForEach-Object {
                [System.Management.Automation.CompletionResult]::new($_, $_, 'ParameterValue', 'Shell')
            }
        }
        'test' {
            $domains = @('cloudaicompanion.googleapis.com', 'chatgpt.com', 'claude.ai', 'gemini.google.com', 'spotify.com', 'canva.com', 'rutracker.org', 'notion.so', 'google.com')
            $domains | Where-Object { $_ -like "$wordToComplete*" } | ForEach-Object {
                [System.Management.Automation.CompletionResult]::new($_, $_, 'ParameterValue', 'Domain')
            }
        }
    }
}
`

// Generate returns the completion script for the requested shell
func Generate(shell string) (string, error) {
	switch strings.ToLower(shell) {
	case "fish":
		return FishScript, nil
	case "bash":
		return BashScript, nil
	case "zsh":
		return ZshScript, nil
	case "powershell", "pwsh":
		return PowerShellScript, nil
	default:
		return "", fmt.Errorf("unsupported shell: %q (supported: fish, zsh, bash, powershell)", shell)
	}
}

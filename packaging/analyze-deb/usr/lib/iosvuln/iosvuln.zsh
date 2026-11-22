# iosvuln zsh shortcuts for jailbroken iOS (NewTerm / zsh).
# Source from ~/.zshrc:  source /usr/lib/iosvuln/iosvuln.zsh
# The deb postinst adds this line automatically.

# Core alias: iv == iosvuln
alias iv='iosvuln'

# One-letter style shortcuts (functions so arguments pass through cleanly).
iv-scan()   { iosvuln run --workdir "${2:-./iosvuln-out}" ${1:+--target "$1"}; }
iv-demo()   { iosvuln demo --workdir "${1:-/var/mobile/iosvuln-demo}"; }
iv-info()   { iosvuln info "$@"; }
iv-targets(){ iosvuln targets "$@"; }
iv-home()   { iosvuln home "$@"; }
iv-import() { iosvuln import "$@"; }
iv-hist()   { iosvuln history "$@"; }

# Super-short aliases
alias ivd='iv-demo'
alias ivs='iv-scan'
alias ivi='iv-info'
alias ivt='iv-targets'
alias ivh='iv-home'
alias ivim='iv-import'
alias ivl='iv-hist'

# Scan a kernelcache with just:  ivk <path> [target]
ivk() {
  local kc="$1"; shift
  iosvuln run --kernelcache "$kc" --workdir /var/mobile/iosvuln-run "$@"
}

# Collect then scan in one shot (needs collect deb):  ivall [path]
ivall() {
  iosvuln-collect "$@" >/dev/null 2>&1 || true
  iosvuln run --kernelcache /var/mobile/iosvuln/kernelcache \
              --workdir /var/mobile/iosvuln-run
}

print -r -- "iosvuln shortcuts loaded: iv, ivs, ivd, ivi, ivt, ivh, ivim, ivl, ivk, ivall" >&2

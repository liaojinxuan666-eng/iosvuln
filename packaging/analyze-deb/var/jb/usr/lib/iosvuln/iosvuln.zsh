# iosvuln zsh shortcuts for jailbroken iOS (NewTerm / zsh).
# Source from ~/.zshrc:  source /usr/lib/iosvuln/iosvuln.zsh
# The deb postinst adds this line automatically.
#
# Everything is built on the one-shot `iosvuln scan`: you only add options.

# `iv` with no args = one-shot auto scan (collect->targets->analyze->report).
# With args, it behaves like plain `iosvuln` (subcommands still available).
iv() {
  if (( $# == 0 )); then
    iosvuln scan --workdir /var/mobile/iosvuln-run
  else
    command iosvuln "$@"
  fi
}

# One-shot scan helpers (all forward options straight to `iosvuln scan`).
iv-scan()   { iosvuln scan "$@"; }
iv-full()   { iosvuln scan --full "$@"; }              # all targets + all plugins
iv-demo()   { iosvuln scan --from demo "$@"; }         # no real firmware needed
iv-fast()   { iosvuln scan --preset fast "$@"; }        # core plugins only
iv-pac()    { iosvuln scan --preset pac "$@"; }         # arm64e PAC / pointer only
iv-deep()   { iosvuln scan --preset deep --full "$@"; }# everything, no limits

# Utility subcommands (kept for advanced use).
iv-info()   { iosvuln info "$@"; }
iv-targets(){ iosvuln targets "$@"; }
iv-home()   { iosvuln home "$@"; }
iv-import() { iosvuln import "$@"; }
iv-hist()   { iosvuln history "$@"; }

# Super-short aliases
alias ivs='iv-scan'
alias ivf='iv-full'
alias ivd='iv-demo'
alias ivz='iv-fast'
alias ivp='iv-pac'
alias ivx='iv-deep'
alias ivi='iv-info'
alias ivt='iv-targets'
alias ivh='iv-home'
alias ivim='iv-import'
alias ivl='iv-hist'

# Scan a specific source with options only:  ivk <kernelcache> [scan options]
ivk() {
  local kc="$1"; shift
  iosvuln scan --kernelcache "$kc" "$@"
}
# Scan an IPSW:  ivipsw <firmware.ipsw> [scan options]
ivipsw() {
  local fw="$1"; shift
  iosvuln scan --ipsw "$fw" "$@"
}
# Collect then one-shot scan (needs collect deb):  ivall [collect opts --] [scan opts]
ivall() {
  iosvuln-collect "$@" >/dev/null 2>&1 || true
  iosvuln scan --kernelcache /var/mobile/iosvuln/kernelcache --full
}

print -r -- "iosvuln shortcuts loaded: iv, ivs, ivf, ivd, ivz, ivp, ivx, ivi, ivt, ivh, ivim, ivl, ivk, ivipsw, ivall" >&2

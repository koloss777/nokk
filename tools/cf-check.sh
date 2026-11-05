#!/usr/bin/env bash
# Run nokk against the public Cloudflare test targets and print, per target: the
# verdict (exit code 0 = through, 3 = a gate is still up), the time, the final
# page title and, where a Turnstile widget sits on the page, its token length.
# A target that passes but made Turnstile send its error beacon is marked EB:
# the challenge script threw in the engine, the first sign of a break. One that
# answers with Cloudflare's block page is marked IP: blocked by address.
# Exits non-zero when any target is not a clean OK, so it doubles as a canary.
# Do not run it alongside `cargo test` or a Chrome: under load a challenge can
# run out of time.
NOKK=${NOKK:-./target/release/nokk}   # or: NOKK=$(command -v nokk) tools/cf-check.sh
PROBE='(() => { const t = document.querySelector("[name=cf-turnstile-response]");
  return document.title + "  |  " + (/Just a moment/i.test(document.title) ? "GATE" : "page")
    + (t && t.value ? "  |  token " + t.value.length + " chars" : ""); })()'
for url in \
  https://www.chess.com/login \
  https://www.scrapingcourse.com/cloudflare-challenge \
  https://peet.ws/turnstile-test/managed.html \
  https://peet.ws/turnstile-test/non-interactive.html \
  https://nopecha.com/demo/cloudflare ; do
  t0=$(date +%s)
  # Logs share stdout with the result; the result is the last non-log line.
  out=$(RUST_LOG=error,nokk_net=warn timeout 90 "$NOKK" --load "$url" --solve-challenge 30 --fail-on-challenge --eval "$PROBE" 2>/dev/null)
  code=$?
  case $code in 0) st="OK  ";; 3) st="FAIL";; 124) st="TIME";; *) st="E$code";; esac
  [ $code = 0 ] && grep -q "error beacon" <<<"$out" && st="EB  "
  # Cloudflare's block page ("Attention Required!") is a firewall rule against the
  # address, not a challenge: real Chrome from the same IP gets it too.
  [ $code = 0 ] && grep -q "Attention Required" <<<"$out" && st="IP  "
  [ "$st" = "OK  " ] || bad=1
  printf '%s %3ss  %-52s %s\n' "$st" $(( $(date +%s)-t0 )) "$url" "$(echo "$out" | grep -v '^\s*$' | grep -v 'error beacon' | tail -1)"
done
exit ${bad:-0}

#!/usr/bin/env -S nix shell nixpkgs#bash nixpkgs#coreutils nixpkgs#gnugrep nixpkgs#jq --command bash

set -euo pipefail

# Paste a fresh list here. Blank lines are ignored.
TARGET_ADDRESSES='
0zk1qyduss9nnfyycfwt03fwds69c7z27rmmulcxsq3lvn0yhwjxfa7lnrv7j6fe3z53la7dxtysu5dtqp9lh6k6qeft3j5cvawwdq7zx6t9ltsncagyz06wk4n66nt
0zk1qypste3j7z623g9h58a3tstj5gemj8um8ccnhsz4du7evyuajzy7frv7j6fe3z53llceke63aaj9n7s42ll44zlh604fh96ssa0hat208xwl9hqj3hhewetyj8c
0zk1qyd6jjx8utlxjj64wjmx8z68ycd2gy0fw7slqv5yx37r5gl9qlqsarv7j6fe3z53lalpg5ftv0ywjxsglmc4pdwk9dl26j5fq6r2y7lkg76928krsgg3c5697dg
0zk1qyq4s9q0rvkmsvjt7x5x84vlkvj55recqft526k3rhf60qk66vv9lrv7j6fe3z53lalqq04g43x8twuwaj6kd3j0y8yrxln94s9xpcffkefjs9jrkrmacrelvt8
0zk1qyrvnyafq9x22x79kz7fkq9y5aywjz6sr2ff9h28a3qtyk0mj3lh8rv7j6fe3z53laxz99ea9ujj4rpa2yvkap4syadklqyqajec6j0hlng9vsv7qt2rq7zpqaz
0zk1qypyarm67q8qlk4jv4jcvnkfv6yfsckrqtpak0z9y9uqngcapqfk8rv7j6fe3z53laakhd23v574qdfrezccxujcy8zfhmegmhgkw8cfcn0u4th3agctk673q8n
0zk1qys0mr2gnugtyscm6g699v6tnfmhkhfa08zfrtp5qy2928rzzarh8rv7j6fe3z53laj08fe4a2dwjjylzpyvdudngprxmy0z9c4t0tvacl9yp0sk3pc0je0puw5
0zk1qygp840xz8q7lqcypgn6d7pxhcn7mj9fpl5g48j9dpyje8gtrd3rerv7j6fe3z53l7tqkpuuat0qnpuh2y0g8xchfl024q9gsvyjeamtreaygfj7vm3rz7568ez
0zk1qyw9ypgk3kdgvccqrcjhu3cjd2rvpl3zuyya9ln7c97w8d2uwyhe0rv7j6fe3z53l7e9njvt6z26fugqgpzrckgcjyz60vv8gtcknyzmzgppy9enazllud8vhgw
0zk1qy2g9k0rrr9920gnjh5pc3knju557e0lxqjtly6kxad05g5msxederv7j6fe3z53l7fmmeepthqqa5vr5q3f2xveqpekle2a52745pujekaegjnh22dr5583tun
0zk1qyqhtwaa9zj3ug9dmxhfedappvm509w7dr5lgadaehxz38w9u457mrv7j6fe3z53layes62mktxj5kd6reh2kxd39ds2gnpf6wphtw39y5g36lsvukeywfqa8y0
0zk1qyzgh9ctuxm6d06gmax39xutjgrawdsljtv80lqnjtqp3exxayuf0rv7j6fe3z53laetcl9u3cma0q9k4npgy8c8ga4h6mx83v09m8ewctsekw4a079dcl5sw4k
0zk1qy5j3nrlkxz0mr52smtc32jfxy5pwzzdc6eucwfu97kzrg5wed3cdrv7j6fe3z53lapeu944eu462rh3q885scpz7578u9xkfuuhl0qvpy45aq75njz7xz2cuwn
0zk1qykqfn7uewrlmam9w8gtwn05j2m55q536yzh2wa0r0sj9le6p9aqarv7j6fe3z53llz0d7vjhr4z2wj656ml79488j77raqtqnmppqek2wk0c29q545wcj33tnp
0zk1qy88aamk4dp3rn2dvfdu5u8vvtfs89vg8h6zyajr4g5mq0ykm28e0rv7j6fe3z53l7zpahc5w52u8juzg54ypn24slqsyy3dy57s5k3669dyg3jxyp6czxszfs7
0zk1qyjyhqjdkqd9qxusgj092ppxl92plvrk3s3cna9u73h5rwt0ghxvfrv7j6fe3z53l7lrzyqw5te7ku5v8fsrpeadzvpkudgawjv9dg08htj7z3mph5kd6dw50jc
'

WORD_COUNT="${WORD_COUNT:-12}"
PROGRESS_EVERY="${PROGRESS_EVERY:-100}"
MAX_ATTEMPTS="${MAX_ATTEMPTS:-}"
REQUIRED_SUFFIX="${REQUIRED_SUFFIX:-}"

trim_line() {
  local value="$1"
  value="${value#"${value%%[![:space:]]*}"}"
  value="${value%"${value##*[![:space:]]}"}"
  printf '%s' "$value"
}

require_supported_word_count() {
  case "$1" in
    12|15|18|21|24) ;;
    *)
      printf 'Unsupported WORD_COUNT: %s\n' "$1" >&2
      exit 1
      ;;
  esac
}

require_non_negative_integer() {
  local label="$1"
  local value="$2"

  if [[ ! "$value" =~ ^[0-9]+$ ]]; then
    printf '%s must be a non-negative integer, got: %s\n' "$label" "$value" >&2
    exit 1
  fi
}

require_valid_address() {
  local value="$1"

  if [[ ! "$value" =~ ^0zk1[023456789acdefghjklmnpqrstuvwxyz]+$ ]]; then
    printf 'Invalid target address: %s\n' "$value" >&2
    exit 1
  fi
}

require_valid_suffix() {
  local value="$1"

  if [[ -z "$value" ]]; then
    return
  fi

  if [[ ! "$value" =~ ^[023456789acdefghjklmnpqrstuvwxyz]+$ ]]; then
    printf 'Invalid REQUIRED_SUFFIX: %s\n' "$value" >&2
    printf 'Suffix must use only Bech32 lowercase payload characters and must not include the 0zk1 prefix.\n' >&2
    exit 1
  fi
}

require_supported_word_count "$WORD_COUNT"
require_non_negative_integer "PROGRESS_EVERY" "$PROGRESS_EVERY"
require_valid_suffix "$REQUIRED_SUFFIX"

if [[ -n "$MAX_ATTEMPTS" ]]; then
  require_non_negative_integer "MAX_ATTEMPTS" "$MAX_ATTEMPTS"
fi

script_dir="$(dirname -- "${BASH_SOURCE[0]}")"
repo_root="$(realpath -- "${script_dir}/..")"

mapfile -t target_addresses < <(
  while IFS= read -r raw_line; do
    line="$(trim_line "$raw_line")"
    if [[ -n "$line" ]]; then
      printf '%s\n' "$line"
    fi
  done <<< "$TARGET_ADDRESSES"
)

if (( ${#target_addresses[@]} == 0 )); then
  printf 'TARGET_ADDRESSES is empty. Paste at least one 0zk address into the script.\n' >&2
  exit 1
fi

for address in "${target_addresses[@]}"; do
  require_valid_address "$address"
done

IFS= read -r minimum_target < <(printf '%s\n' "${target_addresses[@]}" | LC_ALL=C sort)

printf 'Building railgun CLI with Nix...\n' >&2
cli_out="$(nix build "${repo_root}#default" --print-out-paths --no-link)"
cli_bin="${cli_out}/bin/railguncli"

if [[ ! -x "$cli_bin" ]]; then
  printf 'Expected CLI binary was not produced at %s\n' "$cli_bin" >&2
  exit 1
fi

printf 'Searching for an index 0 address smaller than:\n%s\n' "$minimum_target" >&2

if [[ -n "$REQUIRED_SUFFIX" ]]; then
  printf 'Also requiring addresses to end with:\n%s\n' "$REQUIRED_SUFFIX" >&2
fi

attempt=0

while :; do
  if [[ -n "$MAX_ATTEMPTS" ]] && (( attempt >= MAX_ATTEMPTS )); then
    printf 'No matching address found in %d attempts.\n' "$attempt" >&2
    exit 1
  fi

  attempt=$((attempt + 1))

  mnemonic_json="$($cli_bin mnemonic generate --words "$WORD_COUNT" --json)"
  mnemonic="$(jq -r '.mnemonic' <<< "$mnemonic_json")"

  keys_json="$($cli_bin keys derive --mnemonic "$mnemonic" --index 0 --show-secrets --json)"
  viewing_private_key="$(jq -r '.viewingPrivateKey' <<< "$keys_json")"
  packed_spending_public_key="$(jq -r '.packedSpendingPublicKey' <<< "$keys_json")"

  shareable_viewing_key_json="$($cli_bin viewing-key encode --viewing-private-key "$viewing_private_key" --packed-spending-public-key "$packed_spending_public_key" --show-secrets --json)"
  shareable_viewing_key="$(jq -r '.shareableViewingKey' <<< "$shareable_viewing_key_json")"

  decoded_viewing_key_json="$($cli_bin viewing-key decode --shareable-viewing-key "$shareable_viewing_key" --show-secrets --json)"
  candidate_address="$(jq -r '.address' <<< "$decoded_viewing_key_json")"

  if [[ "$candidate_address" < "$minimum_target" ]] && [[ -z "$REQUIRED_SUFFIX" || "$candidate_address" == *"$REQUIRED_SUFFIX" ]]; then
    printf 'Found matching address after %d attempts.\n' "$attempt"
    printf 'minimumTargetAddress: %s\n' "$minimum_target"
    printf 'derivedAddress: %s\n' "$candidate_address"
    printf 'mnemonic: %s\n' "$mnemonic"
    printf 'index: 0\n'
    printf 'wordCount: %s\n' "$WORD_COUNT"
    if [[ -n "$REQUIRED_SUFFIX" ]]; then
      printf 'requiredSuffix: %s\n' "$REQUIRED_SUFFIX"
    fi
    printf 'viewingPrivateKey: %s\n' "$viewing_private_key"
    printf 'packedSpendingPublicKey: %s\n' "$packed_spending_public_key"
    printf 'shareableViewingKey: %s\n' "$shareable_viewing_key"
    exit 0
  fi

  if (( PROGRESS_EVERY > 0 && attempt % PROGRESS_EVERY == 0 )); then
    printf 'Attempts: %d currentAddress: %s targetMinimum: %s\n' \
      "$attempt" \
      "$candidate_address" \
      "$minimum_target" >&2
  fi
done

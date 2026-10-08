#!/usr/bin/env bash
# Offline regression checks: load definitions without running network checks.
set -eo pipefail
script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
source <(awk '/^generate_random_user_agent$/{exit} {print}' "$script_dir/ip-quality.sh")
test_tmp=$(mktemp -d)
trap 'rm -rf "$test_tmp"' EXIT
stderr_file="$test_tmp/stderr"
curl_log="$test_tmp/curl.log"
show_progress_bar(){ :; }
kill_progress_bar(){ :; }
disown(){ :; }
nslookup(){
printf '%s\n' 'Server: 1.1.1.1' 'Address: 1.1.1.1#53' 'Name: example.com' 'Address: 8.8.8.8'
}
dig(){
case "$*" in
*error.example*) echo 127.255.255.254;;
*listed.example*) echo 127.0.0.2;;
*other.example*) echo 127.0.0.3;;
esac
}
export -f dig
set_language
IP="61.13.156.72"
CurlARG="--interface test0 --proxy socks5://localhost:1080"
UA_Browser="regression-test"
rawgithub="https://example.invalid/"
useNIC=""
usePROXY=""
MOCK_BODY=""
MOCK_DIRECT=""
MOCK_MODE="body"
curl(){
printf '%s\n' "$*" >>"$curl_log"
case "$*" in
*api.ipapi.is*) printf '%s' "$MOCK_DIRECT";;
*db-ip.com/api/core/*) printf '%s' '<div data-api-key="test123"></div>';;
*dnsbl.list*) printf '%s\n' clean.example error.example listed.example other.example;;
*)
if [[ $MOCK_MODE == ipv4_fallback && $* == *ipinfo.io/ip* ]];then
printf '%s' '<html>Access denied</html>'
elif [[ $MOCK_MODE == ipv4_fallback && $* == *myip.check.place* ]];then
printf '%s' '999.1.1.1'
elif [[ $MOCK_MODE == failed ]];then
printf '%s' "$MOCK_BODY"
return 22
else
printf '%s' "$MOCK_BODY"
fi;;
esac
}
assert_eq(){
if [[ $1 != "$2" ]];then
printf 'FAIL: %s (expected %s, got %s)\n' "$3" "$2" "$1" >&2
exit 1
fi
}
assert_quiet(){ assert_eq "$(cat "$stderr_file")" "" "$1"; }

# Reproduce the screenshot's string company response and non-JSON failures.
for MOCK_BODY in '{"company":"API quota exceeded"}' '"API error"' '<html>Forbidden</html>' 'null' '{}';do
MOCK_DIRECT="$MOCK_BODY"
ipapi[score]="stale"
if db_ipapi 4 2>"$stderr_file";then
assert_eq accepted rejected 'invalid ipapi response'
fi
assert_quiet 'invalid ipapi response produces no jq/awk errors'
assert_eq "${ipapi[score]-}" "" 'stale ipapi score cleared'
done
for score in '0.125 (Low)' null '' 'invalid';do
MOCK_BODY=$(jq -cn --arg score "$score" '{asn:{type:"isp"},company:{type:"isp",abuser_score:$score},location:{country_code:"SG"}}')
db_ipapi 4 2>"$stderr_file"
assert_quiet 'missing or invalid ipapi scores produce no awk errors'
if [[ $score == '0.125 (Low)' ]];then
assert_eq "${ipapi[score]-}" '12.50%' 'numeric ipapi score'
else
assert_eq "${ipapi[score]-}" '' 'non-numeric ipapi score omitted'
fi
done
MOCK_DIRECT="$MOCK_BODY"
MOCK_BODY='<html>WAF blocked</html>'
db_ipapi 6 2>"$stderr_file"
assert_quiet 'direct ipapi fallback'
assert_eq "${ipapi[countrycode]}" SG 'fallback parses valid data'

# Invalid content, invalid octets and unsuccessful curl must not become IPs.
MOCK_MODE=ipv4_fallback
MOCK_BODY="$IP"
get_ipv4
assert_eq "$IPV4" "$IP" 'IPv4 fallback skips HTML and invalid octets'
MOCK_MODE=body
MOCK_BODY='2001:db8::1'
get_ipv6
assert_eq "$IPV6" "$MOCK_BODY" 'IPv6 extraction'
MOCK_MODE=failed
get_ipv6
assert_eq "$IPV6" '' 'failed curl with an IPv6-looking body rejected'
MOCK_MODE=body
MOCK_BODY='<html>Access denied</html>'
get_ipv6
assert_eq "$IPV6" '' 'IPv6 rejects HTML'
is_valid_ipv4 008.008.008.008
hide_ipv4 "$IP"
assert_eq "$IPhide" '61.13.156.*' 'custom IP mask retained'

# Exact country extraction prevents the long webpage string in the screenshot.
MOCK_BODY='{"currentTerritory": "SG", "currentTerritory":"US", "Program":{"dataType":"Movie"}}'
MediaUnlockTest_PrimeVideo_Region 4
assert_eq "${amazon[uregion]}" '  [SG]   ' 'Amazon first country code'
MOCK_BODY='{"currentTerritory":"Program/dataType/Movie"}'
MediaUnlockTest_PrimeVideo_Region 4
assert_eq "${amazon[uregion]}" "${smedia[nodata]}" 'Amazon rejects arbitrary text'
MOCK_BODY='{"locale":"en_US"}'
MediaUnlockTest_Instagram 4
assert_eq "${instagram[uregion]}" "${smedia[nodata]}" 'Instagram locale is not an IP country'
MOCK_BODY='{"country_code": "SG", "locale":"en_US"}'
MediaUnlockTest_Instagram 4
assert_eq "${instagram[uregion]}" '  [SG]   ' 'Instagram country retained'

# DB-IP must honor the selected route and reject results for another IP.
MOCK_BODY='{"ipAddress":"61.13.156.72","countryCode":"SG","threatLevel":"low","isProxy":false,"isCrawler":true}'
db_dbip 4 2>"$stderr_file"
assert_quiet 'DB-IP JSON response'
assert_eq "${dbip[countrycode]}" SG 'DB-IP country'
assert_eq "${dbip[robot]}" true 'DB-IP crawler'
if ! tail -n 1 "$curl_log" | grep -q -- '--interface test0 --proxy socks5://localhost:1080 -fsL -4';then
assert_eq wrong correct 'DB-IP preserves interface, proxy and IP family'
fi
MOCK_BODY='{"ipAddress":"1.1.1.1","countryCode":"US"}'
if db_dbip 4 2>"$stderr_file";then
assert_eq accepted rejected 'DB-IP mismatched address'
fi
assert_quiet 'DB-IP mismatch'
assert_eq "${dbip[countrycode]-}" '' 'DB-IP mismatch leaves no data'
MOCK_BODY='<html>Forbidden</html>'
if db_dbip 6 2>"$stderr_file";then
assert_eq accepted rejected 'DB-IP invalid response'
fi
assert_quiet 'DB-IP invalid JSON'

# DNS query failures must not be falsely labeled as a DNS unlock.
assert_eq "$(Check_DNS_IP '' '')" 1 'missing DNS IP'
assert_eq "$(Check_DNS_3 example.com)" 1 'empty DNS answer'
assert_eq "$(check_dnsbl_parallel "$IP" 2)" '4 2 1 1' 'DNSBL error-code classification'

# JSON should retain custom media fields and isolate each report's updates.
fullIP=0
mode_lite=1
smail[local]=0
smail[t]=10
smail[c]=9
smail[m]=1
smail[b]=0
ip2location[scomtype]='hosting'
ipjson='{"Head":{},"Info":{},"Type":{},"Score":{},"Factor":{},"Media":{},"Mail":{}}'
mail_updates='INVALID OUTER STATE'
save_json 2>"$stderr_file"
assert_quiet 'JSON serialization'
assert_eq "$(jq -r '.Type.Company.IP2LOCATION' <<<"$ipjson")" hosting 'JSON company field'
assert_eq "$(jq -r '.Media | has("Instagram") and (has("DisneyPlus") | not) and (has("Reddit") | not)' <<<"$ipjson")" true 'custom JSON media retained'
smail[t]=5
save_json 2>"$stderr_file"
assert_quiet 'second JSON report'
assert_eq "$(jq -r '.Mail.DNSBlacklist.Total' <<<"$ipjson")" 5 'JSON report values refreshed'
assert_eq "$mail_updates" 'INVALID OUTER STATE' 'JSON does not mutate outer accumulator'
printf 'PASS: offline API, IP, media, DNSBL and JSON regressions\n'

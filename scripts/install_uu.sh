#!/bin/bash
# Install NetEase UU Remote (official signed pkg) on the throwaway runner VM and
# pre-grant the privacy permissions a remote-control host needs.
set -uo pipefail
work="$RUNNER_TEMP/uu"
mkdir -p "$work"
pkg="$work/uu.pkg"
curl -fsSL --retry 3 -o "$pkg" "https://api.nrd.nie.163.com/api/v1/release/dl/4?channel=gwqd" || { echo "UU download failed"; exit 1; }
ls -l "$pkg"
pkgutil --check-signature "$pkg" | tee "$work/sig.txt"
# Pinned to the Developer ID team that signs the pkg served by the official
# uuyc.163.com download button (via adl.netease.com / gdl.netease.com), notarized by Apple.
grep -q "signed by a developer certificate issued by Apple" "$work/sig.txt" \
  && grep -q "Notarization: trusted by the Apple notary service" "$work/sig.txt" \
  && grep -q "Developer ID Installer: .*(PU9BNSBJW7)" "$work/sig.txt" \
  || { echo "UU package is not the expected notarized Developer ID (team PU9BNSBJW7); refusing to install."; exit 1; }
spctl --assess --type install -vv "$pkg" 2>&1 | tail -2

before=$(ls /Applications)
sudo installer -pkg "$pkg" -target / || { echo "UU install failed"; exit 1; }
app=$(comm -13 <(echo "$before") <(ls /Applications) | grep -i '\.app$' | head -1)
[ -z "$app" ] && app=$(ls /Applications | grep -iE 'uu|网易' | grep '\.app$' | head -1)
[ -z "$app" ] && { echo "UU app bundle not found"; ls /Applications; exit 1; }
app="/Applications/$app"
echo "UU app: $app"
echo "SIP: $(csrutil status 2>&1)"
pkgutil --pkgs | grep -iE 'netease|uu' | while read -r id; do
  echo "pkg $id:"; pkgutil --files "$id" | grep -iE 'launch(daemon|agent)s/|\.app$|/MacOS/[^/]+$' | head -20
done

grant() { # $1 client  $2 client_type (0 bundle id, 1 path)  $3 code path
  local req hex now
  req=$(codesign -d -r- "$3" 2>&1 | sed -n 's/^designated => //p')
  hex=""
  if [ -n "$req" ] && echo "$req" | csreq -r- -b "$work/req.bin" 2>/dev/null; then
    hex=$(xxd -p "$work/req.bin" | tr -d '\n')
  fi
  local blob="NULL"; [ -n "$hex" ] && blob="X'$hex'"
  now=$(date +%s)
  for db in "/Library/Application Support/com.apple.TCC/TCC.db" "$HOME/Library/Application Support/com.apple.TCC/TCC.db"; do
    for svc in kTCCServiceScreenCapture kTCCServiceAccessibility kTCCServicePostEvent kTCCServiceListenEvent \
               kTCCServiceMicrophone kTCCServiceSystemPolicyAllFiles; do
      sudo sqlite3 "$db" "INSERT OR REPLACE INTO access VALUES('$svc','$1',$2,2,4,1,$blob,NULL,0,'UNUSED',NULL,0,$now,NULL,NULL,'UNUSED',$now);" \
        2>&1 | head -1
    done
  done
  echo "Granted permissions to $1 (csreq: $([ -n "$hex" ] && echo yes || echo no))"
}

# Main app plus every nested app bundle (helpers often do the capture/input work).
while IFS= read -r bundle; do
  id=$(defaults read "$bundle/Contents/Info" CFBundleIdentifier 2>/dev/null) || continue
  exe=$(defaults read "$bundle/Contents/Info" CFBundleExecutable 2>/dev/null)
  echo "Bundle $id archs: $(lipo -archs "$bundle/Contents/MacOS/$exe" 2>/dev/null)"
  grant "$id" 0 "$bundle"
done < <({ echo "$app"; find "$app/Contents" -name '*.app' -type d; } | sort -u)
# Daemons/agents installed by the package, referenced by absolute path.
for plist in /Library/LaunchDaemons/*.plist /Library/LaunchAgents/*.plist; do
  grep -qiE 'netease|uu' "$plist" 2>/dev/null || continue
  exe=$(/usr/libexec/PlistBuddy -c 'Print :ProgramArguments:0' "$plist" 2>/dev/null || /usr/libexec/PlistBuddy -c 'Print :Program' "$plist" 2>/dev/null)
  echo "Launchd job $plist -> $exe"
  [ -n "$exe" ] && [ -e "$exe" ] && grant "$exe" 1 "$exe"
done
sudo killall tccd 2>/dev/null || true
killall tccd 2>/dev/null || true
sleep 1
open "$app"
echo "UU_APP=$app" >> "$GITHUB_ENV"
echo "UU Remote installed and launched."

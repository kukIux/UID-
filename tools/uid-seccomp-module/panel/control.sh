#!/system/bin/sh
set -eu
MODDIR=${0%/*}
. "$MODDIR/locale.sh"
ID=cq_uid_seccomp
STORE=/data/adb/cq_uid_seccomp
CURRENT=/data/adb/modules/$ID
PENDING=/data/adb/modules_update/$ID
[ "$(id -u)" = 0 ] || { cq_message '需要模块管理器的 Root 接口' 'The module manager Root interface is required' >&2; exit 1; }
mkdir -p "$STORE"
chmod 700 "$STORE"

validate() {
    [ "$(wc -c < "$1")" -le 32768 ] || return 1
    awk 'NR==1 {if ($0!="enabled=0" && $0!="enabled=1") exit 1; next}
        {if (length($0)>255 || $0 !~ /^[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_]*)+$/ || ++n>128) exit 1}
        END {if (NR<1) exit 1}' "$1"
}
copy_config() {
    target=$1
    [ -d "$target" ] || return 0
    cp "$STORE/config" "$target/config.new"
    chmod 644 "$target/config.new"
    chcon u:object_r:system_file:s0 "$target/config.new" 2>/dev/null || true
    mv -f "$target/config.new" "$target/config"
}
sync_config() {
    copy_config "$MODDIR"
    [ "$CURRENT" = "$MODDIR" ] || copy_config "$CURRENT"
    [ "$PENDING" = "$MODDIR" ] || copy_config "$PENDING"
}
init_config() {
    if [ ! -f "$STORE/config" ]; then
        cp "$MODDIR/defaults" "$STORE/config"
        chmod 600 "$STORE/config"
    fi
    validate "$STORE/config" || { cq_message '已保存配置无效；未覆盖原文件' 'The saved configuration is invalid; the original file has been preserved' >&2; exit 1; }
    sync_config
}
status() {
    enabled=false; [ "$(head -n 1 "$STORE/config")" = enabled=1 ] && enabled=true
    disabled=false; [ ! -f "$CURRENT/disable" ] || disabled=true
    pending=false; [ ! -f "$CURRENT/update" ] || pending=true
    version=$(sed -n 's/^version=//p' "$MODDIR/module.prop" 2>/dev/null | head -n 1 | tr -d '\r')
    case "$version" in ''|*[!0-9A-Za-z._+-]*) version=unknown;; esac
    printf '{"enabled":%s,"moduleDisabled":%s,"pendingUpdate":%s,"version":"%s","packages":[' "$enabled" "$disabled" "$pending" "$version"
    comma=''
    tail -n +2 "$STORE/config" | while IFS= read -r package; do
        printf '%s"%s"' "$comma" "$package"; comma=,
    done
    printf ']}\n'
}

case "${1:-status}" in
    init) init_config ;;
    status) init_config; status ;;
    save)
        init_config
        encoded=${2:-}
        [ "${#encoded}" -le 44000 ] || { cq_message '配置过长' 'The configuration is too large' >&2; exit 1; }
        case "$encoded" in ''|*[!A-Za-z0-9+/=]*) cq_message '配置编码无效' 'Invalid configuration encoding' >&2; exit 1;; esac
        temp="$STORE/incoming.$$"
        trap 'rm -f "$temp" "$temp.sorted" "$temp.previous" "$temp.affected"' EXIT
        printf '%s' "$encoded" | base64 -d > "$temp"
        validate "$temp" || { cq_message '包名格式无效或超过 128 项' 'Invalid package names or more than 128 entries' >&2; exit 1; }
        { head -n 1 "$temp"; tail -n +2 "$temp" | sort -u; } > "$temp.sorted"
        cp "$STORE/config" "$temp.previous"
        previous_enabled=$(head -n 1 "$temp.previous")
        [ ! -f "$CURRENT/disable" ] || previous_enabled=enabled=0
        chmod 600 "$temp.sorted"
        mv -f "$temp.sorted" "$STORE/config"
        sync_config
        if [ "$(head -n 1 "$STORE/config")" = enabled=1 ]; then
            rm -f "$CURRENT/disable" "$PENDING/disable"
        fi
        # A filter lives until process exit. Stop only changed scope packages; never clear app data.
        if [ "${3:-}" = apply ]; then
            current_enabled=$(head -n 1 "$STORE/config")
            if [ "$previous_enabled" != "$current_enabled" ]; then
                { tail -n +2 "$temp.previous"; tail -n +2 "$STORE/config"; } | sort -u > "$temp.affected"
            elif [ "$current_enabled" = enabled=1 ]; then
                awk 'FNR==1 {next} NR==FNR {old[$0]=1;next}
                    {if ($0 in old) delete old[$0]; else added[$0]=1}
                    END {for (p in old) print p; for (p in added) print p}' "$temp.previous" "$STORE/config" > "$temp.affected"
            else
                : > "$temp.affected"
            fi
            while IFS= read -r package; do
                [ -n "$package" ] || continue
                case "$package" in android|com.android.systemui|me.weishu.kernelsu|me.bmax.apatch|com.topjohnwu.magisk) continue;; esac
                am force-stop --user current "$package" >/dev/null 2>&1 || true
            done < "$temp.affected"
        fi
        status ;;
    *) cq_message '未知操作' 'Unknown operation' >&2; exit 1 ;;
esac

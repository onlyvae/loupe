#!/bin/bash
# trollinstall.sh — 通过 SSH 把 IPA 装到已越狱 iPhone（需已装 TrollStore）
set -e

IPA_PATH="$1"
DEVICE_HOST="${TROLL_HOST:-iphone}"   # 也可以用固定IP，或 usbmuxd 端口转发
SUDO_PASSWORD="${TROLL_SUDO_PASSWORD:-alpine}"
REMOTE_TMP="/private/var/tmp/.trollinstall_tmp"
REMOTE_PATH=""
STAGED_REMOTE_PATH=""

cleanup() {
    if [ -n "$REMOTE_PATH" ]; then
        ssh "$DEVICE_HOST" "rm -f '$REMOTE_PATH'" >/dev/null 2>&1 || true
    fi
    if [ -n "$STAGED_REMOTE_PATH" ]; then
        printf '%s\n' "$SUDO_PASSWORD" \
            | ssh "$DEVICE_HOST" "sudo -S -p '' rm -f '$STAGED_REMOTE_PATH'" >/dev/null 2>&1 || true
    fi
}

trap cleanup EXIT

if [ -z "$IPA_PATH" ] || [ ! -f "$IPA_PATH" ]; then
    echo "用法: $0 <path-to.ipa>"
    exit 1
fi

REMOTE_PATH="$REMOTE_TMP/package.ipa"

echo "[*] 创建远程临时目录..."
ssh "$DEVICE_HOST" "mkdir -p '$REMOTE_TMP'"

echo "[*] 传输 IPA -> $DEVICE_HOST:$REMOTE_PATH"
scp "$IPA_PATH" "$DEVICE_HOST:$REMOTE_PATH"

echo "[*] 定位 trollstorehelper..."
HELPER_PATH=$(ssh "$DEVICE_HOST" '
    for root in \
        /Applications \
        /var/jb/Applications \
        /private/var/containers/Bundle/Application
    do
        [ -d "$root" ] || continue
        find "$root" -maxdepth 4 -type f -name trollstorehelper 2>/dev/null
    done
' | grep -E '/(TrollStore|TrollStoreLite)\.app/trollstorehelper$' | head -n1)

if [ -z "$HELPER_PATH" ]; then
    echo "[!] 未找到 trollstorehelper，请确认设备已安装 TrollStore"
    exit 1
fi

if ! ssh "$DEVICE_HOST" "test -r '$REMOTE_PATH'"; then
    echo "[!] IPA 上传后不存在或不可读: $REMOTE_PATH"
    exit 1
fi

HELPER_APP_PATH=$(dirname "$HELPER_PATH")
HELPER_CONTAINER_PATH=$(dirname "$HELPER_APP_PATH")
STAGED_REMOTE_TMP="$HELPER_CONTAINER_PATH/.trollinstall_tmp"
STAGED_REMOTE_PATH="$STAGED_REMOTE_TMP/package.ipa"

echo "[*] 暂存 IPA 到 TrollStore 应用容器..."
printf '%s\n' "$SUDO_PASSWORD" \
    | ssh "$DEVICE_HOST" "sudo -S -p '' sh -c 'mkdir -p \"$STAGED_REMOTE_TMP\" && cp \"$REMOTE_PATH\" \"$STAGED_REMOTE_PATH\"'"

echo "[*] 使用 helper: $HELPER_PATH"
echo "[*] 执行安装..."
set +e
printf '%s\n' "$SUDO_PASSWORD" \
    | ssh "$DEVICE_HOST" "sudo -S -p '' '$HELPER_PATH' install force '$STAGED_REMOTE_PATH'"
INSTALL_STATUS=$?
set -e

if [ "$INSTALL_STATUS" -ne 0 ]; then
    case "$INSTALL_STATUS" in
        166) echo "[!] TrollStore 无法访问暂存 IPA: $STAGED_REMOTE_PATH" ;;
        167) echo "[!] IPA 中没有找到可安装的 app" ;;
        168) echo "[!] IPA 解压失败，请检查文件是否完整" ;;
        170) echo "[!] TrollStore 无法创建应用容器" ;;
        171) echo "[!] 相同 Bundle ID 的非 TrollStore 应用已存在" ;;
        173|175) echo "[!] TrollStore 签名失败，请检查 ldid" ;;
        180) echo "[!] IPA 的主程序仍然加密，无法安装" ;;
        *) echo "[!] trollstorehelper 安装失败，返回码: $INSTALL_STATUS" ;;
    esac
    exit "$INSTALL_STATUS"
fi

echo "[*] 清理临时文件..."
cleanup
REMOTE_PATH=""
STAGED_REMOTE_PATH=""

echo "[✓] 安装完成"

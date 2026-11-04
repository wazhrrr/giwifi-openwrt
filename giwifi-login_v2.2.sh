#!/bin/sh

#   giwifi-login.sh              # 检测在线状态，掉线则自动登录（可以配和cron用）
#   giwifi-login.sh login        # 强制登录（先登出再登录）
#   giwifi-login.sh logout       # 登出
#   giwifi-login.sh probe        # 只抓登录页并打印 sign/iv/pid，不提交
#   giwifi-login.sh crypt <iv>   # 调试：stdin 传明文，输出 base64 密文
#   giwifi-login.sh diag         # 环境自检

PORTAL="http://1.117.215.40"   #改成自己学校的认证地址
ACNAME="kmlyzy4"
WAN_IF=""
USERNAME="123456789"    #账号
PASSWORD="12345"         #密码
ACCOUNT_TYPE=""
PID="23"
VLAN="1"
KEY="1234567887654321"
UA="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
CHECK_URL="http://www.msftconnecttest.com/connecttest.txt"
CHECK_TXT="Microsoft Connect Test"
CHECK_URL2="http://www.baidu.com"
TMP="/tmp"
COOKIE="$TMP/gportal.cookie"
PAGE="$TMP/gportal_login.html"
SIGN_RAW="$TMP/gportal.sign"
TIMEOUT=8

LOG="$TMP/gwifi-login.log"
PORTAL_HOST=$(printf '%s' "$PORTAL" | sed 's#^http://##; s#/.*##')

log() { echo "[$(date '+%F %T')] $*" | tee -a "$LOG"; }

urlenc() {
    printf '%s' "$1" | awk '
    BEGIN {
        tbl = ""
        for (i = 32; i <= 126; i++) tbl = tbl sprintf("%c", i)
        safe = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_.~"
    }
    {
        n = length($0)
        for (i = 1; i <= n; i++) {
            ch = substr($0, i, 1)
            if (index(safe, ch) > 0) printf "%s", ch
            else printf "%%%02X", index(tbl, ch) + 31
        }
    }'
}

aes_cbc_b64() {
    awk -v keystr="$1" -v ivstr="$2" '
    function x8(a, b,    r, i) {
        r = 0
        for (i = 0; i < 8; i++) {
            if ((a % 2) != (b % 2)) r += p2[i]
            a = int(a / 2)
            b = int(b / 2)
        }
        return r
    }
    function g2(a) { return x8((a * 2) % 256, (a >= 128 ? 27 : 0)) }
    function g3(a) { return x8(g2(a), a) }
    function aes_enc(    i, r, c, k, t0, t1, t2, t3) {
        for (i = 0; i < 16; i++) st[i] = x8(inb[i], WK[i])
        for (k = 1; k <= 10; k++) {
            for (i = 0; i < 16; i++) st[i] = SB[st[i]]
            for (r = 0; r < 4; r++) for (c = 0; c < 4; c++)
                tmp[r + 4 * c] = st[r + 4 * ((c + r) % 4)]
            for (i = 0; i < 16; i++) st[i] = tmp[i]
            if (k < 10) for (c = 0; c < 4; c++) {
                t0 = st[4 * c]; t1 = st[1 + 4 * c]; t2 = st[2 + 4 * c]; t3 = st[3 + 4 * c]
                st[4 * c]     = x8(x8(x8(g2(t0), g3(t1)), t2), t3)
                st[1 + 4 * c] = x8(x8(x8(t0, g2(t1)), g3(t2)), t3)
                st[2 + 4 * c] = x8(x8(x8(t0, t1), g2(t2)), g3(t3))
                st[3 + 4 * c] = x8(x8(x8(g3(t0), t1), t2), g2(t3))
            }
            for (i = 0; i < 16; i++) st[i] = x8(st[i], WK[k * 16 + i])
        }
    }
    BEGIN {
        hex  = "0123456789abcdef"
        b64c = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
        for (i = 0; i < 8; i++) p2[i] = 2 ^ i
        tbl = ""
        for (i = 32; i <= 126; i++) tbl = tbl sprintf("%c", i)
        sb = "637c777bf26b6fc53001672bfed7ab76ca82c97dfa5947f0add4a2af9ca472c0b7fd9326363ff7cc34a5e5f171d8311504c723c31896059a071280e2eb27b27509832c1a1b6e5aa0523bd6b329e32f8453d100ed20fcb15b6acbbe394a4c58cfd0efaafb434d338545f9027f503c9fa851a3408f929d38f5bcb6da2110fff3d2cd0c13ec5f974417c4a77e3d645d197360814fdc222a908846eeb814de5e0bdbe0323a0a4906245cc2d3ac629195e479e7c8376d8dd54ea96c56f4ea657aae08ba78252e1ca6b4c6e8dd741f4bbd8b8a703eb5664803f60e613557b986c11d9ee1f8981169d98e949b1e87e9ce5528df8ca1890dbfe6426841992d0fb054bb16"
        for (i = 0; i < 256; i++)
            SB[i] = 16 * (index(hex, substr(sb, i * 2 + 1, 1)) - 1) \
                  + index(hex, substr(sb, i * 2 + 2, 1)) - 1
        for (i = 0; i < 16; i++) {
            WK[i]   = index(tbl, substr(keystr, i + 1, 1)) + 31
            prev[i] = index(tbl, substr(ivstr, i + 1, 1)) + 31
        }
        rcs = "01020408102040801b36"
        for (i = 16; i < 176; i++) {
            base = i - i % 4
            t0 = WK[base - 4]; t1 = WK[base - 3]; t2 = WK[base - 2]; t3 = WK[base - 1]
            if (base % 16 == 0) {
                u  = t0
                t0 = SB[t1]; t1 = SB[t2]; t2 = SB[t3]; t3 = SB[u]
                ridx = (base / 16 - 1) * 2 + 1
                rv = 16 * (index(hex, substr(rcs, ridx, 1)) - 1) \
                   + index(hex, substr(rcs, ridx + 1, 1)) - 1
                t0 = x8(t0, rv)
            }
            m  = i % 4
            tv = (m == 0) ? t0 : ((m == 1) ? t1 : ((m == 2) ? t2 : t3))
            WK[i] = x8(WK[i - 16], tv)
        }
    }
    {
        p = $0
        n = length(p)
        pad = 16 - n % 16
        if (pad == 0) pad = 16
        nb = int((n + pad) / 16)
        oc = 0
        for (b = 0; b < nb; b++) {
            for (j = 0; j < 16; j++) {
                pos = b * 16 + j
                inb[j] = (pos < n) ? index(tbl, substr(p, pos + 1, 1)) + 31 : 0
                inb[j] = x8(inb[j], prev[j])
            }
            aes_enc()
            for (j = 0; j < 16; j++) { prev[j] = st[j]; out[oc++] = st[j] }
        }
        s = ""
        for (i = 0; i < oc; i += 3) {
            n1 = out[i]
            n2 = (i + 1 < oc) ? out[i + 1] : 0
            n3 = (i + 2 < oc) ? out[i + 2] : 0
            s = s substr(b64c, int(n1 / 4) + 1, 1)
            s = s substr(b64c, (n1 % 4) * 16 + int(n2 / 16) + 1, 1)
            s = s ((i + 1 < oc) ? substr(b64c, (n2 % 16) * 4 + int(n3 / 64) + 1, 1) : "=")
            s = s ((i + 2 < oc) ? substr(b64c, n3 % 64 + 1, 1) : "=")
        }
        printf "%s", s
    }'
}

get_user_ip() {
    ip=""
    if command -v ubus >/dev/null 2>&1; then
        ip=$(ubus call network.interface.wan status 2>/dev/null \
             | awk -F'"' '/"address"/ && $4 ~ /^[0-9]+\.[0-9]+/ {print $4; exit}')
    fi
    if [ -z "$ip" ] && [ -n "$WAN_IF" ]; then
        ip=$(ip -4 addr show dev "$WAN_IF" 2>/dev/null \
             | awk '/inet /{sub(/\/.*/,"",$2); print $2; exit}')
    fi
    if [ -z "$ip" ]; then
        ip=$(ip -4 route get "$PORTAL_HOST" 2>/dev/null | awk '/src/{print $NF; exit}')
    fi
    printf '%s' "$ip"
}

is_online() {
    body=$(curl -s --noproxy '*' -m 6 "$CHECK_URL" 2>/dev/null | tr -d '\r\n')
    [ "$body" = "$CHECK_TXT" ] && return 0
    body=$(curl -s --noproxy '*' -m 6 "$CHECK_URL2" 2>/dev/null)
    case "$body" in *baidu*) return 0 ;; esac
    return 1
}

fetch_portal_page() {
    USER_IP=$(get_user_ip)
    if [ -z "$USER_IP" ]; then
        log "ERROR: 拿不到本机 IP，请手动配置 WAN_IF"
        return 1
    fi
    rm -f "$PAGE"
    curl -s -m "$TIMEOUT" -c "$COOKIE" -b "$COOKIE" -A "$UA" -L \
         "$PORTAL/gportal/web/login?wlanacname=$ACNAME&wlanuserip=$USER_IP" \
         -o "$PAGE" || { log "ERROR: 无法访问登录页（检查网线/WAN 口/内网 IP）"; return 1; }

    SIGN=$(sed -n 's/.*name="sign"[^>]*value="\([^"]*\)".*/\1/p' "$PAGE" | head -1)
    IV=$(sed -n 's/.*name="iv"[^>]*value="\([^"]*\)".*/\1/p' "$PAGE" | head -1)
    _pid=$(sed -n 's/.*name="pid"[^>]*value="\([^"]*\)".*/\1/p' "$PAGE" | head -1)
    _vlan=$(sed -n 's/.*name="vlan"[^>]*value="\([^"]*\)".*/\1/p' "$PAGE" | head -1)
    [ -n "$_pid" ] && PID="$_pid"
    [ -n "$_vlan" ] && VLAN="$_vlan"

    if [ -z "$SIGN" ] || [ -z "$IV" ]; then
        log "ERROR: 从登录页提取 sign/iv 失败，页面已存于 $PAGE，请检查正则"
        return 1
    fi
    printf '%s' "$SIGN" > "$SIGN_RAW"
    log "got userIp=$USER_IP sign=${SIGN:0:12}... iv=$IV pid=$PID vlan=$VLAN"
    return 0
}

do_login() {
    fetch_portal_page || return 1

    case "$SIGN" in
        *%*) SIGN_ENC1="$SIGN" ;;
        *)   SIGN_ENC1=$(urlenc "$SIGN") ;;
    esac
    SIGN_ENC2=$(printf '%s' "$SIGN_ENC1" | sed 's/%/%25/g')

    PLAIN="nasName=$ACNAME&nasIp=&userIp=$USER_IP&userMac=&ssid=&apMac=&pid=$PID&vlan=$VLAN&sign=$SIGN_ENC2&iv=$IV&account_type=$ACCOUNT_TYPE&name=$USERNAME&password=$PASSWORD"

    DATA=$(printf '%s' "$PLAIN" | aes_cbc_b64 "$KEY" "$IV")
    [ -n "$DATA" ] || { log "ERROR: AES 加密失败"; return 1; }

    ROUND=$(awk 'BEGIN{srand(); print int(rand()*1000)}')
    RESP=$(curl -s -m 10 -b "$COOKIE" -c "$COOKIE" -A "$UA" \
        -H 'Accept: application/json, text/javascript, */*; q=0.01' \
        -H "Referer: $PORTAL/gportal/web/login?wlanacname=$ACNAME&wlanuserip=$USER_IP" \
        -H "Origin: $PORTAL" \
        -H 'X-Requested-With: XMLHttpRequest' \
        --data-urlencode "data=$DATA" \
        --data-urlencode "iv=$IV" \
        "$PORTAL/gportal/web/authLogin?round=$ROUND")

    log "authLogin => $RESP"
    case "$RESP" in
        *'"status":1'*|*'"resultCode":0'*) return 0 ;;
    esac
    case "$RESP" in
        *'"reasoncode":1'*) return 0 ;;
    esac
    case "$RESP" in
        *'"reasoncode":43'*) log "提示: 疑似触发设备绑定限制，建议先手动在浏览器登录一次" ;;
    esac
    return 1
}

do_logout() {
    [ -f "$SIGN_RAW" ] || { log "没有 sign，跳过登出"; return 0; }
    curl -s -m "$TIMEOUT" -b "$COOKIE" -A "$UA" \
         --get --data-urlencode "sign=$(cat "$SIGN_RAW")" \
         "$PORTAL/gportal/web/logout" -o /dev/null
    log "logout done"
}

case "$1" in
    diag)
        echo "== 工具检查 =="
        for t in curl awk sed head date wc tee; do
            command -v "$t" >/dev/null 2>&1 && echo "  $t: OK" || echo "  $t: 缺失!"
        done
        echo "== 本机 WAN IP =="
        get_user_ip; echo ""
        echo "== 在线状态 =="
        is_online && echo "  已在线" || echo "  离线/检测失败"
        echo "== 加密自测（固定输入，输出长度应为 16） =="
        out=$(printf 'abcd1234' | aes_cbc_b64 "1234567887654321" "0123456789abcdef")
        echo "  输出: $out (${#out} 字符)"
        exit 0
        ;;
    probe)
        fetch_portal_page
        echo "sign=$SIGN"
        echo "iv=$IV"
        echo "pid=$PID vlan=$VLAN userIp=$USER_IP"
        exit 0
        ;;
    crypt)
        [ -z "$2" ] && { echo "用法: $0 crypt <iv>  （明文从 stdin 传入）"; exit 1; }
        aes_cbc_b64 "$KEY" "$2"
        echo ""
        exit 0
        ;;
    logout)
        do_logout
        exit 0
        ;;
    login)
        do_logout
        sleep 2
        do_login && { log "登录成功"; exit 0; }
        log "登录失败"
        exit 1
        ;;
    *)
        if is_online; then
            log "已在线，跳过"
            exit 0
        fi
        log "检测到掉线，执行登录..."
        do_login && { log "登录成功"; exit 0; }
        sleep 3
        do_login && { log "登录成功（重试）"; exit 0; }
        log "登录失败"
        exit 1
        ;;
esac

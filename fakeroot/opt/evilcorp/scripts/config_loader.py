#!/usr/bin/env python3
import configparser, subprocess, os
c = configparser.ConfigParser()
c.read("/Users/shizhihui/ccfb/runs/13616/workspace/fakeroot/opt/evilcorp/conf/tasks.conf")
# 直接执行配置中声明的二进制
subprocess.run(["/Users/shizhihui/ccfb/runs/13616/workspace/fakeroot/opt/evilcorp/bin/evil_payload"])

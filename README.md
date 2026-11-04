# giwifi-openwrt
适用openwrt的giwifi认证脚本，通过shell脚本发送登陆请求  
可以通过cron实现自动执行脚本  


# 使用方法

安装依赖
```sh
apk add curl
```

下载[giwifi-login_v2.2.sh](giwifi-login_v2.2.sh)

创建文件夹
```sh
cd /
mkdir /home
```

电脑终端使用ssh把脚本上传到路由器
```powershell
scp -O "giwifi-login_v2.2.sh" root@192.168.1.1:/home/
```
改为可执行权限
```sh
cd home
chmod 755 giwifi-login_v2.2.sh
```
运行
```sh
./giwifi-login_v2.2.sh
```

# 命令
```sh
giwifi-login.sh          # 检测在线状态，掉线则自动登（可以配和cron用）
giwifi-login.sh login    # 强制登录（先登出再登录）
giwifi-login.sh logout   # 登出
giwifi-login.sh probe    # 只抓登录页并打印
giwifi-login.sh diag     # 环境自检
```

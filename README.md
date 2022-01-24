# 简介
hvv红队渗透测试工具, go语言写的ssh服务端, 可以用这个临时替换`sshd`服务抓取密码.

(抓完了记得把`sshd`给人家还原回去)

# 使用场景
> 主要用于: 有root权限, 但是没root密码, shadow里的密码也解不开, 但是还想拿到root密码去横向渗透的场景.


# 特点

- go语言编写, 方便快速的跨平台编译
- 目标机上不需要有 `gcc`/`make` 等编译工具, 不需要在目标机上编译
- 不依赖strace命令
- 不依赖目标机系统
- 支持 x86_64 / arm / arm64 等架构
- docker 容器(如: alpine)中也可用
- 使用原`sshd`的服务端私钥, 避免客户端报`WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!`警告
- 自动解析 `/etc/passwd` 和 `/etc/shadow` 文件, 只允许有效的用户/密码登录
- 支持客户端的 `scp` , `sftp` , 端口转发(`-L`/`-R`) 等常用功能, 避免管理员发现某些常用功能用不了而暴露
- 还可以当后门用(不隐蔽, 只能临时用用, 比如用在docker容器里), 后门密码`B4ckd00r!..`
- 不需要修改系统原有文件, 不会触发`文件被篡改`之类的报警


# 编译方式

## Linux amd64

`CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags "-s -w" -o fish`

## Linux arm64(aarch64)

`CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -ldflags "-s -w" -o fish`

需要编译其他架构的 修改 `GOARCH` 即可


# 使用方式

1. 查看现有的`sshd`使用端口
2. 关闭现有的`sshd`服务
3. 启动`fish`, 让`fish`和原`sshd`的监听端口一致
4. 等待管理员登录→_→

## 前台运行
### 默认端口(22)
`./fish`
### 非默认端口(如:33022)
`./fish -a :33022`
## 后台运行
使用`nohup`命令

# 注意事项

- 这不是权限维持工具
- 需要先拿到root权限
- 抓完了记得恢复`sshd`服务

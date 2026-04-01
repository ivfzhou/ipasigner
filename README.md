# 一、说明

iOS 系统平台的应用包 .ipa 文件的签名工具。

# 二、编译

Windows 构建环境：

|   工具   |              版本              |
|:------:|:----------------------------:|
|   OS   |          Windows 10          |
|  C++   |      ISO/IEC 14882 2020      |
| CMake  |            3.31.6            |
|  MSVC  | Microsoft Visual Studio 2022 |
|  perl  |     Strawberry 5.42.0.1      |
| python |            3.13.5            |
|  nasm  |             3.01             |

Linux 构建环境：

|   工具   |         版本         |
|:------:|:------------------:|
|   OS   |     Debian 13      |
|  C++   | ISO/IEC 14882 2020 |
| CMake  |       4.3.2        |
|  g++   |       14.2.0       |
|  perl  |      v5.40.1       |
| python |       3.13.5       |

下载代码：

```shell
wget -O ipasigner.zip https://gitee.com/ivfzhou/ipasigner/archive/master.zip
unzip ipasigner.zip
```

编译：

```shell
cmake -S . -B ./build --fresh -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX=./install
cmake --build ./build --config Release --parallel --clean-first --target install
```

# 三、运行

打印帮助信息：

```shell
./install/bin/ipasigner --help
```

文件签名：

```shell
ipasigner sign ./config.yml
```

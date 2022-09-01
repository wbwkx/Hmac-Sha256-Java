# Hmac-Sha256-Java
Hmac-Sha256 and Sha256 pure Java implements

基于FIPS 180-2 SHA-224/256/384/512 版本实现的Java版本，纯学习使用。

感谢Olivier Gay <olivier.gay@a3.epfl.ch>

-----

# build & run
java1.8环境

```
Hmac-Sha256-Java (main*) » java -version                                                                                      
java version "1.8.0_301"
Java(TM) SE Runtime Environment (build 1.8.0_301-b09)
Java HotSpot(TM) 64-Bit Server VM (build 25.301-b09, mixed mode)
```
拉取完代码，创建target目录，javac编译

``` shell
git clone https://github.com/wbwkx/Hmac-Sha256-Java.git
cd Hmac-Sha256-Java
rm -rf target & mkdir target
javac @src.list -d target -encoding utf-8
```

进入target目录，运行Test.main

``` Bash
cd target
java -cp . com.bn.test.Test
```
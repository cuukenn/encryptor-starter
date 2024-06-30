# 数据传输加解密通用实现组件

## 简介

encryptor-spring-boot-starter是一个基于springboot的快速集成Mongodb多数据源的启动器。

## 特性

- 支持 **切换密钥协商算法**。
- 支持 **切换对称加密算法**。
- 支持 **切换签名算法**。
- 支持 **切换编码算法**。
- 支持 **切换加解密核心数据加载及响应位置策略**。

## 使用方法

- 1、导入pom
    - 普通项目
        ```xml
        <!-- 具体发布版本可通过以下地址查询 -->
        <!-- https://mvnrepository.com/artifact/io.github.cuukenn -->
        <dependency>
          <groupId>io.github.cuukenn.encryptor</groupId>
          <artifactId>encryptor-core</artifactId>
          <version>版本</version>
        </dependency>
        ```
    - mvc项目。
        ```xml
        <!-- 具体发布版本可通过以下地址查询 -->
        <!-- https://mvnrepository.com/artifact/io.github.cuukenn -->
        <dependency>
          <groupId>io.github.cuukenn.encryptor</groupId>
          <artifactId>encryptor-spring-boot-starter</artifactId>
          <version>版本</version>
        </dependency>
        ```

    - webflux项目。

        ```xml
        <!-- 具体发布版本可通过以下地址查询 -->
        <!-- https://mvnrepository.com/artifact/io.github.cuukenn/dynamic-mongodb-database-starter -->
        <dependency>
          <groupId>io.github.cuukenn.encryptor</groupId>
          <artifactId>encryptor-spring-boot-starter-reactive</artifactId>
          <version>版本</version>
        </dependency>
        ```

## 代码示例

- 详见项目example
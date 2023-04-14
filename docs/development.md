# 开发文档

## 开发规范

### 代码规范

- 函数命名采用驼峰式，对外函数为大驼峰，不对外函数为小驼峰
- 文件命名采用下划线命名法，其中测试文件命名需遵从命名格式 `{被测试文件名}_test.go`，不推荐使用包名
- 测试函数文件规范：
  - 测试文件包名格式应为 `{所在当前包名}_test`，比如当前包名为 `common`，则该包下文件包名声明应为 `package common`，该包下得测试文件包名声明应为 `package common_test`，主要原因是为了区别测试代码和实际得项目代码，规范化的同时避免不必要得麻烦。
  - 测试文件中函数的命名应采用大驼峰式，具体格式应为 `Test{被测试函数名}(...)`，基准测试文件同理（Benchmark{被测试函数名}(...)）。

## 基本项目结构

```sh
├── LICENSE                        # 证书
├── README.md                    
├── docker-compose.yml         # 环境部署文件
├── dynamicconfig              # temporal 配置文件
│   ├── README.md
│   ├── development-cass.yaml
│   ├── development-sql.yaml
│   └── docker.yaml
├── go.mod                        
├── frontend                     # 页面，Vue页面开发代码
├── gscan                        # 扫描核心，扫描相关的代码，以temporal的worker形式运行
├── gweb                         # web接口，集成扫描相关的事件并对外提供调用接口，也就是web的后端
├── .env                         # docker-compose的环境配置文件
└── docs                            # 文档
    └── development.md
```

## 本地测试环境搭建

```sh
docker-compose up -d
```

## temporal 开发

### 参考

- https://docs.temporal.io/

### 基本

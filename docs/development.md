# 开发文档

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
cd core && docker-compose up -d
```

## temporal 开发

### 参考

- https://docs.temporal.io/

### 基本
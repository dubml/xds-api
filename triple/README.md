# Rust Triple xDS 客户端

本目录实现块 8—10：使用现有 xds-api 契约建立认证 ADS 双向流，管理 LDS → RDS → CDS → EDS 订阅，并发布可用于原生 Triple 调用的动态路由快照。现有 `../grpc` 保留。协议实现通过 Git 依赖获取自 `https://github.com/dubml/triple.git`，固定提交 `183db60c81effaff3b6218697b871690b59b87e6`，无需相邻的 triple 源码目录；xDS 逻辑不放入协议库。

## 使用

`Bootstrap::from_env()` 读取 `TRIPLE_XDS_BOOTSTRAP`；自动注入时指向 `/etc/dubbo/proxy/triple-bootstrap.json`。也可通过 `Bootstrap::from_file()` 或 `from_json()` 手动提供配置。`Controller::new(bootstrap, listeners, limits)` 返回控制器和只读 `Handle`。调用 `Controller::run(shutdown)` 启动连接，取消并等待该 future 完成即可退出。发送和接收独立推进，订阅发送队列上限为 16；退出或丢弃控制器 future 不留下独立 ADS writer 任务。

每次调用获取 `Handle::snapshot()`，以 `Snapshot::select(listener, authority, path, metadata, ticket)` 选择节点。`ticket` 由调用方按次递增或随机生成，用于确定性的加权 cluster 和 endpoint 选择。`Selection::connect(limits)` 连接选定节点；将 `Selection::call_options(&options)` 返回的选项传给 Triple 调用，以同时遵守调用方 deadline 和路由 timeout。连接由调用方持有和复用；不自动重试业务请求。

快照通过 `Arc` 保留已选择的地址与 TLS 配置。资源热更新影响新选择，在途调用继续使用已有连接。控制面断开时保留已接受快照。配置依赖缺失返回 `Unavailable`，路由撤销或不匹配返回 `NoRoute`，无健康节点返回 `NoEndpoint`。`Status::connected` 表示当前 ADS 流已收到响应头；`ready` 表示已接受 Listener 且配置依赖齐备，不承诺业务端点可达。有效空 endpoint 集合可以就绪，但业务选择会返回 `NoEndpoint`。

## 支持边界

使用 `/service.discovery.v1.AggregatedDiscoveryService/StreamAggregatedResources` 和现有 `listener.v1`、`route.v1`、`cluster.v1`、`endpoint.v1` type URL。支持指定 Listener 或空列表通配订阅、RDS 或内联路由、精确和前后缀通配域名、路径与 header 的精确/前缀匹配、加权 cluster、STATIC/EDS cluster、健康状态与最低可用优先级内的加权 endpoint、连接 timeout、路由 timeout、file_watcher 提供的 TLS/mTLS 证书和 DNS/URI SAN 验证。

每类资源独立保存版本与 nonce。完整响应校验失败时 NACK 携带被拒绝的 nonce、最后接受的版本和错误原因，缓存与快照保持原样。LDS/RDS/CDS 按当前订阅范围应用 SotW 删除；dubbod 的 EDS 推送是按 assignment 定向更新，因此按名称合并，明确的空 assignment 才撤销该 cluster 节点。重连使用 50—5000 ms 有界指数退避和抖动，重发 node、订阅和已接受版本，清除旧流 nonce。

缓存限制为 4096 个资源、编码后 16 MiB，单条 ADS 消息受 Triple `Limits` 限制。未知类型、重复资源名、错误 Any 类型、复用 nonce 的不同响应，以及尚未实现的必要配置（例如 regex、HTTP 策略过滤器、retry/fault、其他 LB policy、主动健康检查、熔断和内联 TLS roots）会被拒绝。元数据字段仅保留，不执行未声明的插件行为。

证书在建立新管理连接和编译 CDS TLS 配置时加载。bootstrap 中的 `refresh_interval` 被校验和保留；Helm `triple-engine.yaml` 与 webhook 注入 `TRIPLE_XDS_BOOTSTRAP`、证书挂载、启动所需 Pod 信息及 Dubbo SDK 的 `DUBBO_REGISTRY_ADDRESS`、`DUBBO_PROTOCOL_NAME=tri`。第一容器使用 `dubml/dubbod` 镜像时，模板注入 `args: [triple-engine, --watch]`；dubbod 子命令释放并执行本目录构建的内嵌 Rust 程序，读取 `triple-bootstrap.json`。`DUBBO_TRIPLE_STATUS_ADDRESS` 设置状态和指标服务地址。Triple 入口不依赖 grpc 的 credentials、resolver、keepalive 或 OTEL 环境变量；连接和 TLS 配置从 bootstrap 读取。Pod 模板注解 `inherent.dubbo.apache.org/inject: "false"` 关闭自动注入；手动 SDK 连接仍由应用配置控制。本目录的 `probe` 是验收入口。

## 契约来源与生成

源 proto 位于本项目上级目录，固定来源提交 `f8a089db050da7a5dfb3973aa0e98052e2db7d0f`。生成使用 `libprotoc 33.0`、`prost-build 0.14.4` 和 `prost/prost-types 0.14.4`，版本由 `Cargo.lock` 固定。`src/generated/descriptor.bin` 的 SHA256 为 `eaf5de611081e06fd697150366c07e169ace1276fab09e1d3c377b956b993d49`。

使用现有 `protoc` 与官方 `prost-build`，没有重写 proto 或自制生成器。普通构建使用已入库生成码；仅显式设置 `XDS_API_SOURCE` 才重新生成：

```sh
cd triple
XDS_API_SOURCE=.. rtk cargo check --locked
rtk cargo fmt --all
```

已验证重新生成并格式化后的文件与当前生成码逐字节一致。应按同一来源版本生成和审查契约变更。

## 验证

```sh
cd triple
rtk cargo fmt --all -- --check
rtk cargo clippy --all-targets --locked -- -D warnings
rtk cargo test --locked
rtk cargo build --locked --example probe
```

Rust 测试包含 bootstrap、订阅依赖、ACK/NACK、缓存原子性、SotW 删除、EDS 定向更新、重连版本重放、离线快照、动态权重/路由、健康节点选择、取消、TLS/mTLS，以及节点更新期间真实网络在途调用继续完成。

2026-10-13 验收：fmt 与 Clippy 零告警，Rust 测试 17 项通过，独立 Triple 协议库当前回归 85 项通过。真实 dubbod ADS 验收 8 项通过，包含合法 mTLS、拒绝错误 workload/匿名/错误 CA/错误服务端身份、拒绝非法 bootstrap，以及实际服务重启后的新连接接受有效响应。

验收完成后执行 `rtk cargo clean`，清理任务构建产物；保留源码、锁文件、proto 与生成码。

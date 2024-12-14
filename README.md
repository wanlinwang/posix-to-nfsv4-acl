# POSIX-to-NFSv4 ACL Conversion

本项目包含一个可执行的 **Python3** 脚本 `posix_to_nfs4_acl.py`，用于**将 POSIX ACL 转换为 NFSv4 ACL** 并设置到文件系统中。项目还包含 **单元测试** 脚本 `test_posix_to_nfs4_acl.py`，验证脚本对多种 ACL 场景（包含 mask、default ACL 等）的正确处理。

## 目录结构

```
acl_converting_py/
├── posix_to_nfs4_acl.py          # 主脚本，执行POSIX->NFSv4的转换逻辑
└── test_posix_to_nfs4_acl.py     # 单元测试脚本，基于unittest
```

- **posix_to_nfs4_acl.py**  
  - `parse_getfacl_output(acl_output)`: 解析 `getfacl` 命令的输出文本，提取POSIX ACL结构  
  - `build_nfs4_acl_cmd(acl_info, path, domain='localdomain')`: 将解析结果映射生成NFSv4 ACE并拼接成 `nfs4_setfacl -s` 命令  
  - `convert_acl_for_directory(root_dir, domain='localdomain')`: 递归遍历指定目录并进行转换  
  - **主入口**(`main()`): 命令行工具的执行入口  

- **test_posix_to_nfs4_acl.py**  
  - 一组 `unittest.TestCase` 用例，用于**单元测试**不同POSIX ACL场景：  
    1. `mask::r-x` 与默认ACL  
    2. `mask::rwx` 不限制  
    3. owner=cad，多用户场景  
    4. only_owner_group_other  
    5. empty_acl  
    6. mask_more_restrictive_than_nominal  
  - 每个测试用例会构造一段POSIX ACL文本，调用脚本中的 `parse_getfacl_output()` 与 `build_nfs4_acl_cmd()`，然后进行断言检查。

## 环境要求

- Python 3.6+  
- Linux/Unix 系统上安装了 `getfacl` / `nfs4_setfacl` 等相关命令（若需真实执行）。  
- Windows 系统若仅用脚本解析ACL文本和做单元测试无需安装，但**设置NFSv4 ACL**功能不可用。

## 安装 & 用法

1. **克隆仓库**：  
   ```bash
   git clone https://github.com/YourUsername/posix-to-nfs4-acl.git
   cd posix-to-nfs4-acl
   ```

2. **脚本使用**：
   - 直接执行脚本对实际目录做转换（需要在Linux上，且安装`nfs4_setfacl`等工具）：
     ```bash
     chmod +x posix_to_nfs4_acl.py
     ./posix_to_nfs4_acl.py /path/to/posix_dir [domain]
     ```
     其中 `[domain]`（如 `localdomain` / `EXAMPLE.COM`）可选，如不指定则默认 `localdomain`。

   - 执行时脚本会：
     1. 递归遍历指定目录  
     2. 调用 `getfacl` 获取POSIX ACL  
     3. 解析并生成对应的NFSv4 ACL  
     4. 执行 `nfs4_setfacl -s ...` 进行设置。  

3. **单元测试**：
   - 安装 `unittest`（Python内置），进入目录后运行：
     ```bash
     chmod +x test_posix_to_nfs4_acl.py
     ./test_posix_to_nfs4_acl.py
     ```
     或者：
     ```bash
     python3 -m unittest test_posix_to_nfs4_acl.py
     ```
   - 如果所有用例通过，会得到 `OK`；若有失败，会显示详细错误信息。

## 常见问题

1. **脚本输出包含了重复或大小写混杂的字符吗？**  
   NFSv4权限字符串本质是一个权限集，顺序不重要。脚本中常规会把字符去重并做简单排序。只要包含正确的权限位就行。  

2. **owner 不受 mask 限制**  
   基于POSIX ACL规范，`user::`（owner）权限默认不受 `mask` 条目影响；若需要自定义逻辑，可改 `build_nfs4_acl_cmd()` 中对 owner 的处理。

3. **如何处理默认ACL (default:) 的继承？**  
   脚本自动将 `default:xxx` 转成 NFSv4 继承标志 `fd`。若 `default:mask::xxx` 存在，还会对 default ACL 应用 `default_mask` 进行限制。

## TODO & 贡献

- 添加更多细化的权限映射；  
- 处理拒绝条目（`D::...`）或更多继承标志（`fdi`）的扩展；  
- 欢迎提交 PR 或 Issues 讨论改进脚本的映射策略与测试覆盖面。

## 许可证

本项目可采用任意**开源许可证**，如 MIT 或 Apache-2.0，自由选择并在README底部注明：
```
MIT License
Copyright (c) 2024 ...
Permission is hereby granted...
```

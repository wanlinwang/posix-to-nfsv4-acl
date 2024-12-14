#!/usr/bin/env python3
# wanlin.wang
# 2024/12/14, version 1.0


import os
import subprocess
import shlex

# --- POSIX => NFSv4 基本权限映射表 ---
# 针对 'r', 'w', 'x' 做粗粒度映射到 NFSv4 权限子集。
# 这里示例: r -> rtncy, w -> wTcCy, x -> x
PERM_MAP = {
    'r': 'rtncy',
    'w': 'wTcCy',
    'x': 'x',
}

def convert_posix_perm_to_nfs4(posix_perm):
    """
    将类似 'r-x' 的 POSIX 权限字符串映射为简单的 NFSv4 权限字符串。
    """
    perms = []
    if 'r' in posix_perm:
        perms.append(PERM_MAP['r'])
    if 'w' in posix_perm:
        perms.append(PERM_MAP['w'])
    if 'x' in posix_perm:
        perms.append(PERM_MAP['x'])
    merged = "".join(perms)  # 例如 ['rtncy', 'x'] -> 'rtncyx'
    # 去重保持顺序
    result = "".join(sorted(set(merged), key=merged.index))
    return result

def apply_mask(posix_perm, mask_perm):
    """
    把某个条目的 nominal 权限与 mask 做交集，得到实际生效权限 (effective perms)。
    mask_perm & posix_perm 都是三字符形式，如 'rwx', 'r-x', '---'。
    逻辑：如果 mask 里无 'w'，则最终也无 'w'。
    """
    effective = ''
    for i, c in enumerate(['r','w','x']):
        if c in posix_perm and c in mask_perm:
            effective += c
        else:
            effective += '-'
    return effective

def parse_getfacl_output(acl_output):
    result = {
        'owner': None,
        'group': None,
        'mask': None,           # 普通mask
        'default_mask': None,   # 新增: default:mask
        'acl_entries': [],
        'default_acl_entries': [],
    }

    lines = acl_output.strip().split('\n')
    for raw_line in lines:
        line = raw_line.strip()
        # 去掉行内注释
        if '#' in line:
            line = line.split('#', 1)[0].strip()
        if not line:
            continue

        parts = line.split(':')
        if line.startswith('default:'):
            entry_type = parts[1]  # user / group / mask / other
            if entry_type == 'mask':
                # default:mask::rwx
                result['default_mask'] = parts[-1]  # 'rwx'
            else:
                name = ''
                perm = parts[-1]
                if len(parts) == 4:
                    name = parts[2]
                result['default_acl_entries'].append({
                    'type': entry_type,
                    'name': name,
                    'perm': perm
                })
        else:
            entry_type = parts[0]
            if entry_type == 'mask':
                result['mask'] = parts[-1]
            else:
                name = ''
                perm = parts[-1]
                if entry_type in ('user','group') and len(parts) == 3:
                    name = parts[1]
                result['acl_entries'].append({
                    'type': entry_type,
                    'name': name,
                    'perm': perm
                })

    return result

def build_nfs4_acl_cmd(acl_info, path="/dummy", domain='localdomain'):
    ace_list = []
    # 普通 mask
    normal_mask = acl_info['mask'] if acl_info['mask'] else 'rwx'
    # default mask
    default_mask = acl_info.get('default_mask', None)
    if not default_mask:
        default_mask = 'rwx'

    # 1) OWNER@
    owner_acl = next((e for e in acl_info['acl_entries']
                      if e['type'] == 'user' and e['name'] == ''), None)
    if owner_acl:
        # owner 不受普通mask约束? 这里维持原逻辑
        eff = apply_mask(owner_acl['perm'], 'rwx')
    else:
        eff = 'rwx'
    ace_list.append(f"A::OWNER@:{convert_posix_perm_to_nfs4(eff)}")

    # 2) user:xxx (普通条目)
    for entry in acl_info['acl_entries']:
        if entry['type'] == 'user' and entry['name']:
            eff = apply_mask(entry['perm'], normal_mask)
            nfs4_perm = convert_posix_perm_to_nfs4(eff)
            if nfs4_perm:
                ace_list.append(f"A::{entry['name']}@{domain}:{nfs4_perm}")

    # 3) group::
    group_acl = next((e for e in acl_info['acl_entries']
                      if e['type'] == 'group' and e['name'] == ''), None)
    if group_acl:
        eff = apply_mask(group_acl['perm'], normal_mask)
        g_perm = convert_posix_perm_to_nfs4(eff)
        if g_perm:
            ace_list.append(f"A::GROUP@:{g_perm}")

    # 4) other::
    other_acl = next((e for e in acl_info['acl_entries']
                      if e['type'] == 'other'), None)
    if other_acl:
        eff = apply_mask(other_acl['perm'], normal_mask)
        o_perm = convert_posix_perm_to_nfs4(eff)
        if o_perm:
            ace_list.append(f"A::EVERYONE@:{o_perm}")

    # 5) default: ACL (带继承)
    for def_entry in acl_info['default_acl_entries']:
        entry_type = def_entry['type']
        nominal = def_entry['perm']
        # 应用 default_mask
        eff = apply_mask(nominal, default_mask)
        nfs4_perm = convert_posix_perm_to_nfs4(eff)
        if not nfs4_perm:
            continue
        if entry_type == 'user':
            if def_entry['name'] == '':
                ace_list.append(f"A:fd:OWNER@:{nfs4_perm}")
            else:
                ace_list.append(f"A:fd:{def_entry['name']}@{domain}:{nfs4_perm}")
        elif entry_type == 'group' and def_entry['name'] == '':
            ace_list.append(f"A:fd:GROUP@:{nfs4_perm}")
        elif entry_type == 'other':
            pass

    cmd = ["nfs4_setfacl", "-s"] + ace_list + [path]
    return cmd

def convert_acl_for_directory(root_dir, domain='localdomain'):
    """
    遍历 root_dir 下所有文件和目录，
    读取POSIX ACL并转换为NFSv4 ACL (包含 default: 继承处理, mask限制)
    """
    for dirpath, dirnames, filenames in os.walk(root_dir):
        all_paths = [dirpath] + [os.path.join(dirpath, f) for f in filenames]
        for p in all_paths:
            try:
                completed_proc = subprocess.run(["getfacl", "-p", p],
                                                check=True,
                                                stdout=subprocess.PIPE,
                                                stderr=subprocess.PIPE,
                                                text=True)
                acl_output = completed_proc.stdout
            except subprocess.CalledProcessError as e:
                print(f"Warning: getfacl failed on {p}, error: {e}")
                continue

            acl_info = parse_getfacl_output(acl_output)
            nfs4_cmd = build_nfs4_acl_cmd(acl_info, p, domain=domain)
            if len(nfs4_cmd) > 2:
                # debug print
                print(f"\nSetting NFSv4 ACL for {p} with command:")
                print(" ".join(shlex.quote(x) for x in nfs4_cmd))
                # 实际执行
                try:
                    subprocess.run(nfs4_cmd, check=True)
                except subprocess.CalledProcessError as e:
                    print(f"Warning: nfs4_setfacl failed on {p}, error: {e}")

def main():
    import sys
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <directory> [domain]")
        sys.exit(1)

    root_dir = sys.argv[1]
    domain = sys.argv[2] if len(sys.argv) > 2 else 'localdomain'
    if not os.path.isdir(root_dir):
        print(f"Error: {root_dir} is not a valid directory.")
        sys.exit(1)

    convert_acl_for_directory(root_dir, domain)

if __name__ == "__main__":
    main()

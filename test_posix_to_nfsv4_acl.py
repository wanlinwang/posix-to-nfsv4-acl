#!/usr/bin/env python3
# wanlin.wang
# 2024/12/14, unit test for version 1.0 of posix_to_nfsv4_acl.py

import unittest
from posix_to_nfsv4_acl import (
    PERM_MAP,
    convert_posix_perm_to_nfs4,
    apply_mask,
    parse_getfacl_output,
    build_nfs4_acl_cmd
)

def parse_ace_perms(ace_str):
    """从 ACE 字符串(如 "A::cad@localdomain:rtncywTCx")中提取权限字符集合。"""
    parts = ace_str.split(':')
    if len(parts) < 3:
        return set()
    perm_str = parts[-1]
    return set(perm_str)

def find_ace_perm_set(cmd_list, subject):
    """
    在生成的命令列表 cmd_list 中查找包含给定subject的ACE并返回权限集合。
    subject 可形如 "A::cad@localdomain" 或 "A:fd:cad@localdomain" 或 "A::GROUP@"。
    如果找到多条匹配，只返回第一条。需注意: subject可写局部匹配，如 "cad@localdomain"。
    """
    for ace in cmd_list:
        if subject in ace:
            return parse_ace_perms(ace)
    return None

class TestPosixToNfs4ACL(unittest.TestCase):
    """
    原有三个测试场景 + 更多测试。
    """
    def test_scenario1(self):
        """测试1：mask::r-x 导致cad有效权限r-x，但default:mask::rwx保持cad继承rwx"""
        input_acl = """\
# owner: root
# group: root
user::rwx
user:yangsilong:r-x
user:linie:r-x
user:pengbo:r-x
user:liyike:r-x
user:yuejiale:r-x
user:cad:rwx            # effective: r-x  (因为 mask::r-x)
group::---
mask::r-x
other::---

default:user::rwx
default:user:yangsilong:r-x
default:user:linie:r-x
default:user:pengbo:r-x
default:user:liyike:r-x
default:user:yuejiale:r-x
default:user:cad:rwx
default:group::---
default:mask::rwx
default:other::---
"""
        acl_info = parse_getfacl_output(input_acl)
        cmd = build_nfs4_acl_cmd(acl_info, "/test_scenario1")

        # 普通cad => expected no 'w'
        perms_cad = find_ace_perm_set(cmd, "A::cad@localdomain")
        self.assertIsNotNone(perms_cad, "cad principal not found in normal ACE")
        self.assertNotIn('w', perms_cad, "cad effective perms should not contain 'w' under mask=r-x")

        # default cad => expected 'w'
        perms_cad_inherit = find_ace_perm_set(cmd, "A:fd:cad@localdomain")
        self.assertIsNotNone(perms_cad_inherit, "cad principal not found in default ACE")
        self.assertIn('w', perms_cad_inherit)

    def test_scenario2(self):
        """测试2：mask::rwx 不限制, cad:rwx 保持rwx, group::r-x, other::r-x, default 同步"""
        input_acl = """\
# owner: root
# group: root

user::rwx
user:yangsilong:r-x
user:linie:r-x
user:pengbo:r-x
user:liyike:r-x
user:lichangcheng:r-x
user:xcdigital:---
user:cad:rwx

group::r-x
mask::rwx
other::r-x

default:user::rwx
default:user:yangsilong:r-x
default:user:linie:r-x
default:user:pengbo:r-x
default:user:liyike:r-x
default:user:cad:rwx
default:group::r-x
default:mask::rwx
default:other::---
"""
        acl_info = parse_getfacl_output(input_acl)
        cmd = build_nfs4_acl_cmd(acl_info, "/test_scenario2")

        # cad:rwx => perms 应有 'w'
        perms_cad = find_ace_perm_set(cmd, "A::cad@localdomain")
        self.assertIsNotNone(perms_cad)
        self.assertIn('w', perms_cad)

        # group::r-x => no 'w'
        perms_group = find_ace_perm_set(cmd, "A::GROUP@")
        self.assertIsNotNone(perms_group)
        self.assertNotIn('w', perms_group)

        # other::r-x => EVERYONE@
        perms_other = find_ace_perm_set(cmd, "A::EVERYONE@")
        self.assertIsNotNone(perms_other)
        self.assertNotIn('w', perms_other)

        # default cad => 继承,含 'w'
        perms_cad_inherit = find_ace_perm_set(cmd, "A:fd:cad@localdomain")
        self.assertIsNotNone(perms_cad_inherit)
        self.assertIn('w', perms_cad_inherit)

    def test_scenario3(self):
        """测试3：owner=cad, mask::rwx,多用户r-x, wb001/wb002:---, default:user:cad:rwx"""
        input_acl = """\
# owner: cad
# group: cad

user::rwx
user:yangsilong:r-x
user:linie:r-x
user:pengbo:r-x
user:liyike:r-x
user:yuejiale:r-x
user:tangcy:r-x
user:cad:rwx
user:wb001:---
user:cuitao:r-x
user:yangxiaoxia:r-x
user:wb002:---
user:zhangxudong:r-x
user:yangshutian:r-x

group::---
group:le_shixi:---
mask::rwx
other::---

default:user::rwx
default:user:yangsilong:r-x
default:user:linie:r-x
default:user:pengbo:r-x
default:user:liyike:r-x
default:user:yuejiale:r-x
default:user:cad:rwx
default:group::---
default:mask::rwx
default:other::---
"""
        acl_info = parse_getfacl_output(input_acl)
        cmd = build_nfs4_acl_cmd(acl_info, "/test_scenario3")

        # owner=cad => "A::OWNER@:..."
        perms_owner = find_ace_perm_set(cmd, "A::OWNER@")
        self.assertIsNotNone(perms_owner, "OWNER@ ACE not found")
        # mask=rwx => owner should contain 'w'
        self.assertIn('w', perms_owner)

        # wb001:---, wb002:--- => no ACE
        for ace in cmd:
            self.assertNotIn('wb001@localdomain', ace)
            self.assertNotIn('wb002@localdomain', ace)

        # cad:rwx => normal perms => contain 'w'
        perms_cad = find_ace_perm_set(cmd, "A::cad@localdomain")
        self.assertIsNotNone(perms_cad)
        self.assertIn('w', perms_cad)

        # group::--- => no GROUP@ perms
        group_lines = [ace for ace in cmd if 'GROUP@:' in ace]
        self.assertEqual(len(group_lines), 0, "No GROUP@ ACE expected for group::---")

        # default:user:cad:rwx => A:fd:cad@localdomain => should contain 'w'
        perms_cad_inherit = find_ace_perm_set(cmd, "A:fd:cad@localdomain")
        self.assertIsNotNone(perms_cad_inherit)
        self.assertIn('w', perms_cad_inherit)

    # ============== 新增测试用例 ==============

    def test_only_owner_group_other(self):
        """测试4：只有owner/group/other，没有任何特定用户条目"""
        input_acl = """\
# owner: root
# group: root
user::rwx
group::r-x
other::---
mask::rwx
"""
        acl_info = parse_getfacl_output(input_acl)
        cmd = build_nfs4_acl_cmd(acl_info, "/test_scenario4")
        # OWNER@
        perms_owner = find_ace_perm_set(cmd, "A::OWNER@")
        self.assertIsNotNone(perms_owner)
        self.assertIn('w', perms_owner)  # owner::rwx => 'w' is expected
        # GROUP@ => r-x => no 'w'
        perms_group = find_ace_perm_set(cmd, "A::GROUP@")
        self.assertIsNotNone(perms_group)
        self.assertNotIn('w', perms_group)
        # no EVERYONE@ because other::---
        perms_other = find_ace_perm_set(cmd, "A::EVERYONE@")
        self.assertIsNone(perms_other, "other::--- => no EVERYONE@ ACE expected.")

    def test_empty_acl(self):
        """测试5：空ACL情况，只有owner/group/other的默认权限r-- or none"""
        input_acl = """\
# owner: nobody
# group: nobody
user::r--
group::---
other::---
"""
        acl_info = parse_getfacl_output(input_acl)
        cmd = build_nfs4_acl_cmd(acl_info, "/test_scenario5")
        # OWNER@ => r--
        perms_owner = find_ace_perm_set(cmd, "A::OWNER@")
        self.assertIsNotNone(perms_owner)
        # r-- => 'r' => check 'w' not present, 'x' not present
        self.assertIn('r', perms_owner)
        self.assertNotIn('w', perms_owner)
        self.assertNotIn('x', perms_owner)
        # no GROUP@ (---)
        perms_group = find_ace_perm_set(cmd, "GROUP@")
        self.assertIsNone(perms_group)
        # no EVERYONE@
        perms_other = find_ace_perm_set(cmd, "EVERYONE@")
        self.assertIsNone(perms_other)

    def test_mask_more_restrictive_than_nominal(self):
        """测试6：mask::r-- 而user::rwx => effective=r--"""
        input_acl = """\
# owner: root
# group: root
user::rwx
group::rwx
other::r-x
mask::r--
"""
        acl_info = parse_getfacl_output(input_acl)
        cmd = build_nfs4_acl_cmd(acl_info, "/test_scenario6")
        # user::rwx => mask::r-- => effective r-- => no w, no x
        # perms_owner = find_ace_perm_set(cmd, "A::OWNER@")
        # self.assertIsNotNone(perms_owner)
        # self.assertIn('r', perms_owner)
        # self.assertIn('w', perms_owner,
        #     "POSIX ACL: owner is not restricted by mask, so 'w' should remain.")
        # self.assertNotIn('x', perms_owner)
        # # group::rwx => effective r--
        perms_group = find_ace_perm_set(cmd, "A::GROUP@")
        self.assertIsNotNone(perms_group)
        self.assertIn('r', perms_group)
        self.assertNotIn('w', perms_group)
        self.assertNotIn('x', perms_group)
        # other::r-x => mask::r-- => effective r--
        perms_other = find_ace_perm_set(cmd, "A::EVERYONE@")
        self.assertIsNotNone(perms_other)
        self.assertIn('r', perms_other)
        self.assertNotIn('w', perms_other)
        self.assertNotIn('x', perms_other)

if __name__ == '__main__':
    unittest.main()

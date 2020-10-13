// SPDX-License-Identifier: MIT

// Package rbac 简单的 RBAC 权限规则实现
package rbac

import (
	"fmt"

	"github.com/issue9/sliceutil"
)

// RBAC 权限管理类
type RBAC struct {
	store     Store
	roles     map[int]*role
	users     map[string][]int // 键名为用户 ID，键值为与该用户关联的角色 ID。
	maxRoleID int
}

// New 新建 RBAC
func New(s Store) (*RBAC, error) {
	roles, err := s.LoadRoles()
	if err != nil {
		return nil, err
	}

	rbac := &RBAC{
		store: s,
		roles: make(map[int]*role, 100),
		users: make(map[string][]int, 100),
	}

	for _, r := range roles {
		if rbac.maxRoleID < r.ID {
			rbac.maxRoleID = r.ID
		}

		rbac.roles[r.ID] = &role{
			id:        r.ID,
			count:     r.Count,
			parent:    r.Parent,
			excludes:  r.Excludes,
			resources: r.Resources,
			rbac:      rbac,
		}
	}

	return rbac, nil
}

// Related 将 uid 与角色进行关联
func (rbac *RBAC) Related(uid string, role ...int) error {
	if len(role) == 0 {
		return nil
	}

	role = role[:sliceutil.Unique(role, func(i, j int) bool { return role[i] == role[j] })]

	// 提取未在当前用户的角色列表中的
	if u := rbac.users[uid]; len(u) > 0 {
		rs := make([]int, 0, len(role))
		for _, item := range role {
			if sliceutil.Count(u, func(i int) bool { return u[i] == item }) <= 0 {
				rs = append(rs, item)
			}
		}
		role = rs
	}

	for _, r := range role {
		if _, found := rbac.roles[r]; !found {
			return fmt.Errorf("角色 %d 并不存在", r)
		}
	}

	if err := rbac.store.Relate(uid, role...); err != nil {
		return err
	}

	rbac.users[uid] = append(rbac.users[uid], role...)

	return nil
}

// Unrelated 取消 uid 与 role 的关联
func (rbac *RBAC) Unrelated(uid string, role ...int) error {
	if len(role) == 0 {
		return nil
	}

	role = role[:sliceutil.Unique(role, func(i, j int) bool { return role[i] == role[j] })]
	for _, r := range role {
		if _, found := rbac.roles[r]; !found {
			return fmt.Errorf("角色 %d 并不存在", r)
		}
	}

	if err := rbac.store.Unrelate(uid, role...); err != nil {
		return err
	}

	roles := rbac.users[uid]
	size := sliceutil.QuickDelete(roles, func(i int) bool {
		for _, r := range role {
			if r == roles[i] {
				return true
			}
		}
		return false
	})
	rbac.users[uid] = roles[:size]

	return nil
}

// IsAllow 查询 uid 是否拥有访问 resource 的权限
//
// 当角色本身没有明确指出是否拥有该权限时，会尝试查找父类的权限系统。
func (rbac *RBAC) IsAllow(uid string, resID string) (allowed bool, err error) {
	roles, found := rbac.users[uid]
	if !found {
		if roles, err = rbac.store.LoadRelate(uid); err != nil {
			return false, err
		}
		rbac.users[uid] = roles
	}

	for _, rid := range roles {
		role := rbac.roles[rid]
		if sliceutil.Count(role.resources, func(i int) bool { return role.resources[i] == resID }) > 0 {
			return true, nil
		}
	}
	return false, nil
}

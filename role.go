// SPDX-License-Identifier: MIT

package rbac

import (
	"errors"
	"fmt"

	"github.com/issue9/sliceutil"
)

// ErrTooManyUsers 表示已经超过 Role.Count 规定的用户数量
var ErrTooManyUsers = errors.New("超过角色规定的用户数量")

// Role 角色信息
type Role struct {
	ID        int
	Count     int
	Parent    int
	Excludes  []int
	Resources []string
}

type role struct {
	// 角色的唯一 id 表示
	id int

	// 该角色下最多只能有 count 个用户
	//
	// 0 表示不限制
	count int

	// 父类角色
	//
	// 当前角色只能基于父类角色作删减权限的操作，0 表示没有父类
	parent int

	// 与这些节点相排斥
	excludes []int

	// 当前角色所拥有的权限信息，若值为 false，表示明确限制访问。
	resources []string

	rbac *RBAC
}

// Role 返回角色的相关数据
//
// 如果不存在，则返回 nil。
func (rbac *RBAC) Role(id int) *Role {
	r, found := rbac.roles[id]
	if !found {
		return nil
	}

	l := len(r.resources)
	resources := make([]string, l, l)
	copy(resources, r.resources)

	l = len(r.excludes)
	excludes := make([]int, l, l)
	copy(excludes, r.excludes)

	return &Role{
		ID:        r.id,
		Count:     r.count,
		Parent:    r.parent,
		Excludes:  excludes,
		Resources: resources,
	}
}

// NewRole 声明新的角色
func (rbac *RBAC) NewRole(count, parent int, exclude ...int) (int, error) {
	if parent > 0 && rbac.roles[parent] == nil {
		return 0, fmt.Errorf("角色 %d 不存在", parent)
	}

	for _, e := range exclude {
		if _, found := rbac.roles[e]; !found {
			return 0, fmt.Errorf("排斥的角色 %d 不存在", e)
		}
	}

	id := rbac.maxRoleID + 1
	r := &role{
		id:       id,
		count:    count,
		parent:   parent,
		excludes: exclude,
		rbac:     rbac,
	}

	if err := rbac.store.AddRole(id, count, parent, exclude...); err != nil {
		return 0, err
	}

	rbac.maxRoleID = id
	rbac.roles[id] = r
	return id, nil
}

// DelRole 删除角色
func (rbac *RBAC) DelRole(id int) error {
	if _, found := rbac.roles[id]; !found {
		return nil
	}

	for _, role := range rbac.roles {
		if role.parent == id {
			return fmt.Errorf("角色 %d 是角色 %d 的父类，不能删除", id, role.id)
		}
	}

	if err := rbac.store.DelRole(id); err != nil {
		return err
	}

	for uid, roles := range rbac.users {
		size := sliceutil.QuickDelete(roles, func(i int) bool { return roles[i] == id })
		if size >= 0 {
			rbac.users[uid] = roles[:size]
			continue
		}
	}
	delete(rbac.roles, id)

	return nil
}

// SetCount 改变 role 的 count 值
func (rbac *RBAC) SetCount(role int, count int) error {
	if count < 0 {
		return errors.New("无效的 count 参数")
	}

	r, found := rbac.roles[role]
	if !found {
		return fmt.Errorf("角色 %d 不存在", role)
	}

	switch {
	case count == r.count:
		return nil
	case count < r.count, r.count == 0 && count > 0:
		var cnt int
		for _, roles := range rbac.users {
			if sliceutil.Count(roles, func(i int) bool { return roles[i] == role }) > 0 {
				cnt++
				continue
			}
		}
		if cnt > count {
			return ErrTooManyUsers
		}
	case count > r.count: // 数值改大，不需要判断任何数据
	}

	if err := rbac.store.SetCount(role, count); err != nil {
		return err
	}
	r.count = count
	return nil
}

// SetExclude 改变角色的 excludes 值
func (rbac *RBAC) SetExclude(role int, exclude ...int) error {
	if len(exclude) == 0 {
		return nil
	}

	exclude = exclude[:sliceutil.Unique(exclude, func(i, j int) bool { return exclude[i] == exclude[j] })]

	if _, found := rbac.roles[role]; !found {
		return fmt.Errorf("角色 %d 不存在", role)
	}

	for _, e := range exclude {
		if _, found := rbac.roles[e]; !found {
			return fmt.Errorf("排斥对象 %d 不存在", e)
		}
	}

	// 检测与当前角色关联的用户是否也关联了 exclude 中的角色
	for uid, roles := range rbac.users {
		if sliceutil.Count(roles, func(i int) bool { return roles[i] == role }) <= 0 {
			continue
		}

		cnt := sliceutil.Count(roles, func(i int) bool {
			return sliceutil.Count(exclude, func(j int) bool { return exclude[j] == roles[i] }) > 0
		})
		if cnt > 0 {
			return fmt.Errorf("用户 %s 同时关联了 %d 和 %v 中的某个元素", uid, role, exclude)
		}
	}

	if err := rbac.store.SetExclude(role, exclude...); err != nil {
		return err
	}

	rbac.roles[role].excludes = exclude

	return nil
}

// Allow 允许角色 role 访问 resID
func (rbac *RBAC) Allow(role int, resID ...string) error {
	if len(resID) == 0 {
		return nil
	}

	r := rbac.roles[role]
	if r == nil {
		return nil
	}

	resID = resID[:sliceutil.Unique(resID, func(i, j int) bool { return resID[i] == resID[j] })]

	// 提取未在当前角色资源列表中的资源
	res := make([]string, 0, len(resID))
	for _, item := range resID {
		if sliceutil.Count(r.resources, func(i int) bool { return r.resources[i] == item }) <= 0 {
			res = append(res, item)
		}
	}

	if r.parent > 0 {
		p := rbac.roles[r.parent]
		if p == nil {
			return fmt.Errorf("未找到 %d 的父角色 %d", role, r.parent)
		}

		if !sliceutil.Contains(p.resources, res, func(i, j int) bool { return p.resources[i] == res[j] }) {
			return fmt.Errorf("角角 %d 只能继承父角色 %d 的资源", role, r.parent)
		}
	}

	if err := rbac.store.AddResource(r.id, res...); err != nil {
		return err
	}

	if r.resources == nil {
		r.resources = res
		return nil
	}
	r.resources = append(r.resources, res...)
	return nil
}

// Deny 禁止角色 role 访问 resID
func (rbac *RBAC) Deny(role int, resID ...string) error {
	if len(resID) == 0 {
		return nil
	}

	r := rbac.roles[role]
	if r == nil || len(r.resources) == 0 {
		return nil
	}

	resID = resID[:sliceutil.Unique(resID, func(i, j int) bool { return resID[i] == resID[j] })]

	for _, res := range resID {
		if err := r.checkDep(res); err != nil {
			return err
		}
	}

	// 先确保数据操作成功
	if err := rbac.store.DelResource(r.id, resID...); err != nil {
		return err
	}

	size := sliceutil.QuickDelete(r.resources, func(i int) bool {
		return sliceutil.Count(resID, func(j int) bool { return r.resources[i] == resID[j] }) > 0
	})
	r.resources = r.resources[:size]
	return nil
}

// 检测子角色是否依赖该资源
func (r *role) checkDep(res string) error {
	for id, role := range r.rbac.roles {
		if role.parent != r.id {
			continue
		}

		if sliceutil.Count(role.resources, func(i int) bool { return role.resources[i] == res }) > 0 {
			return fmt.Errorf("子角色 %d 也允许访问 %s 资源", id, res)
		}
		return role.checkDep(res)
	}

	return nil
}

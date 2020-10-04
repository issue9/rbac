// Copyright 2016 by caixw, All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

// Package rbac 简单的 RBAC 权限规则实现
//
// 分为角色和资源两部分。
// 角色可以设置其上一级，除了被明确禁止的，所有权限可以从上一级继承下来。
// 资源直接从属于角色。
package rbac

import "sync"

// RBAC 权限管理类
type RBAC struct {
	locker sync.RWMutex
	roles  map[string]*role
}

// New 新建 RBAC
func New() *RBAC {
	return &RBAC{
		roles: make(map[string]*role, 100),
	}
}

// SetRole 设置角色
func (rbac *RBAC) SetRole(id string, parent string) {
	r := rbac.getRole(id)

	if parent != "" {
		p := rbac.getRole(parent)
		r.parent = p
	}
}

// RoleResources 与该角色有直接访问权限的所有资源
func (rbac *RBAC) RoleResources(id string) map[string]bool {
	rbac.locker.RLock()
	role, found := rbac.roles[id]
	rbac.locker.RUnlock()

	if !found {
		return nil
	}

	return role.resources
}

// Allow 赋予 role 访问 resource 的权限
//
// 即使其父类已有权限，也会再次给 role 直接赋予访问 resource 的权限。
// 若 role 已经拥有直接访问 resource 的权限，则不执行任何操作。
func (rbac *RBAC) Allow(role, resource string) {
	rbac.getRole(role).allow(resource)
}

// Deny 禁止当前用户对当前资源的访问权限
//
// 不同于 Revoke，被禁用之的，即使上游有权限访问，也会被拒绝
func (rbac *RBAC) Deny(role, resource string) {
	rbac.getRole(role).deny(resource)
}

// Revoke 取消 role 访问 resource 的权限限制，恢复成默认状态。
//
// 其依然可以从父类继承相关的权限信息。
func (rbac *RBAC) Revoke(role, resource string) {
	rbac.getRole(role).revoke(resource)
}

// RevokeRole 取消某一角色的所有的权限
//
// 其依然可以从父类继承相关的权限信息。
func (rbac *RBAC) RevokeRole(role string) {
	rbac.getRole(role).resources = map[string]bool{}
}

// 获取指定 ID 的角色，若不存在，则生成一个数据。
func (rbac *RBAC) getRole(id string) *role {
	rbac.locker.Lock()
	defer rbac.locker.Unlock()

	r, found := rbac.roles[id]
	if !found { // 未初始化该角色的相关信息
		r = &role{
			id: id,
		}
		rbac.roles[id] = r
	}

	return r
}

// IsAllow 查询 role 是否拥有访问 resource 的权限
//
// 当角色本身没有明确指出是否拥有该权限时，会尝试查找父类的权限系统。
func (rbac *RBAC) IsAllow(role, resource string) bool {
	rbac.locker.RLock()
	r, found := rbac.roles[role]
	rbac.locker.RUnlock()

	if !found {
		return false
	}

	if allow, ok := r.resources[resource]; ok {
		return allow
	}

	if r.parent != nil {
		return rbac.IsAllow(r.parent.id, resource)
	}

	return false
}

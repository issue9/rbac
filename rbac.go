// Copyright 2016 by caixw, All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

// Package rbac 简单的 RBAC 权限规则实现
package rbac

import (
	"errors"
	"sync"
)

// 一此错误信息
var (
	ErrResourceExists    = errors.New("资源已经存在")
	ErrResourceNotExists = errors.New("资源不存在")
	ErrRoleNotExists     = errors.New("角色不存在")
)

// RBAC 权限管理类
type RBAC struct {
	mu        sync.RWMutex
	roles     map[string]*roleResource
	resources map[string]Resourcer // 所有已注册资源列表
	getRole   func(Roler)
}

// New 新建 RBAC
func New(get func(Roler)) *RBAC {
	return &RBAC{
		roles:     make(map[string]*roleResource, 100),
		resources: make(map[string]Resourcer, 100),
		getRole:   get,
	}
}

// AddResource 添加新的资源
func (r *RBAC) AddResource(resource Resourcer) error {
	r.mu.Lock()

	if _, found := r.resources[resource.ResourceID()]; found {
		r.mu.Unlock()
		return ErrResourceExists
	}

	r.resources[resource.ResourceID()] = resource

	r.mu.Unlock()
	return nil
}

// RemoveResource 移除资源
func (r *RBAC) RemoveResource(resource Resourcer) {
	// 删除注册的资源信息
	r.mu.Lock()
	delete(r.resources, resource.ResourceID())
	r.mu.Unlock()

	// 删除角色相关联的资源信息
	r.mu.RLock()
	for _, role := range r.roles {
		role.revoke(resource)
	}
	r.mu.RUnlock()
}

// HasResource 指定 id 的资源是否存在
func (r *RBAC) HasResource(resourceID string) bool {
	r.mu.RLock()
	_, found := r.resources[resourceID]
	r.mu.RUnlock()

	return found
}

// Resources 获取所有已注册的资源
func (r *RBAC) Resources() []Resourcer {
	ret := make([]Resourcer, 0, len(r.resources))

	r.mu.RLock()
	for _, res := range r.resources {
		ret = append(ret, res)
	}
	r.mu.RUnlock()

	return ret
}

// RoleResources 与该角色有直接访问权限的所有资源
func (r *RBAC) RoleResources(role Roler) []Resourcer {
	r.mu.RLock()
	roleRes, found := r.roles[role.RoleID()]
	r.mu.RUnlock()

	if !found && r.getRole != nil {
		r.getRole(role)
		r.mu.RLock()
		roleRes, found = r.roles[role.RoleID()]
		r.mu.RUnlock()
	}

	if !found {
		return nil
	}

	return roleRes.roleResources()
}

// Assgin 赋予 role 访问 resource 的权限。
//
// 即使其父类已有权限，也会再次给 role 直接赋予访问 resource 的权限。
// 若 role 已经拥有直接访问 resource 的权限，则不执行任何操作。
func (r *RBAC) Assgin(role Roler, resource Resourcer) error {
	r.mu.Lock()
	res, found := r.resources[resource.ResourceID()]

	if !found {
		r.mu.Unlock()
		return ErrResourceNotExists
	}

	elem, found := r.roles[role.RoleID()]
	if !found { // 未初始化该角色的相关信息
		elem = newRoleResource(role)
		r.roles[role.RoleID()] = elem
	}
	r.mu.Unlock()

	// 使用 res，而不是 resource，因为 resource 可能只是一个带 ID 的简单类
	// 而 res 是通过 AddResource 注册的，附带的信息应该是全的。
	elem.assgin(res)

	return nil
}

// Revoke 取消 role 访问 resource 的权限，若父类还有访问 resource 的权限，
// 则 role 依然可以访问 resource。
func (r *RBAC) Revoke(role Roler, resource Resourcer) error {
	r.mu.RLock()
	elem, found := r.roles[role.RoleID()]
	r.mu.RUnlock()

	if !found {
		return ErrRoleNotExists
	}
	elem.revoke(resource)

	return nil
}

// RevokeAll 取消某一角色的所有的权限
func (r *RBAC) RevokeAll(role Roler) {
	r.mu.Lock()
	delete(r.roles, role.RoleID())
	r.mu.Unlock()
}

// HasRole 指定角色是否存在于 RBAC
func (r *RBAC) HasRole(role Roler) bool {
	r.mu.RLock()
	_, found := r.roles[role.RoleID()]
	r.mu.RUnlock()

	if !found && r.getRole != nil {
		r.getRole(role)
		r.mu.RLock()
		_, found = r.roles[role.RoleID()]
		r.mu.RUnlock()
	}

	return found
}

// Role 获取指定 ID 的角色
func (r *RBAC) Role(roleID string) Roler {
	r.mu.RLock()
	elem, found := r.roles[roleID]
	r.mu.RUnlock()

	if !found && r.getRole != nil {
		role := defaultRole{id: roleID}
		r.getRole(role)
		r.mu.RLock()
		elem, found = r.roles[role.RoleID()]
		r.mu.RUnlock()
	}

	return elem.role
}

// IsAllow 查询 role 是否拥有访问 resource 的权限
//
// 当角色不存在时，会尝试调用 RBAC.getRole 来更新角色信息。
// 若角色信息实在找不到，也会尝试调用其父类来查找权限。
func (r *RBAC) IsAllow(role Roler, resource Resourcer) bool {
	r.mu.RLock()
	elem, found := r.roles[role.RoleID()]
	r.mu.RUnlock()

	if !found && r.getRole != nil {
		r.getRole(role)

		r.mu.RLock()
		elem, found = r.roles[role.RoleID()]
		r.mu.RUnlock()
	}

	if found {
		elem.RLock()
		_, found = elem.resources[resource.ResourceID()]
		elem.RUnlock()
		if found {
			return true
		}
	}

	for _, parent := range role.Parents() {
		if parent != nil && r.IsAllow(parent, resource) {
			return true
		}
	}
	return false
}

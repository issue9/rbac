// Copyright 2016 by caixw, All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package rbac

import (
	"errors"
	"sync"
)

var (
	ErrResourceExists    = errors.New("资源已经存在")
	ErrResourceNotExists = errors.New("资源不存在")
	ErrRoleNotExists     = errors.New("角色不存在")
)

type RBAC struct {
	mu        sync.RWMutex
	roles     map[string]*roleResource
	resources map[string]Resourcer // 所有已注册资源列表
}

// New 新建 RBAC
func New() *RBAC {
	return &RBAC{
		roles:     make(map[string]*roleResource, 100),
		resources: make(map[string]Resourcer, 100),
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

// Assgin 赋予 role 访问 resource 的权限。
//
// 即使其父类已有权限，也会再次给 role 直接赋予访问 resource 的权限。
// 若 role 已经拥有直接访问 resource 的权限，则不执行任何操作。
func (r *RBAC) Assgin(role Roler, resource Resourcer) error {
	r.mu.Lock()
	_, found := r.resources[resource.ResourceID()]

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

	elem.assgin(resource)

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

// 指定角色是否存在于 RBAC
func (r *RBAC) HasRole(role Roler) bool {
	r.mu.RLock()
	_, found := r.roles[role.RoleID()]
	r.mu.RUnlock()
	return found
}

// IsAllow 查询 role 是否拥有访问 resource 的权限
func (r *RBAC) IsAllow(role Roler, resource Resourcer) bool {
	switch role.IsAllowHook(resource) {
	case True:
		return true
	case False:
		return false
	}

	r.mu.RLock()
	elem, found := r.roles[role.RoleID()]
	r.mu.RUnlock()
	if !found {
		return false
	}

	elem.RLock()
	_, found = elem.resources[resource.ResourceID()]
	elem.RUnlock()
	if found {
		return true
	}

	for _, parent := range role.Parents() {
		if parent != nil && r.IsAllow(parent, resource) {
			return true
		}
	}
	return false
}

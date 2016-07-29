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
	roles     map[string]*role
	resources map[string]bool // 所有已注册资源列表
}

// New 新建 RBAC
func New() *RBAC {
	return &RBAC{
		roles:     make(map[string]*role, 100),
		resources: make(map[string]bool, 100),
	}
}

// AddResource 添加新的资源
func (r *RBAC) AddResource(resource string) error {
	r.mu.Lock()

	for key, _ := range r.resources {
		if key == resource {
			r.mu.Unlock()
			return ErrResourceExists
		}
	}
	r.resources[resource] = true

	r.mu.Unlock()
	return nil
}

// RemoveResource 删除存在的资源，会同时去掉所有用户对该资源的访问权限。
func (r *RBAC) RemoveResource(resource string) {
	r.mu.Lock()
	delete(r.resources, resource)
	r.mu.Unlock()

	for _, role := range r.roles {
		role.revoke(resource)
	}
}

// SetParent 设置角色 roleID 的父类为 parents，这会覆盖已有的父类内容。
//
// 若将 parents 传递为空值，相当于取消了其所有的父类。
func (r *RBAC) SetParents(roleID string, parents ...string) error {
	r.mu.RLock()
	defer r.mu.RUnlock()

	elem, found := r.roles[roleID]
	if !found {
		return ErrRoleNotExists
	}

	ps := make([]*role, 0, len(parents))
	for _, parent := range parents {
		role, found := r.roles[parent]
		if !found {
			return ErrRoleNotExists
		}
		ps = append(ps, role)
	}

	elem.setParents(ps)

	return nil
}

// 为角色 roleID 添加新的父类 parents
func (r *RBAC) AddParents(roleID string, parents ...string) error {
	if len(parents) == 0 {
		return errors.New("参数 parents 至少指定一个")
	}

	r.mu.RLock()
	defer r.mu.RUnlock()

	elem, found := r.roles[roleID]
	if !found {
		return ErrRoleNotExists
	}

	ps := make([]*role, 0, len(parents))
	for _, parent := range parents {
		p, found := r.roles[parent]
		if !found {
			return ErrRoleNotExists
		}
		ps = append(ps, p)
	}

	elem.addParents(ps)

	return nil
}

// Assgin 赋予 roleID 访问 resourceID 的权限。
//
// 即使其父类已有权限，也会再次给 roleID 直接赋予访问 resourceID 的权限。
// 若 roleID 已经拥有直接访问 resourceID 的权限，则不执行任何操作。
func (r *RBAC) Assgin(roleID, resourceID string) error {
	r.mu.RLock()
	defer r.mu.RUnlock()

	if _, found := r.resources[resourceID]; !found {
		return ErrResourceNotExists
	}

	role, found := r.roles[roleID]
	if !found {
		role = newRole()
		r.roles[roleID] = role
	}

	role.assgin(resourceID)
	return nil
}

// Revoke 取消 roleID 访问 resourceID 的权限。
// 若父类还有访问 resourceID 的权限，则 roleID 依然可以访问 resourceID。
func (r *RBAC) Revoke(roleID, resourceID string) error {
	r.mu.RLock()
	elem, found := r.roles[roleID]
	r.mu.RUnlock()

	if !found {
		return ErrRoleNotExists
	}
	elem.revoke(resourceID)
	return nil
}

// RevokeAll 取消某一角色的所有的权限
func (r *RBAC) RevokeAll(roleID string) {
	r.mu.Lock()
	delete(r.roles, roleID)
	r.mu.Unlock()
}

// IsAllow 查询 roleID 是否拥有访问 resourceID 的权限
//
// 若角色或资源不存在，也返回 false。
func (r *RBAC) IsAllow(roleID, resourceID string) bool {
	r.mu.RLock()
	elem, found := r.roles[roleID]
	_, resFound := r.resources[resourceID]
	r.mu.RUnlock()

	if !found || !resFound {
		return false
	}

	return elem.isAllow(resourceID)
}

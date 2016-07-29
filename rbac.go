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

type role struct {
	parents   []string        // 角色的父类，部分权限可能从其父类继承
	resources map[string]bool // 角色的可访问资源列表，保存的是 RBAC.resources 的索引
}

func newRole() *role {
	return &role{
		resources: make(map[string]bool, 10),
	}
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

	for _, role := range r.roles {
		delete(role.resources, resource)
	}

	r.mu.Unlock()
}

// SetParent 设置角色 role 的父类为 parents，这会覆盖已有的父类内容。
//
// 若将 parents 传递为空值，相当于取消了其所有的父类。
func (r *RBAC) SetParent(role string, parents ...string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	elem, found := r.roles[role]
	if !found {
		return ErrRoleNotExists
	}

	for _, parent := range parents {
		if _, found = r.roles[parent]; !found {
			return ErrRoleNotExists
		}
	}

	elem.parents = parents

	return nil
}

// 为角色 role 添加新的父类 parents
func (r *RBAC) AddParent(role string, parents ...string) error {
	if len(parents) == 0 {
		return errors.New("参数 parents 至少指定一个")
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	elem, found := r.roles[role]
	if !found {
		return ErrRoleNotExists
	}

	for _, parent := range parents {
		if _, found = r.roles[parent]; !found {
			return ErrRoleNotExists
		}
	}

	if len(elem.parents) == 0 {
		elem.parents = parents
	} else {
		elem.parents = append(elem.parents, parents...)
	}

	return nil
}

// Assgin 赋予 role 访问 resource 的权限。
//
// 即使其父类已有权限，也会再次给 role 直接赋予访问 resource 的权限。
// 若 role 已经拥有直接访问 resource 的权限，则不执行任何操作。
func (r *RBAC) Assgin(role, resource string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if _, found := r.resources[resource]; !found {
		return ErrResourceNotExists
	}

	roleInst, found := r.roles[role]
	if !found {
		roleInst = newRole()
		r.roles[role] = roleInst
	}

	roleInst.resources[resource] = true
	return nil
}

// Revoke 取消 role 访问 resource 的权限。
// 若父类还有访问 resource 的权限，则 role 依然可以访问 resource。
func (r *RBAC) Revoke(role, resource string) error {
	r.mu.Lock()

	elem, found := r.roles[role]
	if !found {
		r.mu.Unlock()
		return ErrRoleNotExists
	}
	delete(elem.resources, resource)

	r.mu.Unlock()
	return nil
}

// RevokeAll 取消某一角色的所有的权限
func (r *RBAC) RevokeAll(role string) {
	r.mu.Lock()
	delete(r.roles, role)
	r.mu.Unlock()
}

// IsAllow 查询 role 是否拥有访问 resource 的权限
//
// 若角色不存在，也返回 false。
func (r *RBAC) IsAllow(role, resource string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()

	elem, found := r.roles[role]
	if !found {
		return false
	}

	if _, found = elem.resources[resource]; found {
		return true
	}

	for _, parent := range elem.parents {
		if r.IsAllow(parent, resource) {
			return true
		}
	}

	return false
}

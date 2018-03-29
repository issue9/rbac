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
)

// RBAC 权限管理类
type RBAC struct {
	locker sync.RWMutex
	roles  map[string]*role
	// 所有注册的资源，键名为资源唯一名称，键值为资源的描述信息
	resources map[string]string
}

// New 新建 RBAC
func New() *RBAC {
	return &RBAC{
		roles:     make(map[string]*role, 100),
		resources: make(map[string]string, 100),
	}
}

// SetRole 设置角色
func (rbac *RBAC) SetRole(id string, parent string) {
	r := rbac.getRole(id)
	p := rbac.getRole(parent)
	r.parent = p
}

// AddResource 添加新的资源
func (rbac *RBAC) AddResource(id, desc string) error {
	rbac.locker.Lock()
	defer rbac.locker.Unlock()

	if _, found := rbac.resources[id]; found {
		return ErrResourceExists
	}

	rbac.resources[id] = desc

	return nil
}

// AddResources 添加多条新的资源信息
func (rbac *RBAC) AddResources(res map[string]string) error {
	rbac.locker.Lock()
	defer rbac.locker.Unlock()

	for id, desc := range res {
		if _, found := rbac.resources[id]; found {
			return ErrResourceExists
		}
		rbac.resources[id] = desc
	}

	return nil
}

// RemoveResource 移除资源
func (rbac *RBAC) RemoveResource(id string) {
	// 删除注册的资源信息
	rbac.locker.Lock()
	delete(rbac.resources, id)
	rbac.locker.Unlock()

	// 删除角色相关联的资源信息
	rbac.locker.RLock()
	for _, role := range rbac.roles {
		role.revoke(id)
	}
	rbac.locker.RUnlock()
}

// HasResource 指定 id 的资源是否存在
func (rbac *RBAC) HasResource(id string) bool {
	rbac.locker.RLock()
	_, found := rbac.resources[id]
	rbac.locker.RUnlock()

	return found
}

// Resources 获取所有已注册的资源
func (rbac *RBAC) Resources() map[string]string {
	ret := make(map[string]string, len(rbac.resources))

	rbac.locker.RLock()
	for id, desc := range rbac.resources {
		ret[id] = desc
	}
	rbac.locker.RUnlock()

	return ret
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

// Allow 赋予 role 访问 resource 的权限。
//
// 即使其父类已有权限，也会再次给 role 直接赋予访问 resource 的权限。
// 若 role 已经拥有直接访问 resource 的权限，则不执行任何操作。
func (rbac *RBAC) Allow(role, resource string) error {
	rbac.locker.RLock()
	_, found := rbac.resources[resource]
	rbac.locker.RUnlock()

	if !found {
		return ErrResourceNotExists
	}

	rbac.getRole(role).allow(resource)
	return nil
}

// Deny 禁止当前用户对当前资源的访问权限。
//
// 不同于 Revoke，被禁用之的，即使上游有权限访问，也会被拒绝
func (rbac *RBAC) Deny(role, resource string) error {
	rbac.locker.RLock()
	_, found := rbac.resources[resource]
	rbac.locker.RUnlock()

	if !found {
		return ErrResourceNotExists
	}

	rbac.getRole(role).deny(resource)
	return nil
}

// Revoke 取消 role 访问 resource 的权限限制，恢复成默认状态。
//
// 其依然可以从父类继承相关的权限信息。
func (rbac *RBAC) Revoke(role, resource string) error {
	rbac.locker.RLock()
	_, found := rbac.resources[resource]
	rbac.locker.RUnlock()

	if !found {
		return ErrResourceNotExists
	}

	rbac.getRole(role).revoke(resource)
	return nil
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

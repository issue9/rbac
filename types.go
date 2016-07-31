// Copyright 2016 by caixw, All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package rbac

import "sync"

const (
	True = iota
	False
	Continue
)

// 角色接口
type Roler interface {
	// 角色的唯一 ID，不能触发 panic，否则结果是未知的。
	RoleID() string

	// 当前角色的所直接父类
	Parents() []Roler

	// 在 RBAC.IsAllow() 中判断当前角色是否拥有对 Resource
	// 访问权之前进行调用的勾子函数。
	IsAllowHook(Resourcer) int
}

// 资源接口
type Resourcer interface {
	// 资源的唯一 ID，不能触发 panic，否则结果是未知的。
	ResourceID() string
}

// 角色与资源的关联
type roleResource struct {
	sync.RWMutex
	role      Roler
	resources map[string]Resourcer // 当前用户的可访问资源列表
}

func newRoleResource(role Roler) *roleResource {
	return &roleResource{
		role:      role,
		resources: make(map[string]Resourcer, 10),
	}
}

// 赋予当前角色访问 resource 的权限。
func (r *roleResource) assgin(resource Resourcer) {
	r.Lock()
	r.resources[resource.ResourceID()] = resource
	r.Unlock()
}

// 取消当前角色访问 resource 的权限
//
// NOTE: 依然可以从其父类继承该权限。
func (r *roleResource) revoke(resource Resourcer) {
	r.Lock()
	delete(r.resources, resource.ResourceID())
	r.Unlock()
}

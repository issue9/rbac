// Copyright 2016 by caixw, All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package rbac

import "sync"

// Roler 角色接口
type Roler interface {
	// 角色的唯一 ID，不能触发 panic，否则结果是未知的。
	RoleID() string

	// 当前角色的所直接父类
	Parents() []Roler
}

// Resourcer 资源接口
type Resourcer interface {
	// 资源的唯一 ID，不能触发 panic，否则结果是未知的。
	ResourceID() string
}

// 默认的 Roler 接口实现。
type defaultRole struct {
	id string
}

func (r defaultRole) RoleID() string {
	return r.id
}

func (r defaultRole) Parents() []Roler {
	return nil
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

func (r *roleResource) roleResources() []Resourcer {
	ret := make([]Resourcer, 0, len(r.resources))

	r.RLock()
	for _, res := range r.resources {
		ret = append(ret, res)
	}
	r.RUnlock()

	return ret
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

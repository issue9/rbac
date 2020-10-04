// SPDX-License-Identifier: MIT

package rbac

import "sync"

type role struct {
	sync.Mutex

	id string

	// 父类角色
	//
	// 只能有一个父类角色，如果有多个父类角色，可能造成权限紊乱，
	// 比如父 A 允许某个权限，而父类 B 不允许。
	// 单个父类角色，可以根据上下级关系确定是否允许当前操作。
	parent *role

	// 当前角色所拥有的权限信息，若值为 false，表示明确限制访问。
	resources map[string]bool
}

// 赋予当前角色访问 id 的权限
func (r *role) allow(id string) {
	if r.resources == nil {
		r.resources = map[string]bool{id: true}
		return
	}

	r.Lock()
	r.resources[id] = true
	r.Unlock()
}

// 禁用当前角色访问 id 的权限
func (r *role) deny(id string) {
	if r.resources == nil {
		r.resources = map[string]bool{id: false}
		return
	}

	r.Lock()
	r.resources[id] = false
	r.Unlock()
}

// 取消当前角色访问 resource 的权限
//
// NOTE: 依然可以从其父类继承该权限。
func (r *role) revoke(id string) {
	if r.resources == nil {
		return
	}

	r.Lock()
	delete(r.resources, id)
	r.Unlock()
}

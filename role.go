// Copyright 2016 by caixw, All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package rbac

import (
	"sync"
)

type role struct {
	sync.Locker

	id string

	// 父类角色。
	//
	// 只能有一个父类角色，如果有多个父类角色，可能造成权限紊乱，
	// 比如父 A 允许某个权限，而父类 B 不允许。
	parent *role

	// 当前角色所拥有的权限信息，若值为 false，表示明确限制访问。
	resources map[string]bool
}

// 赋予当前角色访问 id 的权限。
func (r *role) allow(id string) {
	if len(r.resources) == 0 {
		r.resources = map[string]bool{id: true}
		return
	}

	r.Lock()
	r.resources[id] = true
	r.Unlock()
}

// 赋予当前角色访问 id 的权限。
func (r *role) deny(id string) {
	if len(r.resources) == 0 {
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
	r.Lock()
	delete(r.resources, id)
	r.Unlock()
}

// Copyright 2016 by caixw, All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package rbac

import "sync"

type role struct {
	mu        sync.RWMutex
	parents   []string        // 角色的父类，部分权限可能从其父类继承
	resources map[string]bool // 角色的可访问资源列表，保存的是 RBAC.resources 的索引
}

func newRole() *role {
	return &role{
		resources: make(map[string]bool, 10),
	}
}

func (r *role) setParents(parents []string) {
	r.mu.Lock()
	r.parents = parents
	r.mu.Unlock()
}

func (r *role) addParents(parents []string) {
	r.mu.Lock()
	if len(r.parents) == 0 {
		r.parents = parents
	} else {
		r.parents = append(r.parents, parents...)
	}
	r.mu.Unlock()
}

func (r *role) assgin(resource string) {
	r.mu.Lock()
	r.resources[resource] = true
	r.mu.Unlock()
}

func (r *role) revoke(resource string) {
	r.mu.Lock()
	delete(r.resources, resource)
	r.mu.Unlock()
}

// 当前角色是否直接拥有访问 resource 的权限
func (r *role) isAllow(resource string) bool {
	r.mu.RLock()

	_, found := r.resources[resource]
	r.mu.RUnlock()
	return found
}

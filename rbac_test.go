// Copyright 2016 by caixw, All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package rbac

import (
	"testing"

	"github.com/issue9/assert"
)

var _ Roler = defaultRole{}

func TestRBAC_AddRemoveResource(t *testing.T) {
	a := assert.New(t)
	r := New(nil)
	a.NotNil(r)

	a.NotError(r.AddResource(&testResource{id: "1"}))
	a.NotError(r.AddResource(&testResource{id: "2"}))
	a.Equal(len(r.resources), 2)

	// 添加相同资源
	a.Error(r.AddResource(&testResource{id: "2"}))
	a.Equal(len(r.resources), 2)

	r.RemoveResource(&testResource{id: "1"})
	a.Equal(len(r.resources), 1)

	// 移除不存在的资源
	r.RemoveResource(&testResource{id: "1"})
	a.Equal(len(r.resources), 1)
}

func TestRBAC_AssginRevoke(t *testing.T) {
	a := assert.New(t)
	r := New(nil)
	a.NotNil(r)

	res1 := &testResource{id: "1"}
	res2 := &testResource{id: "2"}
	usr1 := &testUser{id: "1"}
	a.NotError(r.AddResource(res1))

	a.NotError(r.Assgin(usr1, res1))
	a.NotError(r.Assgin(usr1, res1)) // 相同资源
	a.Error(r.Assgin(usr1, res2))    // 未注册的资源
	a.True(r.IsAllow(usr1, res1))

	a.NotError(r.Revoke(usr1, res1))
	a.False(r.IsAllow(usr1, res1))

	// 移除资源，自动去掉相应的访问权限
	a.NotError(r.Assgin(usr1, res1))
	r.RemoveResource(res1)
	a.False(r.IsAllow(usr1, res1))

	// 角色不存在
	a.Error(r.Revoke(&testUser{id: "3"}, res1))
}

func TestRBAC_IsAllow(t *testing.T) {
	a := assert.New(t)
	r := New(nil)
	a.NotNil(r)

	ures1 := &testResource{id: "u1"}
	ures2 := &testResource{id: "u2"}
	gres1 := &testResource{id: "g1"}
	gres2 := &testResource{id: "g2"}
	a.NotError(r.AddResource(ures1))
	a.NotError(r.AddResource(ures2))
	a.NotError(r.AddResource(gres1))
	a.NotError(r.AddResource(gres2))

	g1 := &testGroup{id: "g1"}
	usr1 := &testUser{id: "u1", parent: g1}
	a.False(r.IsAllow(g1, gres1)) // 还未执行 assgin 操作
	a.NotError(r.Assgin(g1, gres1))
	a.True(r.IsAllow(g1, gres1))

	a.NotError(r.Assgin(usr1, ures1))
	a.True(r.IsAllow(usr1, ures1))
	a.True(r.IsAllow(usr1, gres1)) // 通过 g1 间接获得权限

	// 虽然是同一个 roleID，但是 parent 已经不同
	g2 := &testGroup{id: "g2"}
	usr1Copy := &testUser{id: "u1", parent: g2}
	a.NotError(r.Assgin(g2, gres2))
	a.True(r.IsAllow(usr1Copy, gres2))
	a.False(r.IsAllow(usr1Copy, gres1))

	// usr1 本身已经已经不存在于 rbac 了，但依然可以通过关联的 g1 获取权限
	r.RevokeAll(usr1)
	a.True(r.IsAllow(usr1, gres1))
}

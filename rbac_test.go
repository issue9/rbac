// Copyright 2016 by caixw, All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package rbac

import (
	"testing"

	"github.com/issue9/assert"
)

func TestRBAC_AddRemoveResource(t *testing.T) {
	a := assert.New(t)
	r := New()
	a.NotNil(r)

	a.NotError(r.AddResource("1"))
	a.NotError(r.AddResource("2"))
	a.Equal(len(r.resources), 2)

	// 添加相同资源
	a.Error(r.AddResource("2"))
	a.Equal(len(r.resources), 2)

	r.RemoveResource("1")
	a.Equal(len(r.resources), 1)

	// 移除不存在的资源
	r.RemoveResource("1")
	a.Equal(len(r.resources), 1)
}

func TestRBAC_AssginRevoke(t *testing.T) {
	a := assert.New(t)
	r := New()
	a.NotNil(r)

	a.NotError(r.AddResource("res1"))

	a.NotError(r.Assgin("usr1", "res1"))
	a.NotError(r.Assgin("usr1", "res1")) // 相同资源
	a.Error(r.Assgin("usr1", "res2"))    // 未注册的资源
	a.True(r.IsAllow("usr1", "res1"))

	a.NotError(r.Revoke("usr1", "res1"))
	a.False(r.IsAllow("usr1", "res1"))

	// 移除资源，自动去掉相应的访问权限
	a.NotError(r.Assgin("usr1", "res1"))
	r.RemoveResource("res1")
	a.False(r.IsAllow("usr1", "res1"))

	// 角色不存在
	a.Error(r.Revoke("usr3", "res1"))
}

func TestRBAC(t *testing.T) {
	a := assert.New(t)
	r := New()
	a.NotNil(r)

	a.NotError(r.AddResource("res1"))
	a.NotError(r.AddResource("res2"))

	a.False(r.IsAllow("g1", "res1"))
	a.NotError(r.Assgin("g1", "res1"))
	a.True(r.IsAllow("g1", "res1"))

	a.NotError(r.Assgin("usr1", "res2"))
	a.True(r.IsAllow("usr1", "res2"))

	a.NotError(r.SetParents("usr1", "g1"))
	a.True(r.IsAllow("usr1", "res1")) // 通过 g1 间接获得权限
}

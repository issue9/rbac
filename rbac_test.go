// SPDX-License-Identifier: MIT

package rbac

import (
	"testing"

	"github.com/issue9/assert"
)

func TestRBAC(t *testing.T) {
	a := assert.New(t)
	r := New()
	a.NotNil(r)

	r.Allow("u1", "r1")
	a.True(r.IsAllow("u1", "r1"))
	a.False(r.IsAllow("u1", "r2")) // r2 不存在

	r.Deny("u1", "r2")
	a.False(r.IsAllow("u1", "r2"))

	r.Revoke("u1", "r1")
	a.False(r.IsAllow("u1", "r1"))

	// 通过继续父类得到权限
	r.SetRole("u1", "u2")
	r.Allow("u2", "r10")
	a.True(r.IsAllow("u1", "r10"))

	r.Deny("u1", "r10")
	a.False(r.IsAllow("u1", "r10"))
}

func TestRBAC_resources(t *testing.T) {
	a := assert.New(t)
	r := New()
	a.NotNil(r)

	r.Allow("u1", "r1")
	r.Allow("u1", "r2")
	r.Deny("u1", "r3")

	a.Equal(r.RoleResources("u1"), map[string]bool{
		"r1": true,
		"r2": true,
		"r3": false,
	})

	r.RevokeRole("u1")
	a.Empty(r.RoleResources("u1"))
}

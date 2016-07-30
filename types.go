// Copyright 2016 by caixw, All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package rbac

const (
	True = iota
	False
	Continue
)

// 角色接口
type Roler interface {
	// 角色的唯一 ID，不能触发 panic，否则结束是未知的。
	UniqueID() string

	// 当前角色的所直接父类
	Parents() []Roler

	// 在 RBAC.IsAllow() 中判断当前角色是否拥有对 Resource
	// 访问权之前进行调用的勾子函数。
	IsAllowHook(Resourcer) int
}

// 资源接口
type Resourcer interface {
	// 资源的唯一 ID，不能触发 panic，否则结束是未知的。
	UniqueID() string
}

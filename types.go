// Copyright 2016 by caixw, All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package rbac

// 角色接口
type Roler interface {
	// 角色的唯一 ID，不能触发 panic，否则结束是未知的。
	UniqueID() string

	Parents() []Roler
}

// 资源接口
type Resourcer interface {
	// 资源的唯一 ID，不能触发 panic，否则结束是未知的。
	UniqueID() string
}

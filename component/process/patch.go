package process

import "github.com/Dreamacro/clash/constant"

type PackageNameResolver func(metadata *constant.Metadata) (string, error)

var DefaultPackageNameResolver PackageNameResolver

func FindPackageName(metadata *constant.Metadata) (string, error) {
	if resolver := DefaultPackageNameResolver; resolver != nil {
		return resolver(metadata)
	}
	return "", ErrPlatformNotSupport
}

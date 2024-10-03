package fileserver

import (
	"fileserver/pkg/fileserver/shared"
	"fmt"
	"testing"
)

func Test_IsValidKey(t *testing.T) {
	var tests = []struct {
		val           string
		allowMatchers bool
		isDir         bool
		want          error
	}{
		{"", false, true, shared.ErrKeyNameSyntaxError},
		{"", false, false, shared.ErrKeyNameSyntaxError},
		{"", true, false, shared.ErrKeyNameSyntaxError},
		{"", true, false, shared.ErrKeyNameSyntaxError},
		{"*", true, false, nil},
		{"nzzz", false, true, shared.ErrKeyNameSyntaxError},
		{"nzzz?", true, true, nil},
		{"nzz z?", true, true, shared.ErrKeyNameSyntaxError},
		{"n", false, false, nil},
		{" ", false, true, shared.ErrKeyNameSyntaxError},
		{" ", false, false, shared.ErrKeyNameSyntaxError},
		{"\t", false, true, shared.ErrKeyNameSyntaxError},
		{"\t/ ", false, false, shared.ErrKeyNameSyntaxError},
		{" / ", false, true, shared.ErrKeyNameSyntaxError},
		{" / ", false, false, shared.ErrKeyNameSyntaxError},
		{" /", false, true, shared.ErrKeyNameSyntaxError},
		{" /", false, false, shared.ErrKeyNameSyntaxError},
		{" / /", false, true, shared.ErrKeyNameSyntaxError},
		{" / /", false, false, shared.ErrKeyNameSyntaxError},
		{" / / ", false, true, shared.ErrKeyNameSyntaxError},
		{" / / ", false, false, shared.ErrKeyNameSyntaxError},
		{"name", false, true, shared.ErrKeyNameSyntaxError},
		{"name", false, false, nil},
		{"name/nested", false, true, shared.ErrKeyNameSyntaxError},
		{"name/nested", false, false, nil},
		{"name/nested.", false, true, shared.ErrKeyNameSyntaxError},
		{"name/nested.", false, false, nil},
		{"name/nested.ext", false, true, shared.ErrKeyNameSyntaxError},
		{"name/nested.ext", false, false, nil},
		{"name/.hidden", false, true, shared.ErrKeyNameSyntaxError},
		{"name/.hidden", false, false, nil},
		{".hidden", false, true, shared.ErrKeyNameSyntaxError},
		{".hidden", false, false, nil},
		{"name/nested/slash_suffix_not_allowed_for_file/", false, true, nil},
		{"name/nested/slash_suffix_not_allowed_for_file/", false, false, shared.ErrKeyNameSyntaxError},
		{".", false, true, shared.ErrKeyNameSyntaxError},
		{".", false, false, nil},
		{"..", false, true, shared.ErrKeyNameSyntaxError},
		{"..", false, false, nil},
		{"../", false, true, nil},
		{"../", false, false, shared.ErrKeyNameSyntaxError},
		{"/..", false, true, shared.ErrKeyNameSyntaxError},
		{"/..", false, false, shared.ErrKeyNameSyntaxError},
		{"./", false, true, nil},
		{"./", false, false, shared.ErrKeyNameSyntaxError},
		{"/.", false, true, shared.ErrKeyNameSyntaxError},
		{"/.", false, false, shared.ErrKeyNameSyntaxError},
		{"/", false, true, shared.ErrKeyNameSyntaxError},
		{"/", false, false, shared.ErrKeyNameSyntaxError},
		{"//", false, true, shared.ErrKeyNameSyntaxError},
		{"//", false, false, shared.ErrKeyNameSyntaxError},
		{"spacesuffix ", false, true, shared.ErrKeyNameSyntaxError},
		{"spacesuffix ", false, false, shared.ErrKeyNameSyntaxError},
		{" spaceprefix ", false, true, shared.ErrKeyNameSyntaxError},
		{" spaceprefix ", false, false, shared.ErrKeyNameSyntaxError},
		{"/ spaceprefix ", false, true, shared.ErrKeyNameSyntaxError},
		{"/ spaceprefix ", false, false, shared.ErrKeyNameSyntaxError},
		{"spacesufix /", false, true, shared.ErrKeyNameSyntaxError},
		{"spacesufix /", false, false, shared.ErrKeyNameSyntaxError},
		{" /spaceprefix", false, true, shared.ErrKeyNameSyntaxError},
		{" /spaceprefix", false, false, shared.ErrKeyNameSyntaxError},
	}

	for _, tt := range tests {
		// t.Run enables running "subtests", one for each
		// table entry. These are shown separately
		// when executing `go test -v`.
		testname := fmt.Sprintf("%q.matchers=%v.isDir=%v", tt.val, tt.allowMatchers, tt.isDir)
		t.Run(testname, func(t *testing.T) {

			ans := IsValidKey(tt.val, tt.allowMatchers, tt.isDir)
			var err error
			if ans != nil {
				err = ans.Cause()
			}
			if tt.want != err {
				t.Errorf("got %v, want %v", ans, tt.want)
			}
		})
	}
}

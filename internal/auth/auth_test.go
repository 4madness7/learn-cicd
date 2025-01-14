package auth

import (
	"errors"
	"net/http"
	"testing"
)

func TestAuth(t *testing.T) {
	errNoAuthHeaderIncluded := errors.New("no authorization header included")
	errMalformedHeader := errors.New("malformed authorization header")

	type testResult struct {
		key string
		err string
	}

	type testCase struct {
		input    http.Header
		got      testResult
		expected testResult
	}

	cases := map[string]testCase{
		"good header": {
			input:    http.Header{"Authorization": []string{"ApiKey asdfasdfasdfasdfasdfasdf"}},
			expected: testResult{key: "asdfasdfasdfasdfasdfasdf", err: ""},
		},
		"no auth header 1": {
			input:    http.Header{},
			expected: testResult{key: "", err: errNoAuthHeaderIncluded.Error()},
		},
		"no auth header 2": {
			input:    http.Header{"Authorization": []string{""}},
			expected: testResult{key: "", err: errNoAuthHeaderIncluded.Error()},
		},
		"malformed header 1": {
			input:    http.Header{"Authorization": []string{"asdfasdfasdfasdfasdf"}},
			expected: testResult{key: "", err: errMalformedHeader.Error()},
		},
		"malformed header 2": {
			input:    http.Header{"Authorization": []string{"ApiKey"}},
			expected: testResult{key: "", err: errMalformedHeader.Error()},
		},
	}

	for name, tc := range cases {
		key, err := GetAPIKey(tc.input)
		tc.got.key = key
		if err != nil {
			tc.got.err = err.Error()
		} else {
			tc.got.err = ""
		}

		if tc.got != tc.expected {
			t.Errorf(
				"failed '%s': got %#v expected %#v",
				name,
				tc.got,
				tc.expected,
			)
		}
	}
}

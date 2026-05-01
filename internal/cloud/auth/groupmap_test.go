package auth

import (
	"reflect"
	"sort"
	"strings"
	"testing"
)

func TestParseGroupMap(t *testing.T) {
	tests := []struct {
		name    string
		raw     string
		want    map[string][]string
		wantErr string
	}{
		{
			name: "empty input returns empty map",
			raw:  "",
			want: map[string][]string{},
		},
		{
			name: "single group single project",
			raw:  "ops:proj-a",
			want: map[string][]string{"ops": {"proj-a"}},
		},
		{
			name: "multi-group multi-project with whitespace",
			raw:  " ops : proj-a , proj-b ;  devs:proj-c ",
			want: map[string][]string{
				"ops":  {"proj-a", "proj-b"},
				"devs": {"proj-c"},
			},
		},
		{
			name: "wildcard project preserved",
			raw:  "admins:*",
			want: map[string][]string{"admins": {"*"}},
		},
		{
			name: "empty entries are ignored",
			raw:  ";;ops:proj-a;;devs:proj-b;",
			want: map[string][]string{
				"ops":  {"proj-a"},
				"devs": {"proj-b"},
			},
		},
		{
			name:    "duplicate group rejected",
			raw:     "ops:proj-a;ops:proj-b",
			wantErr: "duplicate group",
		},
		{
			name:    "missing colon rejected",
			raw:     "ops-no-colon",
			wantErr: "missing ':' separator",
		},
		{
			name:    "empty projects list rejected",
			raw:     "ops:",
			wantErr: "empty projects",
		},
		{
			name:    "empty group name rejected",
			raw:     ":proj-a",
			wantErr: "empty group",
		},
		{
			name:    "whitespace-only group rejected",
			raw:     "   :proj-a",
			wantErr: "empty group",
		},
		{
			name:    "whitespace-only project rejected",
			raw:     "ops:  ",
			wantErr: "empty projects",
		},
		{
			name: "duplicate projects within a group are deduplicated",
			raw:  "ops:proj-a,proj-a,proj-b",
			want: map[string][]string{"ops": {"proj-a", "proj-b"}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseGroupMap(tt.raw)
			if tt.wantErr != "" {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil (result: %v)", tt.wantErr, got)
				}
				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("expected error containing %q, got %q", tt.wantErr, err.Error())
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("map mismatch\n got: %v\nwant: %v", got, tt.want)
			}
		})
	}
}

func TestProjectsFor(t *testing.T) {
	m := map[string][]string{
		"ops":   {"proj-a", "proj-b"},
		"devs":  {"proj-b", "proj-c"},
		"admin": {WildcardProject},
	}

	tests := []struct {
		name   string
		groups []string
		want   []string
	}{
		{
			name:   "single mapped group",
			groups: []string{"ops"},
			want:   []string{"proj-a", "proj-b"},
		},
		{
			name:   "multi-group union deduplicated",
			groups: []string{"ops", "devs"},
			want:   []string{"proj-a", "proj-b", "proj-c"},
		},
		{
			name:   "unmapped group returns empty",
			groups: []string{"unknown"},
			want:   []string{},
		},
		{
			name:   "empty groups returns empty",
			groups: []string{},
			want:   []string{},
		},
		{
			name:   "wildcard passes through",
			groups: []string{"admin"},
			want:   []string{WildcardProject},
		},
		{
			name:   "mixed mapped and unmapped",
			groups: []string{"ops", "ghost"},
			want:   []string{"proj-a", "proj-b"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ProjectsFor(tt.groups, m)
			gotSorted := append([]string{}, got...)
			wantSorted := append([]string{}, tt.want...)
			sort.Strings(gotSorted)
			sort.Strings(wantSorted)
			if !reflect.DeepEqual(gotSorted, wantSorted) {
				t.Fatalf("projects mismatch\n got: %v\nwant: %v", got, tt.want)
			}
		})
	}
}

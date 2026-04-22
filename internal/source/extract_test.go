package source

import (
	"reflect"
	"testing"
)

func TestExtractHostsFromText(t *testing.T) {
	input := `
		<td>api.example.com</td>
		<td>https://dev.example.com/path</td>
		<td>api.example.com</td>
		<td>ignore.other.com</td>
	`
	got := extractHostsFromText(input, "example.com")
	want := []string{"api.example.com", "dev.example.com"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("unexpected hosts: got %v want %v", got, want)
	}
}

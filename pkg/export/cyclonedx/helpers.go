package cyclonedx

import "encoding/json"

func marshalStringList(items []string) string {
	b, _ := json.Marshal(items)
	return string(b)
}
